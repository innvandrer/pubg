#Requires -Version 5.1
<#
.SYNOPSIS
    Copy OpenCV, CUDA/NPP, and YOLO assets next to Launcher.exe at build time.

.DESCRIPTION
    Does not commit large binaries. Sources:
      - opencv_world470.dll from ai-aimassist-source OpenCV bin
      - CUDA 11 / NPP / cuBLAS / cuFFT / cuDNN from ai-aimassist-source cuda11\bin
      - yolov3-tiny.weights if found on disk (not downloaded)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutDir,

    [string] $RepoRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-DepOk([string] $Message) {
    Write-Host "    OK: $Message" -ForegroundColor Green
}

function Write-DepWarn([string] $Message) {
    Write-Host "    WARN: $Message" -ForegroundColor Yellow
}

if (-not $RepoRoot) {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
}

function Normalize-DirPath([string] $PathValue) {
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $PathValue
    }
    $PathValue = $PathValue.Trim().Trim('"')
    # Trailing backslash in MSBuild "$(OutDir)\" can swallow the closing quote.
    $glue = ' -RepoRoot '
    if ($PathValue -like "*$glue*") {
        $PathValue = $PathValue.Split($glue)[0].Trim().Trim('"')
    }
    try {
        $PathValue = [System.IO.Path]::GetFullPath($PathValue)
    }
    catch {
        # Keep trimmed value; Test-Path will report a clear error.
    }
    return $PathValue.TrimEnd('\', '/')
}

$OutDir = Normalize-DirPath $OutDir
$RepoRoot = Normalize-DirPath $RepoRoot

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$runtimeDir = Join-Path $OutDir 'runtime'
if (-not (Test-Path $runtimeDir)) {
    New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
}

$devRoot = Split-Path $RepoRoot -Parent
$aimassist = Join-Path $devRoot 'ai-aimassist-source\example_win32_directx11'
$opencvDll = Join-Path $aimassist 'misc\opencv2\x64\vc16\bin\opencv_world470.dll'
$cudaBin = Join-Path $aimassist 'misc\cuda11\bin'

function Copy-IfExists {
    param(
        [string] $Source,
        [string] $DestinationDir,
        [switch] $Required
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        if ($Required) {
            Write-DepWarn "Missing required file: $Source"
        }
        return $false
    }

    if (-not (Test-Path $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    $dest = Join-Path $DestinationDir (Split-Path $Source -Leaf)
    if (Test-Path -LiteralPath $dest) {
        $srcItem = Get-Item -LiteralPath $Source
        $dstItem = Get-Item -LiteralPath $dest
        if ($srcItem.Length -eq $dstItem.Length -and $srcItem.LastWriteTimeUtc -le $dstItem.LastWriteTimeUtc) {
            return $true
        }
    }
    Copy-Item -LiteralPath $Source -Destination $dest -Force
    return $true
}

# OpenCV (CUDA-linked world DLL). CLI load/ping delay-loads this; overlay still needs it.
if (Copy-IfExists -Source $opencvDll -DestinationDir $OutDir) {
    Write-DepOk "Copied opencv_world470.dll"
}
else {
    Write-DepWarn "opencv_world470.dll not found at $opencvDll"
}

# Direct + typical transitive CUDA deps of opencv_world470.dll (dumpbin /DEPENDENTS).
# Skip *train* and 32-bit (~1.5GB). Do not copy into git.
$cudaDlls = @(
    'cudart64_110.dll',
    'nppc64_11.dll',
    'nppial64_11.dll',
    'nppicc64_11.dll',
    'nppidei64_11.dll',
    'nppif64_11.dll',
    'nppig64_11.dll',
    'nppim64_11.dll',
    'nppist64_11.dll',
    'nppisu64_11.dll',
    'nppitc64_11.dll',
    'npps64_11.dll',
    'cublas64_11.dll',
    'cublasLt64_11.dll',
    'cufft64_10.dll',
    'cudnn64_8.dll',
    'cudnn_adv_infer64_8.dll',
    'cudnn_cnn_infer64_8.dll',
    'cudnn_ops_infer64_8.dll'
)

$copiedCuda = 0
$missingCuda = @()
if (Test-Path $cudaBin) {
    foreach ($name in $cudaDlls) {
        $src = Join-Path $cudaBin $name
        if (Copy-IfExists -Source $src -DestinationDir $OutDir) {
            $copiedCuda++
        }
        else {
            $missingCuda += $name
        }
    }
    Write-DepOk "Copied $copiedCuda CUDA/NPP DLL(s) from $cudaBin"
    if ($missingCuda.Count -gt 0) {
        Write-DepWarn ("CUDA DLLs not found: " + ($missingCuda -join ', '))
    }
}
else {
    Write-DepWarn "CUDA bin not found: $cudaBin (GUI overlay needs these next to Launcher.exe; CLI load/ping does not)"
}

# Small runtime assets already in-repo.
foreach ($name in @('coco-dataset.labels', 'yolov3-tiny.cfg')) {
    $src = Join-Path $RepoRoot "runtime\$name"
    if (Copy-IfExists -Source $src -DestinationDir $runtimeDir) {
        Write-DepOk "Copied runtime\$name"
    }
}

$weightCandidates = @(
    (Join-Path $RepoRoot 'runtime\yolov3-tiny.weights'),
    (Join-Path $aimassist 'runtime\yolov3-tiny.weights'),
    (Join-Path $aimassist 'Release\yolov3-tiny.weights'),
    (Join-Path $OutDir 'runtime\yolov3-tiny.weights')
)

$weightsCopied = $false
foreach ($candidate in $weightCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        if (Copy-IfExists -Source $candidate -DestinationDir $runtimeDir) {
            Write-DepOk "Copied yolov3-tiny.weights from $candidate"
            $weightsCopied = $true
            break
        }
    }
}

if (-not $weightsCopied) {
    Write-DepWarn "yolov3-tiny.weights not found (AI overlay needs it under runtime\). Place the file in repo\runtime\ or ai-aimassist-source\...\runtime\ and rebuild. Not downloaded or committed."
}
