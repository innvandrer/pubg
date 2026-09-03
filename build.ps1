#Requires -Version 5.1
<#
.SYNOPSIS
    Build, sign, load, and verify MyMemoryDriver for PUBG-Memory-Visualization.

.DESCRIPTION
    End-to-end automation:
      1. Locate MSBuild (VS 2022) and WDK
      2. Build kernel driver + unified Launcher (+ optional test_read)
      3. Create test code-signing certificate if missing
      4. Sign MyMemoryDriver.sys with signtool
      5. Load driver via SCM (Launcher.exe or sc.exe)
      6. Run Launcher.exe ping (IOCTL_PING + XOR handshake)

    The Launcher executable combines the BYOVD driver loader and the PUBG client overlay/aim assist.

    Default certificate password: test1234 (override with -CertPassword).

.PARAMETER Configuration
    MSBuild configuration (Debug or Release). Default: Release.

.PARAMETER Platform
    Target platform. Default: x64.

.PARAMETER SkipSign
    Skip driver code signing (requires testsigning on for load).

.PARAMETER SkipLoad
    Build and sign only; do not load driver or run ping.

.PARAMETER SkipTestBuild
    Do not build the test_read harness.

.PARAMETER DriverProject
    Optional path to driver .vcxproj. Default: .\MyMemoryDriver.vcxproj

.PARAMETER SolutionPath
    Optional path to .sln. Default: .\PUBG-Memory-Visualization.sln

.PARAMETER CertPassword
    Password for test PFX (creation and signing). Default: test1234

.PARAMETER WhatIf
    Show planned actions without executing build/load/sign steps.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [ValidateSet('x64')]
    [string] $Platform = 'x64',

    [switch] $SkipSign,
    [switch] $SkipLoad,
    [switch] $SkipTestBuild,
    [switch] $RunTests,

    [string] $DriverProject = '',
    [string] $SolutionPath = '',
    [string] $CertPassword = 'test1234'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step([string] $Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string] $Message) {
    Write-Host "    OK: $Message" -ForegroundColor Green
}

function Write-Warn([string] $Message) {
    Write-Host "    WARN: $Message" -ForegroundColor Yellow
}

function Write-Err([string] $Message) {
    Write-Host "    ERROR: $Message" -ForegroundColor Red
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-MsBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found. Install Visual Studio 2022 with Desktop development with C++."
    }

    $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    if (-not $installPath) {
        throw "Visual Studio 2022 with MSBuild not found."
    }

    $msbuild = Join-Path $installPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path $msbuild)) {
        throw "MSBuild.exe not found at: $msbuild"
    }

    return $msbuild
}

function Test-WdkInstalled {
    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    if (-not (Test-Path $kitsRoot)) { return $false }

    # WDK 10.0.26100+ uses versioned build folders (e.g. build\10.0.28000.0\).
    $versionedProps = Get-ChildItem -Path (Join-Path $kitsRoot 'build') -Filter 'WindowsDriver.Common.props' -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($versionedProps) { return $true }

    # Legacy unversioned layout.
    return (Test-Path (Join-Path $kitsRoot 'build\WindowsDriver.common.props'))
}

function Get-WdkKitVersion {
    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    $includeRoot = Join-Path $kitsRoot 'Include'
    if (-not (Test-Path $includeRoot)) { return $null }

    $kmVersions = Get-ChildItem -Path $includeRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'km\ntddk.h') } |
        Sort-Object Name -Descending

    if ($kmVersions) {
        return $kmVersions[0].Name
    }
    return $null
}

function Invoke-MsBuild {
    param(
        [string] $MsBuild,
        [string] $Target,
        [string[]] $ExtraArgs
    )

    $args = @(
        $Target,
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/m",
        "/v:minimal",
        "/nologo"
    ) + $ExtraArgs

    if ($PSCmdlet.ShouldProcess($Target, "MSBuild $Configuration|$Platform")) {
        & $MsBuild @args
        if ($LASTEXITCODE -ne 0) {
            throw "MSBuild failed for $Target (exit $LASTEXITCODE)"
        }
    }
    else {
        Write-Warn "[WhatIf] MSBuild $($args -join ' ')"
    }
}

function Load-DriverViaScm {
    param(
        [string] $DriverPath,
        [string] $ServiceName = 'MyMemoryDriver'
    )

    $fullPath = (Resolve-Path $DriverPath).Path

    if ($PSCmdlet.ShouldProcess($fullPath, "Load driver via SCM")) {
        sc.exe stop $ServiceName 2>$null | Out-Null
        sc.exe delete $ServiceName 2>$null | Out-Null

        sc.exe create $ServiceName type= kernel start= demand binPath= "`"$fullPath`""
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create failed (exit $LASTEXITCODE). Is test signing enabled?"
        }

        sc.exe start $ServiceName
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe start failed (exit $LASTEXITCODE). Common causes: unsigned driver (577), testsigning off."
        }

        Write-Ok "Driver loaded: $ServiceName"
    }
    else {
        Write-Warn "[WhatIf] Would load driver via SCM: $fullPath"
    }
}

function Invoke-LoaderPing {
    param([string] $LoaderExe)

    if (-not (Test-Path $LoaderExe)) {
        throw "Launcher.exe not found: $LoaderExe"
    }

    if ($PSCmdlet.ShouldProcess($LoaderExe, "Run ping + handshake")) {
        & $LoaderExe ping
        if ($LASTEXITCODE -ne 0) {
            throw "Launcher.exe ping failed (exit $LASTEXITCODE)"
        }
        Write-Ok "Ping and XOR handshake verified"
    }
    else {
        Write-Warn "[WhatIf] Would run: $LoaderExe ping"
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Get-Location }

Push-Location $scriptRoot
try {
    Write-Host "PUBG-Memory-Visualization build automation" -ForegroundColor White
    Write-Host "  Configuration : $Configuration"
    Write-Host "  Platform      : $Platform"
    Write-Host "  SkipSign      : $SkipSign"
    Write-Host "  SkipLoad      : $SkipLoad"

    if ($SkipSign) {
        $env:PUBG_SKIP_DRIVER_SIGN = '1'
    }
    else {
        Remove-Item Env:PUBG_SKIP_DRIVER_SIGN -ErrorAction SilentlyContinue
    }

    if (-not $SolutionPath) {
        $SolutionPath = Join-Path $scriptRoot 'PUBG-Memory-Visualization.sln'
    }
    if (-not $DriverProject) {
        $DriverProject = Join-Path $scriptRoot 'MyMemoryDriver.vcxproj'
    }

    if (-not (Test-Path $SolutionPath)) {
        throw "Solution not found: $SolutionPath"
    }
    if (-not (Test-Path $DriverProject)) {
        throw "Driver project not found: $DriverProject"
    }

    Write-Step "Locating build tools"
    $msbuild = Find-MsBuild
    Write-Ok "MSBuild: $msbuild"

    if (-not (Test-WdkInstalled)) {
        Write-Warn "WDK not detected (WindowsDriver.Common.props missing under Windows Kits\10\build)."
        Write-Warn "Install WDK matching VS 2022: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk"
        Write-Warn "Also install the 'Windows Driver Kit' VS extension (Individual components or Extensions)."
    }
    else {
        $wdkKit = Get-WdkKitVersion
        if ($wdkKit) {
            Write-Ok "WDK detected (kernel headers: $wdkKit)"
        }
        else {
            Write-Ok "WDK build props detected (kernel headers not found - repair WDK install)"
        }
    }

    $outDir = Join-Path $scriptRoot "$Platform\$Configuration"
    $driverSys = Join-Path $outDir 'MyMemoryDriver.sys'
    $launcherExe = Join-Path $outDir 'Launcher.exe'
    $testReadExe = Join-Path $outDir 'test_read.exe'

    # --- Build driver ---
    Write-Step "Building kernel driver"
    Invoke-MsBuild -MsBuild $msbuild -Target $DriverProject -ExtraArgs @()

    if (-not $WhatIfPreference -and -not (Test-Path $driverSys)) {
        throw "Expected driver output missing: $driverSys"
    }
    if (-not $WhatIfPreference) {
        Write-Ok "Driver built: $driverSys"
    }

    # --- Build unified launcher (driver loader + PUBG client overlay) ---
    Write-Step "Building unified launcher"
    $launcherProject = Join-Path $scriptRoot 'Launcher\Launcher.vcxproj'
    Invoke-MsBuild -MsBuild $msbuild -Target $launcherProject -ExtraArgs @()

    if (-not $WhatIfPreference -and -not (Test-Path $launcherExe)) {
        throw "Expected launcher output missing: $launcherExe"
    }
    if (-not $WhatIfPreference) {
        Write-Ok "Launcher built: $launcherExe"
    }

    # --- Runtime packaging (OpenCV / CUDA / YOLO) ---
    Write-Step "Copying runtime dependencies"
    $copyScript = Join-Path $scriptRoot 'scripts\copy_runtime_deps.ps1'
    if (Test-Path $copyScript) {
        if ($PSCmdlet.ShouldProcess($outDir, "Copy runtime DLLs and assets")) {
            & $copyScript -OutDir $outDir -RepoRoot $scriptRoot
            if ($LASTEXITCODE -ne 0) {
                throw "copy_runtime_deps.ps1 failed (exit $LASTEXITCODE)"
            }
        }
        else {
            Write-Warn "[WhatIf] Would copy OpenCV/CUDA/YOLO assets into $outDir"
        }
    }
    else {
        Write-Warn "Runtime copy script missing: $copyScript"
    }

    # --- Build test harness (optional) ---
    if (-not $SkipTestBuild) {
        $testProject = Join-Path $scriptRoot 'test_read.vcxproj'
        if (Test-Path $testProject) {
            Write-Step "Building test_read harness"
            Invoke-MsBuild -MsBuild $msbuild -Target $testProject -ExtraArgs @()
            if (-not $WhatIfPreference -and (Test-Path $testReadExe)) {
                Write-Ok "test_read built: $testReadExe"
            }
        }
    }

    # --- Sign (also runs as a driver project post-build unless PUBG_SKIP_DRIVER_SIGN=1) ---
    if (-not $SkipSign) {
        Write-Step "Signing driver"
        $signScript = Join-Path $scriptRoot 'scripts\sign_driver.ps1'
        if (-not (Test-Path $signScript)) {
            throw "Signing script not found: $signScript"
        }
        if ($PSCmdlet.ShouldProcess($driverSys, "Test-sign driver")) {
            & $signScript -DriverSys $driverSys -CertPassword $CertPassword
            if ($LASTEXITCODE -ne 0) {
                throw "sign_driver.ps1 failed (exit $LASTEXITCODE)"
            }
        }
        else {
            Write-Warn "[WhatIf] Would sign $driverSys via $signScript"
        }
    }
    else {
        Write-Warn "Skipping sign (-SkipSign). Driver must be test-signed or testsigning must be on."
    }

    # --- Load + verify ---
    if (-not $SkipLoad) {
        if (-not (Test-Admin)) {
            throw "Loading the driver requires Administrator. Re-run PowerShell as Admin or use -SkipLoad."
        }

        Write-Step "Loading driver via SCM"
        if (Test-Path $launcherExe) {
            if ($PSCmdlet.ShouldProcess($driverSys, "Launcher.exe load")) {
                & $launcherExe load $driverSys
                if ($LASTEXITCODE -ne 0) {
                    throw "Launcher.exe load failed (exit $LASTEXITCODE)"
                }
                Write-Ok "Launcher.exe load succeeded"
            }
            else {
                Write-Warn "[WhatIf] Would run: $launcherExe load $driverSys"
            }
        }
        else {
            Load-DriverViaScm -DriverPath $driverSys
        }

        Write-Step "Verifying driver (ping + handshake)"
        Invoke-LoaderPing -LoaderExe $launcherExe

        if ($RunTests -and (Test-Path $testReadExe)) {
            Write-Step "Running test_read harness"
            if ($PSCmdlet.ShouldProcess($testReadExe, "Run memory tests")) {
                & $testReadExe
                if ($LASTEXITCODE -ne 0) {
                    throw "test_read.exe failed (exit $LASTEXITCODE)"
                }
                Write-Ok "test_read passed"
            }
        }
        elseif ($RunTests -and -not (Test-Path $testReadExe)) {
            Write-Warn "-RunTests set but test_read.exe not found at $testReadExe"
        }
    }
    else {
        Write-Warn "Skipping load and ping (-SkipLoad)"
    }

    Write-Host "`nBuild automation completed successfully." -ForegroundColor Green
    Write-Host "  Driver  : $driverSys"
    Write-Host "  Launcher: $launcherExe"
    if (Test-Path $testReadExe) {
        Write-Host "  Tests   : $testReadExe"
    }
}
catch {
    Write-Err $_.Exception.Message
    exit 1
}
finally {
    Pop-Location
}
