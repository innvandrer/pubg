#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Smoke-test the PUBG-Memory-Visualization build inside a VirtualBox Windows VM.

.DESCRIPTION
    Stages the built Release x64 artifacts from the host, copies them into the VM,
    loads the driver via the Launcher SCM path, runs ping + test_read, and unloads.
    A snapshot is taken before the driver load and restored at the end so the VM
    returns to a clean state.

.PARAMETER VmName
    VirtualBox VM name (default: tester).

.PARAMETER Password
    Guest OS password for the vboxuser account. Prefer passing via VM_TEST_PASSWORD env var.

.PARAMETER ProjectRoot
    Repo root on the host. Default is the script's parent directory.

.PARAMETER Configuration
    Build configuration to test (default: Release).

.PARAMETER CleanSnapshot
    Snapshot name to restore to after testing. If not supplied, the current snapshot is kept.
#>
param(
    [string]$VmName = 'tester',
    [string]$Password = $env:VM_TEST_PASSWORD,
    [string]$ProjectRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$Configuration = 'Release',
    [string]$CleanSnapshot = ''
)

$ErrorActionPreference = 'Stop'

if (-not $Password) {
    throw "Password required. Set VM_TEST_PASSWORD env var or pass -Password."
}

$vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
if (-not (Test-Path $vbox)) {
    throw "VBoxManage not found at $vbox"
}

$platform = 'x64'
$outDir = Join-Path $ProjectRoot "$platform\$Configuration"

$required = @('Launcher.exe', 'MyMemoryDriver.sys', 'test_read.exe', 'opencv_world470.dll')
foreach ($f in $required) {
    $p = Join-Path $outDir $f
    if (-not (Test-Path $p)) { throw "Missing $p" }
}

$staging = Join-Path $env:TEMP 'PUBGVMTest'
$vmDestParent = 'C:\Users\vboxuser\Desktop'
$vmDest = Join-Path $vmDestParent 'PUBGVMTest'

function VBoxRun([string[]]$arguments) {
    $quoted = $arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }
    $joined = $quoted -join ' '
    Write-Host "VBoxManage> $joined" -ForegroundColor Cyan
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $vbox
    $psi.Arguments = $joined
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($stdout) { Write-Host $stdout }
    if ($stderr) { Write-Host $stderr -ForegroundColor DarkGray }
    if ($p.ExitCode -ne 0) {
        throw "VBoxManage failed (exit $($p.ExitCode)): $joined"
    }
}

Write-Host "Staging host artifacts to $staging" -ForegroundColor White
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force -Path $staging | Out-Null

Copy-Item (Join-Path $outDir 'Launcher.exe') $staging
Copy-Item (Join-Path $outDir 'MyMemoryDriver.sys') $staging
Copy-Item (Join-Path $outDir 'test_read.exe') $staging
Copy-Item (Join-Path $outDir 'opencv_world470.dll') $staging
if (Test-Path (Join-Path $outDir 'runtime')) {
    Copy-Item -Recurse (Join-Path $outDir 'runtime') (Join-Path $staging 'runtime')
}
if (Test-Path (Join-Path $outDir 'drivers')) {
    Copy-Item -Recurse (Join-Path $outDir 'drivers') (Join-Path $staging 'drivers')
}

try {
    $preDriverSnapshot = "pre-driver-load-$(Get-Date -Format 'yyyy-MM-dd-HHmmss')"
    Write-Host "Creating VM snapshot $preDriverSnapshot before driver load" -ForegroundColor White
    VBoxRun @('snapshot', $VmName, 'take', $preDriverSnapshot)

    Write-Host "Copying artifacts to VM $VmName" -ForegroundColor White
    VBoxRun @('guestcontrol', $VmName, 'copyto', '--recursive', '--username', 'vboxuser', '--password', $Password, $staging, $vmDestParent)

    Write-Host "Loading driver via SCM" -ForegroundColor White
    VBoxRun @('guestcontrol', $VmName, 'run', '--username', 'vboxuser', '--password', $Password,
              '--cwd', $vmDest, '--wait-stdout', '--wait-stderr', '--exe', "$vmDest\Launcher.exe", '--', 'load', "$vmDest\MyMemoryDriver.sys")

    Write-Host "Pinging driver" -ForegroundColor White
    VBoxRun @('guestcontrol', $VmName, 'run', '--username', 'vboxuser', '--password', $Password,
              '--cwd', $vmDest, '--wait-stdout', '--wait-stderr', '--exe', "$vmDest\Launcher.exe", '--', 'ping')

    Write-Host "Running test_read harness" -ForegroundColor White
    VBoxRun @('guestcontrol', $VmName, 'run', '--username', 'vboxuser', '--password', $Password,
              '--cwd', $vmDest, '--wait-stdout', '--wait-stderr', '--exe', "$vmDest\test_read.exe")

    Write-Host "Unloading driver" -ForegroundColor White
    VBoxRun @('guestcontrol', $VmName, 'run', '--username', 'vboxuser', '--password', $Password,
              '--cwd', $vmDest, '--wait-stdout', '--wait-stderr', '--exe', "$vmDest\Launcher.exe", '--', 'unload')

    Write-Host "Copying launcher.log back from VM" -ForegroundColor White
    $logDest = Join-Path $env:TEMP 'PUBGVMTest_launcher.log'
    VBoxRun @('guestcontrol', $VmName, 'copyfrom', '--username', 'vboxuser', '--password', $Password,
              '--target-directory', $env:TEMP, "$vmDest\launcher.log")
    if (Test-Path $logDest) { Write-Host "VM log saved to $logDest" -ForegroundColor Green }
}
catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    throw
}
finally {
    if ($CleanSnapshot) {
        Write-Host "Powering off VM $VmName" -ForegroundColor White
        try { VBoxRun @('controlvm', $VmName, 'poweroff') } catch { Write-Host "Poweroff note: $_" -ForegroundColor DarkGray }

        Write-Host "Waiting for VM to stop" -ForegroundColor White
        $stopTimeout = 60
        $elapsed = 0
        while ($elapsed -lt $stopTimeout) {
            $info = & $vbox showvminfo $VmName --machinereadable 2>$null | Where-Object { $_ -like 'VMState=*' }
            if ($info -like 'VMState="poweredoff"*') { break }
            Start-Sleep -Seconds 1
            $elapsed++
        }

        Write-Host "Restoring VM snapshot $CleanSnapshot" -ForegroundColor White
        VBoxRun @('snapshot', $VmName, 'restore', $CleanSnapshot)
        Write-Host "VM restored to $CleanSnapshot" -ForegroundColor Green
    }
    else {
        Write-Host "No -CleanSnapshot supplied; VM left at $preDriverSnapshot" -ForegroundColor Yellow
    }
    Write-Host "VM smoke test complete" -ForegroundColor Green
}
