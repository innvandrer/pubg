#Requires -Version 5.1
<#
.SYNOPSIS
    Test-sign MyMemoryDriver.sys with a local code-signing certificate.

.DESCRIPTION
    Creates $env:USERPROFILE\PubgMemVisTest.pfx if missing (password default: test1234),
    then signs the .sys with signtool. Does not write the PFX into the repo.

    Set PUBG_SKIP_DRIVER_SIGN=1 to no-op (used by build.ps1 -SkipSign).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DriverSys,

    [string] $CertPassword = 'test1234',

    [switch] $AllowMissingTools
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-SignOk([string] $Message) {
    Write-Host "    OK: $Message" -ForegroundColor Green
}

function Write-SignWarn([string] $Message) {
    Write-Host "    WARN: $Message" -ForegroundColor Yellow
}

function Find-SignTool {
    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (-not (Test-Path $kitsRoot)) {
        throw "Windows SDK not found under $kitsRoot"
    }

    $signtool = Get-ChildItem -Path $kitsRoot -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $signtool) {
        throw "signtool.exe (x64) not found. Install Windows SDK."
    }

    return $signtool.FullName
}

function Get-TestCertPaths {
    return @{
        Pfx = Join-Path $env:USERPROFILE 'PubgMemVisTest.pfx'
        Cer = Join-Path $env:USERPROFILE 'PubgMemVisTest.cer'
    }
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ExistingTestCert {
    $subjects = @('CN=PubgMemVis Test', 'CN=PubgMemVisTest')
    Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.HasPrivateKey -and (
                $subjects -contains $_.Subject -or
                $_.Subject -like 'CN=PubgMemVis*'
            )
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

function Ensure-TestCertificate {
    param([string] $Password)

    $paths = Get-TestCertPaths
    $existing = Get-ExistingTestCert
    if ($existing) {
        Write-SignOk "Test certificate in CurrentUser\My: $($existing.Subject) ($($existing.Thumbprint))"
        Export-TestCertificateFiles -Cert $existing -Paths $paths -Password $Password
        return @{ Paths = $paths; Cert = $existing }
    }

    if (Test-Path $paths.Pfx) {
        Write-SignOk "Test certificate PFX exists: $($paths.Pfx)"
        return @{ Paths = $paths; Cert = $null }
    }

    Write-Host "==> Creating self-signed test code-signing certificate" -ForegroundColor Cyan

    $cert = $null
    $attempts = @(
        @{ Name = 'CodeSigningCert'; Script = { New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=PubgMemVisTest' -CertStoreLocation 'Cert:\CurrentUser\My' } },
        @{ Name = 'CodeSigningCert+SHA256'; Script = { New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=PubgMemVis Test' -CertStoreLocation 'Cert:\CurrentUser\My' -HashAlgorithm SHA256 } },
        @{ Name = 'Custom EKU'; Script = { New-SelfSignedCertificate -Type Custom -Subject 'CN=PubgMemVisTest' -KeyUsage DigitalSignature -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -CertStoreLocation 'Cert:\CurrentUser\My' } }
    )

    $lastError = $null
    foreach ($attempt in $attempts) {
        try {
            $cert = & $attempt.Script
            Write-SignOk "Created cert via $($attempt.Name): $($cert.Thumbprint)"
            break
        }
        catch {
            $lastError = $_.Exception.Message
            Write-SignWarn "$($attempt.Name) failed: $lastError"
        }
    }

    if (-not $cert) {
        throw "Could not create a test code-signing certificate. Last error: $lastError"
    }

    Export-TestCertificateFiles -Cert $cert -Paths $paths -Password $Password
    return @{ Paths = $paths; Cert = $cert }
}

function Export-TestCertificateFiles {
    param(
        $Cert,
        $Paths,
        [string] $Password
    )

    try {
        if (-not (Test-Path $Paths.Cer)) {
            Export-Certificate -Cert $Cert -FilePath $Paths.Cer | Out-Null
        }
        if (-not (Test-Path $Paths.Pfx)) {
            $secure = ConvertTo-SecureString $Password -AsPlainText -Force
            Export-PfxCertificate -Cert $Cert -FilePath $Paths.Pfx -Password $secure | Out-Null
            Write-SignOk "Exported PFX: $($Paths.Pfx) (user profile only, not the repo)"
        }
    }
    catch {
        Write-SignWarn "Could not export PFX/CER (will sign from the certificate store): $($_.Exception.Message)"
    }
}

function Import-TestCertificateTrust {
    param([string] $CerPath)

    if (-not (Test-Path $CerPath)) {
        return
    }
    if (-not (Test-Admin)) {
        Write-SignWarn "Not Administrator: skip LocalMachine TrustedPublisher/Root import. Enable test signing and/or import the .cer as Admin (see build.md)."
        return
    }

    try {
        Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
        Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Write-SignOk "Imported test cert to LocalMachine TrustedPublisher and Root"
    }
    catch {
        Write-SignWarn "Could not import test cert to LocalMachine stores: $($_.Exception.Message)"
    }
}

if ($env:PUBG_SKIP_DRIVER_SIGN -eq '1') {
    Write-SignWarn "PUBG_SKIP_DRIVER_SIGN=1; skipping driver test-sign"
    exit 0
}

if (-not (Test-Path $DriverSys)) {
    throw "Driver not found for signing: $DriverSys"
}

try {
    $signtool = Find-SignTool
}
catch {
    if ($AllowMissingTools) {
        Write-SignWarn $_.Exception.Message
        exit 0
    }
    throw
}

$created = Ensure-TestCertificate -Password $CertPassword
$paths = $created.Paths
$cert = $created.Cert
Import-TestCertificateTrust -CerPath $paths.Cer

Write-Host "==> Signing $DriverSys" -ForegroundColor Cyan

$signTargets = @()
if ($cert -and $cert.Thumbprint) {
    $signTargets += @{ Name = "store thumbprint $($cert.Thumbprint)"; Args = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/sha1', $cert.Thumbprint) }
}
if ($paths.Pfx -and (Test-Path $paths.Pfx)) {
    $signTargets += @{ Name = "PFX $($paths.Pfx)"; Args = @('sign', '/fd', 'SHA256', '/a', '/td', 'SHA256', '/f', $paths.Pfx, '/p', $CertPassword) }
}

if ($signTargets.Count -eq 0) {
    throw "No certificate or PFX available to sign $DriverSys"
}

$signed = $false
foreach ($target in $signTargets) {
    $withTs = $target.Args + @('/tr', 'http://timestamp.digicert.com', $DriverSys)
    $withoutTs = $target.Args + @($DriverSys)
    Write-Host "    Trying $($target.Name)"
    & $signtool @withTs | Out-Host
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-SignWarn "Timestamped sign failed (exit $code); retrying without timestamp"
        & $signtool @withoutTs | Out-Host
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        $signed = $true
        break
    }
    Write-SignWarn "$($target.Name) failed (exit $code)"
}

if (-not $signed) {
    throw "signtool sign failed for $DriverSys"
}

Write-SignOk "Signed: $DriverSys"
$sig = Get-AuthenticodeSignature -FilePath $DriverSys
Write-Host "    Authenticode Status: $($sig.Status)"
if ($sig.SignerCertificate) {
    Write-Host "    Signer: $($sig.SignerCertificate.Subject)"
}
if ($sig.Status -eq 'NotSigned') {
    throw "signtool reported success but Authenticode Status is NotSigned"
}
