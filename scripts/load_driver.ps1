param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath
)

$ServiceName = "MyMemoryDriver"

if (-not (Test-Path $DriverPath)) {
    Write-Error "Driver not found: $DriverPath"
    exit 1
}

$FullPath = (Resolve-Path $DriverPath).Path

Write-Host "Stopping existing service..."
sc.exe stop $ServiceName 2>$null | Out-Null
sc.exe delete $ServiceName 2>$null | Out-Null

Write-Host "Creating service..."
sc.exe create $ServiceName type= kernel start= demand binPath= "`"$FullPath`""
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Starting driver..."
sc.exe start $ServiceName
exit $LASTEXITCODE
