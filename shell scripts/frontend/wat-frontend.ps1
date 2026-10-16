[CmdletBinding()]
param(
    [string] $AllowedHosts = $env:JOSH_ALLOWED_HOSTS
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python 3 is required.'
}
if ($AllowedHosts) { $env:JOSH_ALLOWED_HOSTS = $AllowedHosts }
$server = Join-Path $PSScriptRoot '..\..\sources\jam.py'
$allowedlistFile = Join-Path $PSScriptRoot '..\..\allowed_hosts.txt'
$port = if ($env:JOSH_PORT) { $env:JOSH_PORT } else {'8000'}
Write-Host "J.O.S.H security workspace: http//127.0.0.1:$port"
$fileHosts = @()
if (Test-Path -LiteralPath $allowedlistFile) {
    $fileHosts = @(Get-Content -LiteralPath $allowedlistFile) | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })
}
if (-not $env:JOSH_ALLOWED_HOSTS -and -not $fileHosts.Count) {
	Write-Host 'Scanning is disabled until you add an exact hostname to allowed_hosts.txt.'
}
python $server

