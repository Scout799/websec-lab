param(
    [ValidateSet('setup', 'start', 'stop', 'status', 'browser')]
    [string]$Action = 'status',
    [string]$Profile = 'https-samesite-lax',
    [ValidateSet('chrome', 'msedge')]
    [string]$Browser = 'chrome',
    [switch]$TrustRoot
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $arguments = @('-m', 'websec_lab.https_lab', $Action, '--profile', $Profile, '--browser', $Browser)
    if ($TrustRoot) { $arguments += '--trust' }
    python @arguments
    if ($LASTEXITCODE -ne 0) { throw "HTTPS lab command failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}
