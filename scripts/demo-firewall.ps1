# ---------------------------------------------------------------------------
# scripts/demo-firewall.ps1
#
# Single-laptop demo: turn the PUBLIC firewall profile off for one attestation,
# then put it back. Requires an elevated PowerShell.
#
#   .\scripts\demo-firewall.ps1 off-public    record state, disable Public profile
#   .\scripts\demo-firewall.ps1 restore       put the recorded state back
#
# The previous state is written to verifier\data\demo-firewall-state.json (local
# disk, git-ignored) so `restore` still works if the terminal or the script died.
# It is deleted after a successful restore. Nothing is sent anywhere.
#
# Safety: if disabling fails or the profile does not read back as disabled, the
# original state is restored immediately, before the error is raised.
# ---------------------------------------------------------------------------
param(
    [Parameter(Position = 0)]
    [ValidateSet('off-public', 'restore')]
    [string]$Action = 'off-public'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $root 'verifier\data'
$stateFile = Join-Path $stateDir 'demo-firewall-state.json'

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script needs an elevated (Administrator) PowerShell window.'
    }
}

function Set-PublicProfile([bool]$enabled) {
    Set-NetFirewallProfile -Profile Public -Enabled $enabled
    $after = Get-NetFirewallProfile -Profile Public
    if ([bool]$after.Enabled -ne $enabled) {
        throw "Public profile did not change (expected Enabled=$enabled, got $($after.Enabled))."
    }
    return [bool]$after.Enabled
}

Assert-Elevated

Write-Host ''
Write-Host 'ZK Posture Gate - demo firewall helper' -ForegroundColor Cyan
Write-Host "action: $Action"
Write-Host ''

if ($Action -eq 'off-public') {
    $before = Get-NetFirewallProfile -Profile Public
    $enabledBefore = [bool]$before.Enabled

    [System.IO.Directory]::CreateDirectory($stateDir) | Out-Null
    [pscustomobject]@{
        profile       = 'Public'
        enabledBefore = $enabledBefore
        recordedAt    = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -Encoding UTF8 $stateFile

    Write-Host "Recorded: Public profile Enabled=$enabledBefore" -ForegroundColor DarkGray

    if (-not $enabledBefore) {
        Write-Host 'The Public profile is ALREADY disabled. Nothing to turn off.' -ForegroundColor Yellow
        Write-Host 'Use "restore" when you are done with the demo.' -ForegroundColor Yellow
        Write-Host ''
        exit 0
    }

    try {
        Set-PublicProfile $false | Out-Null
        Write-Host 'Public firewall profile is now DISABLED.' -ForegroundColor Green
        Write-Host 'A compliant policy requires all profiles, so attestations should now be DENIED.' -ForegroundColor Green
        Write-Host ''
        Write-Host 'Restore immediately after that attestation:' -ForegroundColor Cyan
        Write-Host '  .\scripts\demo-firewall.ps1 restore' -ForegroundColor Cyan
        Write-Host ''
    } catch {
        Write-Host "Failed to disable the profile: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Restoring the previous state (Enabled=$enabledBefore)..." -ForegroundColor Yellow
        Set-PublicProfile $enabledBefore | Out-Null
        throw
    }
    exit 0
}

# --- restore -------------------------------------------------------------
if (-not (Test-Path $stateFile)) {
    Write-Host 'No recorded firewall state was found, so nothing is restored automatically.' -ForegroundColor Yellow
    Write-Host 'Set it yourself if needed:' -ForegroundColor Yellow
    Write-Host '  Set-NetFirewallProfile -Profile Public -Enabled True' -ForegroundColor Yellow
    Write-Host ''
    exit 1
}

$saved = Get-Content $stateFile -Raw | ConvertFrom-Json
$restored = Set-PublicProfile ([bool]$saved.enabledBefore)
Remove-Item $stateFile -Force

Write-Host "Public firewall profile restored to Enabled=$restored (as recorded at $($saved.recordedAt))." -ForegroundColor Green
Write-Host 'Verify: Get-NetFirewallProfile -Profile Public | Select-Object Name, Enabled' -ForegroundColor Cyan
Write-Host ''
