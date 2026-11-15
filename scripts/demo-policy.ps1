# ---------------------------------------------------------------------------
# scripts/demo-policy.ps1
#
# Single-laptop demo: change the verifier policy to match (or exceed) THIS
# machine's real posture, so the difference between GRANTED and DENIED is honest.
#
#   .\scripts\demo-policy.ps1 set-current   policy == this laptop's real values
#   .\scripts\demo-policy.ps1 raise         policy above this laptop's real values
#   .\scripts\demo-policy.ps1 reset         restore the policy from before the demo
#
# It reads the real values by running agent\lib\posture.ps1. It prints them to
# THIS CONSOLE ONLY (no file, no network, no log) so the presenter can show that
# the policy numbers equal the machine's real numbers. Treat that screen as
# sensitive: do not stream it.
#
# The admin password comes from $env:ADMIN_PASSWORD (prompted if absent) and is
# never written anywhere.
#
# Honest caveat: setting the policy to the real values sends those numbers to the
# VERIFIER as policy (that is the demo). The verifier's policy file then contains
# them, which is why "reset" restores the pre-demo policy afterwards. No
# attestation ever carries them.
# ---------------------------------------------------------------------------
param(
    [Parameter(Position = 0)]
    [ValidateSet('set-current', 'raise', 'reset')]
    [string]$Action = 'set-current',

    [string]$BaseUrl = $(if ($env:VERIFIER_URL) { $env:VERIFIER_URL } else { 'https://127.0.0.1:3000' })
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$postureScript = Join-Path $root 'agent\lib\posture.ps1'
$backupDir = Join-Path $root 'verifier\data'
$backupFile = Join-Path $backupDir 'demo-policy-backup.json'

function Get-AdminSession {
    $password = $env:ADMIN_PASSWORD
    if (-not $password) {
        $secure = Read-Host -AsSecureString -Prompt 'Admin password (12+ characters)'
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }

    $login = Invoke-RestMethod "$BaseUrl/api/admin/login" `
        -Method Post `
        -ContentType 'application/json' `
        -Body (@{ password = $password } | ConvertTo-Json) `
        -SessionVariable session

    return [pscustomobject]@{ Session = $session; Csrf = $login.csrfToken }
}

function Save-Policy($admin, $policy) {
    $body = @{
        minBuild        = [int64]$policy.minBuild
        maxUpdateAge    = [int]$policy.maxUpdateAge
        requireFirewall = [bool]$policy.requireFirewall
        requireDefender = [bool]$policy.requireDefender
    } | ConvertTo-Json

    return Invoke-RestMethod "$BaseUrl/api/admin/policy" `
        -Method Post `
        -WebSession $admin.Session `
        -Headers @{ 'x-csrf-token' = $admin.Csrf } `
        -ContentType 'application/json' `
        -Body $body
}

function Read-RealPosture {
    $json = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $postureScript
    if ($LASTEXITCODE -ne 0) {
        throw "agent\lib\posture.ps1 failed (exit $LASTEXITCODE)."
    }
    $raw = $json | ConvertFrom-Json
    if (-not $raw.ok) {
        throw "posture.ps1 reported: $($raw.error)"
    }
    return $raw
}

Write-Host ''
Write-Host 'ZK Posture Gate - demo policy helper' -ForegroundColor Cyan
Write-Host "verifier: $BaseUrl"
Write-Host "action:   $Action"
Write-Host ''

$admin = Get-AdminSession
$current = Invoke-RestMethod "$BaseUrl/api/policy"

if ($Action -eq 'reset') {
    if (-not (Test-Path $backupFile)) {
        Write-Host 'No pre-demo policy backup found. Nothing to reset; policy is unchanged.' -ForegroundColor Yellow
        exit 0
    }
    $saved = Get-Content $backupFile -Raw | ConvertFrom-Json
    $result = Save-Policy $admin $saved
    Remove-Item $backupFile -Force
    Write-Host "Policy reset to the pre-demo values. Now v$($result.policy.version)." -ForegroundColor Green
    Write-Host "  minBuild=$($result.policy.minBuild)  maxUpdateAge=$($result.policy.maxUpdateAge)  requireFirewall=$($result.policy.requireFirewall)  requireDefender=$($result.policy.requireDefender)"
    Write-Host ''
    exit 0
}

# --- read this machine's real values -------------------------------------
$posture = Read-RealPosture
$encoded = [int64]$posture.build * 100000 + [int64]$posture.ubr

Write-Host 'LOCAL SCREEN ONLY - real posture values, printed so you can show that the' -ForegroundColor Yellow
Write-Host 'policy equals reality. Never stored, never sent, do not stream this screen.' -ForegroundColor Yellow
Write-Host ''
Write-Host "  CurrentBuild      : $($posture.build)"
Write-Host "  UBR               : $($posture.ubr)"
Write-Host "  encoded build     : $encoded   (build * 100000 + UBR)"
Write-Host "  updateAgeDays     : $($posture.updateAgeDays)   (source: $($posture.updateSource))"
Write-Host "  firewall (all)    : $($posture.firewallAllProfiles)"
Write-Host "  Defender realtime : $($posture.defenderRealTime)"
Write-Host ''

# --- keep the pre-demo policy once --------------------------------------
if (-not (Test-Path $backupFile)) {
    [System.IO.Directory]::CreateDirectory($backupDir) | Out-Null
    [pscustomobject]@{
        savedAt         = (Get-Date).ToUniversalTime().ToString('o')
        minBuild        = [int64]$current.minBuild
        maxUpdateAge    = [int]$current.maxUpdateAge
        requireFirewall = [bool]$current.requireFirewall
        requireDefender = [bool]$current.requireDefender
    } | ConvertTo-Json | Set-Content -Encoding UTF8 $backupFile
    Write-Host "Saved the pre-demo policy to verifier\data\demo-policy-backup.json (reset will restore it)." -ForegroundColor DarkGray
}

# --- choose the new policy ----------------------------------------------
# Requirements stay true so the firewall/Defender checks are exercised.
if ($Action -eq 'set-current') {
    $next = @{
        minBuild        = $encoded
        maxUpdateAge    = [int]$posture.updateAgeDays
        requireFirewall = $true
        requireDefender = $true
    }
    Write-Host 'Setting the policy to EXACTLY this laptop''s real values (boundary case).' -ForegroundColor Cyan
} else {
    # One build increment above reality guarantees the build check fails.
    $next = @{
        minBuild        = [int64]($encoded + 100000)
        maxUpdateAge    = [int][Math]::Max(0, [int]$posture.updateAgeDays - 1)
        requireFirewall = $true
        requireDefender = $true
    }
    Write-Host 'Raising the policy ABOVE this laptop''s real values.' -ForegroundColor Cyan
}

if (-not $posture.firewallAllProfiles -or -not $posture.defenderRealTime) {
    Write-Host 'Warning: this machine currently fails firewall/Defender, so it will be DENIED' -ForegroundColor Yellow
    Write-Host 'even with set-current. Fix the machine first, or use this to show a denial.' -ForegroundColor Yellow
}

$result = Save-Policy $admin $next
Write-Host ''
Write-Host "Policy is now v$($result.policy.version)." -ForegroundColor Green
Write-Host "  minBuild=$($result.policy.minBuild)  maxUpdateAge=$($result.policy.maxUpdateAge)  requireFirewall=$($result.policy.requireFirewall)  requireDefender=$($result.policy.requireDefender)"
Write-Host ''
Write-Host 'Next:  node agent attest' -ForegroundColor Cyan
Write-Host 'Undo:  .\scripts\demo-policy.ps1 reset'
Write-Host ''
