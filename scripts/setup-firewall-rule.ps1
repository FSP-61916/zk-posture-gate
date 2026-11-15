# ---------------------------------------------------------------------------
# scripts/setup-firewall-rule.ps1
#
# Opens inbound TCP 3000 for the 3-laptop demo.
#
# PRIVATE profile only: the demo runs on a hotspot or a router we control.
# Never run this on a public network profile.
# Run this in an ELEVATED PowerShell window.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$ruleName = 'ZK Posture Gate (TCP 3000)'

$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Rule already exists: $ruleName"
} else {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Description 'Demo only: ZK Posture Gate verifier + dashboard' `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 3000 `
        -Profile Private | Out-Null
    Write-Host "Created inbound rule: $ruleName (Private profile, TCP 3000)"
}

Write-Host ''
Write-Host 'Verify with:'
Get-NetFirewallRule -DisplayName $ruleName | Select-Object DisplayName, Enabled, Profile, Direction, Action
Get-NetFirewallRule -DisplayName $ruleName | Get-NetFirewallPortFilter | Select-Object Protocol, LocalPort
Write-Host ''
Write-Host 'Remove before the demo ends: scripts\remove-firewall-rule.ps1'
