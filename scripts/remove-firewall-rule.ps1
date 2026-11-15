# ---------------------------------------------------------------------------
# scripts/remove-firewall-rule.ps1
#
# Removes the inbound TCP 3000 rule created for the demo.
# Run this in an ELEVATED PowerShell window when the demo is over.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$ruleName = 'ZK Posture Gate (TCP 3000)'

$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "No rule named '$ruleName' found. Nothing to remove."
    exit 0
}

Remove-NetFirewallRule -DisplayName $ruleName
Write-Host "Removed firewall rule: $ruleName"
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host 'WARNING: rule still present.'
}
