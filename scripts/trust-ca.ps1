<#
  scripts/trust-ca.ps1

  Imports the local ZK Posture Gate CA into the CURRENT USER's trusted root
  store so the browser stops warning about the demo certificate. No admin
  rights, no machine-wide change, and nothing else on the laptop trusts it.

  Usage:
    .\scripts\trust-ca.ps1            # add / refresh
    .\scripts\trust-ca.ps1 -Remove    # remove every ZK Posture Gate CA

  Run this once. If the CA is later regenerated (data folder deleted), run it
  again; the old CA is removed first so the store does not accumulate entries.
#>

param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$caPath = Join-Path $PSScriptRoot '..\verifier\data\tls\ca.crt.pem'
$store = 'Cert:\CurrentUser\Root'
$subject = 'CN=ZK Posture Gate Local CA'

function Remove-GateCas {
  $old = Get-ChildItem $store | Where-Object { $_.Subject -eq $subject }
  foreach ($cert in $old) {
    Remove-Item -Path $cert.PSPath -Force
    Write-Host "  Removed old CA $($cert.Thumbprint)"
  }
}

if ($Remove) {
  Remove-GateCas
  Write-Host '  Done. The browser will warn about the demo certificate again.'
  exit 0
}

if (-not (Test-Path $caPath)) {
  Write-Error "No CA found at $caPath. Start the verifier once (it creates the CA), then retry."
  exit 1
}

# Replace a previous CA rather than trusting both forever.
Remove-GateCas

$imported = Import-Certificate -FilePath $caPath -CertStoreLocation $store
Write-Host ''
Write-Host "  Trusted for the current user: $($imported.Subject)"
Write-Host "  SHA-1 thumbprint: $($imported.Thumbprint)"
Write-Host '  Close and reopen the browser, then use https://127.0.0.1:3000'
Write-Host ''
Write-Host '  Applies to this Windows user only. Undo with: .\scripts\trust-ca.ps1 -Remove'
