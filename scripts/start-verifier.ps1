# ---------------------------------------------------------------------------
# scripts/start-verifier.ps1
#
# Start the verifier + dashboard on the main computer.
#
#   .\scripts\start-verifier.ps1          local only (127.0.0.1:3000)
#   .\scripts\start-verifier.ps1 -Lan     listen on 0.0.0.0:3000 for the demo
#
# The admin password is read into this process's environment only. It is never
# written to a file and never leaves the machine.
# ---------------------------------------------------------------------------
param([switch]$Lan)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $env:ADMIN_PASSWORD) {
    $secure = Read-Host -AsSecureString -Prompt 'Admin password (12+ characters)'
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $env:ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

if ($Lan) {
    $env:DEMO_LAN = '1'
    Write-Host 'DEMO_LAN=1: verifier will listen on 0.0.0.0:3000 (plain HTTP, demo only).'
    Write-Host 'If laptops cannot connect, run in an elevated shell: .\scripts\setup-firewall-rule.ps1'
} else {
    $env:DEMO_LAN = '0'
}

if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing pinned dependencies (npm ci)...'
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
}

if (-not (Test-Path 'circuits\build\verification_key.json')) {
    Write-Host 'Circuit artifacts missing. Run this first:'
    Write-Host '  $env:CIRCOM_BIN = "C:\path\to\circom.exe"; npm run setup:circuit'
    exit 1
}

node verifier\server.js
