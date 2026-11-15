# ---------------------------------------------------------------------------
# agent/lib/posture.ps1
#
# Read-only posture collection for the ZK Posture Gate agent.
# Prints ONE compressed JSON object. Node consumes it as private circuit input;
# the values are never printed to the console by the agent itself.
#
# Design notes (why these APIs):
#   * OS build: registry CurrentBuild + UBR. UBR is the revision that actually
#     moves with monthly updates, so build*100000+UBR is the real patch level.
#   * Update age: Windows Update COM history first (Microsoft.Update.Session),
#     because it records the date updates were INSTALLED, which is what the
#     policy is about. Get-HotFix is the fallback (only lists some updates).
#   * Firewall: Get-NetFirewallProfile, all three profiles must be Enabled.
#   * Defender: Get-MpComputerStatus RealTimeProtectionEnabled.
#   * BitLocker: optional; skipped silently when not elevated.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$message) {
    $out = [ordered]@{ ok = $false; error = $message }
    $out | ConvertTo-Json -Compress
    exit 0
}

try {
    # --- OS build ----------------------------------------------------------
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuild
    $ubr = 0
    if ($null -ne $cv.UBR) { $ubr = [int]$cv.UBR }

    # --- Days since last installed update ----------------------------------
    $lastInstalled = $null
    $source = 'none'

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = [int]$searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $take = [Math]::Min($total, 100)
            $history = $searcher.QueryHistory(0, $take)
            foreach ($entry in $history) {
                # ResultCode 2 = orcSucceeded - only count updates that installed
                if ($entry.ResultCode -eq 2) {
                    $lastInstalled = $entry.Date
                    $source = 'windows-update-com'
                    break
                }
            }
        }
    } catch {
        $source = 'windows-update-com-failed'
    }

    if ($null -eq $lastInstalled) {
        try {
            $hotfix = Get-HotFix -ErrorAction Stop |
                Where-Object { $null -ne $_.InstalledOn } |
                Sort-Object InstalledOn -Descending |
                Select-Object -First 1
            if ($null -ne $hotfix) {
                $lastInstalled = $hotfix.InstalledOn
                $source = 'get-hotfix'
            }
        } catch {
            $source = 'get-hotfix-failed'
        }
    }

    if ($null -eq $lastInstalled) { Fail 'no installed-update date found (update history empty)' }

    $ageDays = [int][Math]::Floor(((Get-Date) - $lastInstalled.ToLocalTime()).TotalDays)
    if ($ageDays -lt 0) { $ageDays = 0 }

    # --- Firewall: must be enabled on ALL profiles -------------------------
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($profiles.Count -eq 0) { Fail 'no firewall profiles returned' }
    $firewallAll = $true
    foreach ($p in $profiles) { if (-not $p.Enabled) { $firewallAll = $false } }

    # --- Defender real-time protection ------------------------------------
    $defenderRealTime = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defenderRealTime = [bool]$mp.RealTimeProtectionEnabled
    } catch {
        $defenderRealTime = $null
    }
    if ($null -eq $defenderRealTime) { Fail 'could not read Defender status' }

    # --- BitLocker (optional, needs admin) --------------------------------
    $bitlocker = $null
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $bitlocker = ($bl.ProtectionStatus -eq 'On')
    } catch {
        $bitlocker = $null   # not elevated or not available: skip gracefully
    }

    [ordered]@{
        ok                  = $true
        build               = $build
        ubr                 = $ubr
        updateAgeDays       = $ageDays
        updateSource        = $source
        firewallAllProfiles = [bool]$firewallAll
        defenderRealTime    = [bool]$defenderRealTime
        bitlocker           = $bitlocker
    } | ConvertTo-Json -Compress

} catch {
    Fail $_.Exception.Message
}
