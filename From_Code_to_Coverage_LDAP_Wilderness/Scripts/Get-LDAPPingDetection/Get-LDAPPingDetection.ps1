<#
.SYNOPSIS
    Get-LDAPPingDetection.ps1 - Detect LDAP Ping (ldapnomnom-style) username enumeration
    by correlating Event 5156 (source IP) with netlogon.log (queried usernames).

.DESCRIPTION
    Part 6 companion script for "From Code to Coverage" blog series.
    
    ldapnomnom and similar tools send LDAP Ping requests (NtVer + AAC + User= filter)
    to enumerate valid Active Directory accounts. Windows logs two separate data sources:
    
      - Event 5156 (Security log): Source IP of every inbound TCP connection to port 389/636
                                   Requires: Audit Filtering Platform Connection = Success
      
      - netlogon.log (%windir%\debug\netlogon.log): Every username queried + response type
                                   Requires: nltest /dbflag:0x2080ffff
    
    Neither source alone is complete. This script correlates them by timestamp to produce
    a unified view: WHO queried (from 5156) + WHAT they queried (from netlogon.log).

    LAB-CONFIRMED FINDINGS (NEWJERSEY.SOPRANOS.LOCAL):
      - Event 5156 fires for ldapnomnom TCP port 389 AND port 636 (TLS) with full source IP
      - netlogon.log captures every username, hit/miss/disabled status
      - netlogon.log source IP is always (null) for LDAP Ping traffic
      - Disabled accounts appear in netlogon.log even though ldapnomnom reports them as Unknown
      - Timestamp correlation window of ~5 seconds reliably joins the two sources

.PARAMETER LogPath
    Path to netlogon.log. Default: $env:windir\debug\netlogon.log

.PARAMETER HoursBack
    How many hours of history to analyze. Default: 24

.PARAMETER CorrelationWindowSeconds
    Time window in seconds to join 5156 events with netlogon.log entries. Default: 5

.PARAMETER HoneytokenAccounts
    Comma-separated list of account names to alert on immediately if queried.
    These should be accounts that exist (so they return "Sam Logon Response Ex")
    but should never be legitimately queried anonymously.

.PARAMETER AlertThreshold
    Alert if a single source IP queries more than N unique usernames within the
    correlation window. Default: 10

.PARAMETER ExportPath
    Optional CSV export path for full results.

.PARAMETER EnableLogging
    If specified, enables the required logging (nltest + auditpol) automatically.
    Requires running as administrator on the DC.

.PARAMETER Monitor
    Real-time monitoring mode. Tails netlogon.log and polls Event 5156 every
    MonitorIntervalSeconds, alerting on new LDAP Ping activity as it happens.
    Press Ctrl+C to stop.

.PARAMETER MonitorIntervalSeconds
    How often to poll for new events in monitor mode. Default: 10 seconds.

.EXAMPLE
    # Monitor mode - real-time detection
    .\Get-LDAPPingDetection.ps1 -Monitor

.EXAMPLE
    # Monitor mode with honeytokens and tight polling
    .\Get-LDAPPingDetection.ps1 -Monitor -MonitorIntervalSeconds 5 -HoneytokenAccounts "administrator,svc_backup"

.EXAMPLE
    # Basic run - analyze last 24 hours
    .\Get-LDAPPingDetection.ps1

.EXAMPLE
    # With honeytokens and CSV export
    .\Get-LDAPPingDetection.ps1 -HoneytokenAccounts "administrator,admin,svc_backup,helpdesk" -ExportPath C:\Logs\ldap_ping_detections.csv

.EXAMPLE
    # Enable logging first, then analyze
    .\Get-LDAPPingDetection.ps1 -EnableLogging -HoursBack 1

.EXAMPLE
    # Tight correlation window for high-speed attacks
    .\Get-LDAPPingDetection.ps1 -CorrelationWindowSeconds 2 -AlertThreshold 5

.NOTES
    Author: Andrew Schwartz (@4ndr3w6S)
    Series: From Code to Coverage - Part 6
    License: MIT License
    Copyright (c) 2025 Andrew Schwartz (see LICENSE)
    
    PREREQUISITES:
      1. Run on Domain Controller
      2. Audit Filtering Platform Connection enabled:
         auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
      3. Netlogon debug logging enabled:
         nltest /dbflag:0x2080ffff
      
    WARNING: Filtering Platform Connection auditing generates HIGH volume on busy DCs.
    Filter aggressively in your SIEM. Focus on port 389/636 from non-DC sources.
    
    RELATED SCRIPTS:
      Get-ADWSAttribution.ps1 (Part 5B) - ADWS source IP correlation via Event 5156
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:windir\debug\netlogon.log",
    [int]$HoursBack = 24,
    [int]$CorrelationWindowSeconds = 5,
    [string]$HoneytokenAccounts = "",
    [int]$AlertThreshold = 10,
    [string]$ExportPath = "",
    [switch]$EnableLogging,
    [switch]$Monitor,
    [int]$MonitorIntervalSeconds = 10
)

#region ── SETUP ────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

$script:Version = "1.0"
$script:StartTime = Get-Date
$script:Findings = @()
$script:HoneytokenList = @()

if ($HoneytokenAccounts -ne "") {
    $script:HoneytokenList = $HoneytokenAccounts.Split(",").Trim().ToLower()
}

function Write-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         Get-LDAPPingDetection.ps1  v$script:Version                   ║" -ForegroundColor Cyan
    Write-Host "║         From Code to Coverage - Part 6                       ║" -ForegroundColor Cyan
    Write-Host "║         LDAP Ping Enumeration Detection                      ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "─── $Title " -ForegroundColor Yellow -NoNewline
    Write-Host ("─" * (60 - $Title.Length)) -ForegroundColor DarkGray
}

function Write-Finding {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Detail = ""
    )
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Red" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Cyan" }
        "INFO"     { "Gray" }
        default    { "White" }
    }
    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host $Message -ForegroundColor White
    if ($Detail) {
        Write-Host "           $Detail" -ForegroundColor DarkGray
    }
    $script:Findings += [PSCustomObject]@{
        Time     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Severity = $Severity
        Message  = $Message
        Detail   = $Detail
    }
}

#endregion

#region ── PREREQ CHECK ─────────────────────────────────────────────────────────

function Test-Prerequisites {
    Write-Section "Prerequisites Check"

    # Check running on DC
    $isDC = $false
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($computerSystem.DomainRole -ge 4) { $isDC = $true }
    } catch {}
    
    if ($isDC) {
        Write-Host "  [OK] Running on Domain Controller" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Not detected as DC - netlogon.log may be empty" -ForegroundColor Yellow
    }

    # Check netlogon.log exists
    if (Test-Path $LogPath) {
        $logSize = (Get-Item $LogPath).Length / 1KB
        Write-Host "  [OK] netlogon.log found ($([math]::Round($logSize, 1)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] netlogon.log not found at: $LogPath" -ForegroundColor Red
        Write-Host "            Enable with: nltest /dbflag:0x2080ffff" -ForegroundColor DarkYellow
        if (-not $EnableLogging) {
            Write-Host "            Or run with -EnableLogging to enable automatically" -ForegroundColor DarkYellow
        }
    }

    # Check Filtering Platform Connection auditing
    $auditResult = auditpol /get /subcategory:"Filtering Platform Connection" 2>$null
    $fpcEnabled = $auditResult | Select-String "Success" | Select-String -NotMatch "No Auditing"
    if ($fpcEnabled) {
        Write-Host "  [OK] Filtering Platform Connection auditing enabled" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] Filtering Platform Connection auditing not enabled" -ForegroundColor Red
        Write-Host "            Enable with: auditpol /set /subcategory:`"Filtering Platform Connection`" /success:enable" -ForegroundColor DarkYellow
        if (-not $EnableLogging) {
            Write-Host "            Or run with -EnableLogging to enable automatically" -ForegroundColor DarkYellow
        }
    }

    # Check honeytokens configured
    if ($script:HoneytokenList.Count -gt 0) {
        Write-Host "  [OK] $($script:HoneytokenList.Count) honeytoken account(s) configured" -ForegroundColor Green
        Write-Host "       Accounts: $($script:HoneytokenList -join ', ')" -ForegroundColor DarkGray
    } else {
        Write-Host "  [INFO] No honeytoken accounts configured" -ForegroundColor Gray
        Write-Host "         Use -HoneytokenAccounts 'admin,svc_backup,helpdesk' to add canaries" -ForegroundColor DarkGray
    }
}

function Enable-RequiredLogging {
    Write-Section "Enabling Required Logging"

    # Enable Filtering Platform Connection auditing
    Write-Host "  Enabling Filtering Platform Connection auditing..." -ForegroundColor Gray
    try {
        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable 2>$null
        Write-Host "  [OK] Filtering Platform Connection auditing enabled" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not enable FPC auditing: $_" -ForegroundColor Red
    }

    # Enable Netlogon debug logging
    Write-Host "  Enabling Netlogon debug logging..." -ForegroundColor Gray
    try {
        nltest /dbflag:0x2080ffff 2>$null | Out-Null

        # Set 100MB max log size to prevent disk issues
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Set-ItemProperty -Path $regPath -Name "MaximumLogFileSize" -Value 104857600 -Type DWord -Force
        Write-Host "  [OK] Netlogon debug logging enabled (max 100MB)" -ForegroundColor Green
        Write-Host "       Log: $LogPath" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [FAIL] Could not enable Netlogon logging: $_" -ForegroundColor Red
    }
}

#endregion

#region ── SOURCE 1: EVENT 5156 ─────────────────────────────────────────────────

function Get-5156Events {
    param([DateTime]$Since)

    Write-Section "Collecting Event 5156 (Filtering Platform Connection)"
    Write-Host "  Looking back: $HoursBack hours" -ForegroundColor Gray
    Write-Host "  Filter: Inbound TCP to port 389 or 636" -ForegroundColor Gray

    $events5156 = @()

    try {
        # XPath filter for inbound connections to port 389/636
        $xpath = @"
*[System[EventID=5156 and TimeCreated[timediff(@SystemTime) <= $($HoursBack * 3600000)]]]
and
*[EventData[Data[@Name='Direction'] and (Data[@Name='DestPort']='389' or Data[@Name='DestPort']='636')]]
"@
        # Simplified approach - get all 5156 and filter in PowerShell for reliability
        $rawEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=5156]]" `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $Since }

        foreach ($evt in $rawEvents) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $data[$d.Name] = $d.'#text'
            }

            # Only care about inbound to port 389/636
            $destPort = $data['DestPort']
            $direction = $data['Direction']

            if ($destPort -notin @('389','636')) { continue }
            if ($direction -notmatch '%%14592|Inbound') { continue }

            $srcIP = $data['SourceAddress']
            if ([string]::IsNullOrEmpty($srcIP)) { continue }
            if ($srcIP -in @('127.0.0.1','::1','0.0.0.0')) { continue }
            if ($srcIP -match '^fe80:') { continue }   # link-local IPv6 — DC Locator noise
            # Exclude DC self-queries (get DC IPs)
            $dcIPs = @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | 
                       Select-Object -ExpandProperty IPAddressToString)
            if ($srcIP -in $dcIPs) { continue }

            $events5156 += [PSCustomObject]@{
                Timestamp   = $evt.TimeCreated
                SourceIP    = $srcIP
                SourcePort  = $data['SourcePort']
                DestPort    = $destPort
                Protocol    = if ($data['Protocol'] -eq '6') { 'TCP' } else { $data['Protocol'] }
                Application = ($data['Application'] -split '\\')[-1]
                ProcessID   = $data['ProcessID']
            }
        }

        Write-Host "  Found $($events5156.Count) inbound connection(s) to port 389/636" -ForegroundColor $(if ($events5156.Count -gt 0) { 'Green' } else { 'Gray' })

        # Show top source IPs
        if ($events5156.Count -gt 0) {
            $topIPs = $events5156 | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 5
            Write-Host ""
            Write-Host "  Top source IPs:" -ForegroundColor Gray
            foreach ($ip in $topIPs) {
                $ports = ($events5156 | Where-Object {$_.SourceIP -eq $ip.Name} | 
                    Select-Object -ExpandProperty DestPort -Unique) -join ','
                Write-Host "    $($ip.Name.PadRight(18)) $($ip.Count) connection(s) on port $ports" -ForegroundColor White
            }
        }

    } catch {
        Write-Host "  [WARN] Could not read Security event log: $_" -ForegroundColor Yellow
        Write-Host "         Ensure script runs with sufficient privileges" -ForegroundColor DarkYellow
    }

    return @($events5156)
}

#endregion

#region ── SOURCE 2: NETLOGON.LOG ───────────────────────────────────────────────

function Get-NetlogonPingEntries {
    param([DateTime]$Since)

    Write-Section "Parsing netlogon.log"

    $pingEntries = @()
    $currentYear = (Get-Date).Year

    if (-not (Test-Path $LogPath)) {
        Write-Host "  [SKIP] netlogon.log not found" -ForegroundColor Yellow
        return @($pingEntries)
    }

    Write-Host "  Parsing: $LogPath" -ForegroundColor Gray

    try {
        $lines = Get-Content $LogPath -ErrorAction Stop
        Write-Host "  Lines read: $($lines.Count)" -ForegroundColor Gray

        # Track ping/response pairs
        # Format: MM/DD HH:MM:SS [MAILSLOT] [TID] Received ping from (null)((null)) (null) <username> on UDP LDAP
        # Format: MM/DD HH:MM:SS [MAILSLOT] [TID] DOMAIN: Ping response '<ResponseType>' <username> to \\(null) Site: ... on UDP LDAP

        $pendingPings = @{}  # key: username+thread, value: received timestamp

        foreach ($line in $lines) {
            # Only process MAILSLOT lines (LDAP Ping traffic)
            if ($line -notmatch '\[MAILSLOT\]') { continue }

            # Parse timestamp MM/DD HH:MM:SS
            if ($line -notmatch '^(\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})') { continue }
            $datePart = $Matches[1]
            $timePart = $Matches[2]

            try {
                $timestamp = [DateTime]::ParseExact(
                    "$datePart/$currentYear $timePart",
                    "MM/dd/yyyy HH:mm:ss",
                    $null
                )
                # Handle year rollover
                if ($timestamp -gt (Get-Date).AddHours(1)) {
                    $timestamp = $timestamp.AddYears(-1)
                }
            } catch { continue }

            if ($timestamp -lt $Since) { continue }

            # Extract thread ID
            $threadID = ""
            if ($line -match '\[MAILSLOT\]\s+\[(\d+)\]') {
                $threadID = $Matches[1]
            }

            # ── Received ping line ────────────────────────────────────────────
            # ldapnomnom enumeration: "Received ping from (null)((null)) (null) tony.soprano on UDP LDAP"
            # ldapnomnom --dump:      "Received ping from (null)((null)) (null) on UDP LDAP" (no username)
            # DC Locator (legit):     "Received ping from BADABING(BADABING.domain) domain. (null) on <Local>"
            if ($line -match 'Received ping from') {

                # ldapnomnom --dump mode: stripped ping with NO username field
                if ($line -match 'Received ping from \(null\)\(\(null\)\) \(null\) on (UDP LDAP|TCP LDAP)') {
                    # Dump mode generates connections but no username — track for 5156 correlation
                    $pingEntries += [PSCustomObject]@{
                        Timestamp    = $timestamp
                        Username     = "__DUMP_MODE__"
                        ResponseType = "RootDSE Dump"
                        IsHit        = $false
                        IsDisabled   = $false
                        IsDump       = $true
                        Transport    = $Matches[1]
                        Source       = "anonymous"
                        ThreadID     = $threadID
                        IsHoneytoken = $false
                    }
                    continue
                }
                # Regular username enumeration ping
                elseif ($line -match 'Received ping from \(null\)\(\(null\)\) \(null\) (.+?) on (UDP LDAP|TCP LDAP)') {
                    $username   = $Matches[1].Trim()
                    $transport  = $Matches[2]
                    $key        = "$username|$threadID"
                    $pendingPings[$key] = @{
                        Timestamp = $timestamp
                        Username  = $username
                        Transport = $transport
                        Source    = "anonymous"
                    }
                }
                # Legitimate DC Locator ping from domain-joined machine (has hostname)
                elseif ($line -match 'Received ping from (\S+)\((\S+)\)') {
                    # Skip - this is normal DC discovery, not enumeration
                    # We log it only if there are unusual usernames present
                    if ($line -match 'Received ping from \S+\(\S+\) \S+ (\S+) on') {
                        $possibleUser = $Matches[1]
                        # Skip null, domain names, and empty
                        if ($possibleUser -ne '(null)' -and 
                            $possibleUser -notmatch '\.' -and 
                            $possibleUser -ne '') {
                            # Legitimate client DC locator with user - log but mark as known source
                            $key = "$possibleUser|$threadID"
                            $pendingPings[$key] = @{
                                Timestamp = $timestamp
                                Username  = $possibleUser
                                Transport = "DC Locator"
                                Source    = "domain-joined"
                            }
                        }
                    }
                }
                continue
            }

            # ── Disabled account detection ────────────────────────────────────
            # "NlSamVerifyUserAccountEnabled: bobby.baccalieri account is disabled"
            if ($line -match 'NlSamVerifyUserAccountEnabled:\s+(.+?)\s+account is disabled') {
                $disabledUser = $Matches[1].Trim()
                $pingEntries += [PSCustomObject]@{
                    Timestamp    = $timestamp
                    Username     = $disabledUser
                    ResponseType = "DISABLED_ACCOUNT_DETECTED"
                    IsHit        = $false
                    IsDisabled   = $true
                    IsDump       = $false
                    Transport    = "unknown"
                    Source       = "anonymous"
                    ThreadID     = $threadID
                    IsHoneytoken = ($script:HoneytokenList -contains $disabledUser.ToLower())
                }
                continue
            }

            # ── Ping response line ────────────────────────────────────────────
            # "NEWJERSEY: Ping response 'Sam Logon Response Ex' tony.soprano to \\(null) Site: ..."
            # "NEWJERSEY: Ping response 'Sam User Unknown Ex' fake.person to \\(null) Site: ..."
            if ($line -match "Ping response '(.+?)'\s+(.+?)\s+to") {
                $responseType = $Matches[1].Trim()
                $username     = $Matches[2].Trim()

                # Skip null/empty/placeholder usernames
                if ([string]::IsNullOrWhiteSpace($username) -or 
                    $username -eq '(null)' -or 
                    $username -eq '-') { continue }

                $isHit = ($responseType -eq 'Sam Logon Response Ex')

                # Find matching pending ping
                $key = "$username|$threadID"
                $pingSource = "anonymous"
                $transport  = "LDAP Ping"

                if ($pendingPings.ContainsKey($key)) {
                    $pingSource = $pendingPings[$key].Source
                    $transport  = $pendingPings[$key].Transport
                    $pendingPings.Remove($key)
                }

                $isHoneytoken = ($script:HoneytokenList -contains $username.ToLower())

                $pingEntries += [PSCustomObject]@{
                    Timestamp    = $timestamp
                    Username     = $username
                    ResponseType = $responseType
                    IsHit        = $isHit
                    IsDisabled   = $false
                    IsDump       = $false
                    Transport    = $transport
                    Source       = $pingSource
                    ThreadID     = $threadID
                    IsHoneytoken = $isHoneytoken
                }
            }
        }

    } catch {
        Write-Host "  [WARN] Error parsing netlogon.log: $_" -ForegroundColor Yellow
    }

    $hits    = @($pingEntries | Where-Object { $_.IsHit }).Count
    $misses  = @($pingEntries | Where-Object { -not $_.IsHit -and -not $_.IsDisabled }).Count
    $disabled = @($pingEntries | Where-Object { $_.IsDisabled }).Count
    $honeys  = @($pingEntries | Where-Object { $_.IsHoneytoken }).Count

    Write-Host "  Parsed entries:  $($pingEntries.Count) total" -ForegroundColor Gray
    Write-Host "    Hits (valid enabled accounts): $hits" -ForegroundColor $(if ($hits -gt 0) {'Red'} else {'Gray'})
    Write-Host "    Misses (unknown accounts):     $misses" -ForegroundColor Gray
    Write-Host "    Disabled account detections:   $disabled" -ForegroundColor $(if ($disabled -gt 0) {'Yellow'} else {'Gray'})
    Write-Host "    Honeytoken hits:               $honeys" -ForegroundColor $(if ($honeys -gt 0) {'Red'} else {'Gray'})

    return @($pingEntries)
}

#endregion

#region ── CORRELATION ENGINE ────────────────────────────────────────────────────

function Invoke-Correlation {
    param(
        [array]$Events5156,
        [array]$PingEntries
    )

    Write-Section "Correlating Event 5156 with netlogon.log"
    Write-Host "  Correlation window: $CorrelationWindowSeconds seconds" -ForegroundColor Gray

    $correlatedSessions = @()

    if ($Events5156.Count -eq 0 -and $PingEntries.Count -eq 0) {
        Write-Host "  No data to correlate" -ForegroundColor Gray
        return $correlatedSessions
    }

    # Group 5156 events by source IP and find burst windows
    $ipGroups = $Events5156 | Group-Object SourceIP

    foreach ($ipGroup in $ipGroups) {
        $sourceIP = $ipGroup.Name
        $ipEvents = @($ipGroup.Group | Sort-Object Timestamp)

        # Find burst windows - cluster connections within CorrelationWindowSeconds of each other
        $windows = @()
        $currentWindow = @($ipEvents[0])

        for ($i = 1; $i -lt $ipEvents.Count; $i++) {
            $gap = ($ipEvents[$i].Timestamp - $currentWindow[-1].Timestamp).TotalSeconds
            if ($gap -le $CorrelationWindowSeconds) {
                $currentWindow += $ipEvents[$i]
            } else {
                if ($currentWindow.Count -ge 2) {
                    $windows += ,@($currentWindow)
                }
                $currentWindow = @($ipEvents[$i])
            }
        }
        if ($currentWindow.Count -ge 1) {
            $windows += ,@($currentWindow)
        }

        foreach ($window in $windows) {
            $windowStart = ($window | Measure-Object Timestamp -Minimum).Minimum
            $windowEnd   = ($window | Measure-Object Timestamp -Maximum).Maximum

            # Expand window slightly for netlogon.log correlation
            $lookStart = $windowStart.AddSeconds(-$CorrelationWindowSeconds)
            $lookEnd   = $windowEnd.AddSeconds($CorrelationWindowSeconds)

            # Find netlogon.log entries in this time window
            $matchedPings = @($PingEntries | Where-Object {
                $_.Timestamp -ge $lookStart -and $_.Timestamp -le $lookEnd
            })

            $hits      = @($matchedPings | Where-Object { $_.IsHit -and -not $_.IsDump })
            $misses    = @($matchedPings | Where-Object { -not $_.IsHit -and -not $_.IsDisabled -and -not $_.IsDump })
            $disabled  = @($matchedPings | Where-Object { $_.IsDisabled })
            $honeyhits = @($matchedPings | Where-Object { $_.IsHoneytoken -and $_.IsHit })
            $dumpPings = @($matchedPings | Where-Object { $_.IsDump })

            # Detect: 5156 connections with ZERO matching ping entries = likely --dump mode
            $isDumpMode = ($matchedPings.Count -eq 0 -and $window.Count -ge 1) -or ($dumpPings.Count -gt 0)

            $session = [PSCustomObject]@{
                SourceIP         = $sourceIP
                WindowStart      = $windowStart
                WindowEnd        = $windowEnd
                DurationSeconds  = ($windowEnd - $windowStart).TotalSeconds
                Connections      = $window.Count
                Ports            = ($window | Select-Object -ExpandProperty DestPort -Unique) -join ','
                TotalQueries     = $matchedPings.Count
                ValidAccounts    = $hits.Count
                UnknownAccounts  = $misses.Count
                DisabledAccounts = $disabled.Count
                HoneytokenHits   = $honeyhits.Count
                DumpModeDetected = $isDumpMode
                HitUsernames     = ($hits | Select-Object -ExpandProperty Username -Unique) -join ','
                DisabledUsernames= ($disabled | Select-Object -ExpandProperty Username -Unique) -join ','
                HoneytokenNames  = ($honeyhits | Select-Object -ExpandProperty Username -Unique) -join ','
                AllUsernames     = ($matchedPings | Where-Object { -not $_.IsDump } | 
                                    Select-Object -ExpandProperty Username -Unique | Sort-Object) -join ','
                CorrelationMethod = if ($dumpPings.Count -gt 0) { "5156+netlogon.log (--dump mode)" }
                                    elseif ($matchedPings.Count -gt 0) { "5156+netlogon.log" }
                                    else { "5156 only (possible --dump or no username queries)" }
            }

            $correlatedSessions += $session
        }
    }

    # Also surface netlogon.log entries that have no 5156 correlation
    # (possible UDP cLDAP, or 5156 auditing not enabled)
    if ($PingEntries.Count -gt 0) {
        $allCorrelatedTimes = @($correlatedSessions | ForEach-Object {
            $start = $_.WindowStart.AddSeconds(-$CorrelationWindowSeconds)
            $end   = $_.WindowEnd.AddSeconds($CorrelationWindowSeconds)
            @{ Start = $start; End = $end }
        })

        $uncorrelatedPings = @($PingEntries | Where-Object {
            $ping = $_
            $matched = $false
            foreach ($window in $allCorrelatedTimes) {
                if ($ping.Timestamp -ge $window.Start -and $ping.Timestamp -le $window.End) {
                    $matched = $true
                    break
                }
            }
            -not $matched
        })

        if ($uncorrelatedPings.Count -gt 0) {
            # Group uncorrelated pings into burst windows
            $sorted = @($uncorrelatedPings | Sort-Object Timestamp)
            $ucWindow = @($sorted[0])

            for ($i = 1; $i -lt $sorted.Count; $i++) {
                $gap = ($sorted[$i].Timestamp - $ucWindow[-1].Timestamp).TotalSeconds
                if ($gap -le ($CorrelationWindowSeconds * 3)) {
                    $ucWindow += $sorted[$i]
                } else {
                    if ($ucWindow.Count -gt 0) {
                        $hits     = @($ucWindow | Where-Object { $_.IsHit })
                        $misses   = @($ucWindow | Where-Object { -not $_.IsHit -and -not $_.IsDisabled })
                        $disabled = @($ucWindow | Where-Object { $_.IsDisabled })
                        $honeyhits = @($ucWindow | Where-Object { $_.IsHoneytoken -and $_.IsHit })

                        $correlatedSessions += [PSCustomObject]@{
                            SourceIP         = "(null) - no 5156 match"
                            WindowStart      = ($ucWindow | Measure-Object Timestamp -Minimum).Minimum
                            WindowEnd        = ($ucWindow | Measure-Object Timestamp -Maximum).Maximum
                            DurationSeconds  = (($ucWindow | Measure-Object Timestamp -Maximum).Maximum - ($ucWindow | Measure-Object Timestamp -Minimum).Minimum).TotalSeconds
                            Connections      = 0
                            Ports            = "unknown"
                            TotalQueries     = $ucWindow.Count
                            ValidAccounts    = $hits.Count
                            UnknownAccounts  = $misses.Count
                            DisabledAccounts = $disabled.Count
                            HoneytokenHits   = $honeyhits.Count
                            HitUsernames     = ($hits | Select-Object -ExpandProperty Username -Unique) -join ','
                            DisabledUsernames= ($disabled | Select-Object -ExpandProperty Username -Unique) -join ','
                            HoneytokenNames  = ($honeyhits | Select-Object -ExpandProperty Username -Unique) -join ','
                            AllUsernames     = ($ucWindow | Select-Object -ExpandProperty Username -Unique | Sort-Object) -join ','
                            CorrelationMethod = "netlogon.log only (possible UDP cLDAP or 5156 not enabled)"
                        }
                    }
                    $ucWindow = @($sorted[$i])
                }
            }
        }
    }

    Write-Host "  Correlated sessions: $($correlatedSessions.Count)" -ForegroundColor Gray

    return @($correlatedSessions | Sort-Object WindowStart -Descending)
}

#endregion

#region ── ANALYSIS AND ALERTS ───────────────────────────────────────────────────

function Invoke-Analysis {
    param([array]$Sessions)

    Write-Section "Analysis and Alerts"

    if ($Sessions.Count -eq 0) {
        Write-Host "  No LDAP Ping activity detected in the analysis window" -ForegroundColor Green
        Write-Host "  Either no enumeration occurred, or logging is not yet enabled" -ForegroundColor Gray
        return
    }

    foreach ($session in $Sessions) {

        $timeStr = $session.WindowStart.ToString("MM/dd HH:mm:ss")
        $ip = $session.SourceIP

        # ── Dump mode detection ────────────────────────────────────────────
        if ($session.DumpModeDetected -and $session.TotalQueries -eq 0) {
            Write-Finding -Severity "MEDIUM" `
                -Message "ROOTDSE DUMP DETECTED — $ip at $timeStr" `
                -Detail "$($session.Connections) connection(s) to port $($session.Ports) with zero username queries — consistent with ldapnomnom --dump"
            Write-Finding -Severity "MEDIUM" `
                -Message "Domain recon collected: DC names, forest/domain structure, DC roles (PDC/GC/KDC), site topology" `
                -Detail "No credentials required. No usernames enumerated. Pre-authentication reconnaissance."
        } elseif ($session.CorrelationMethod -match '--dump mode') {
            Write-Finding -Severity "MEDIUM" `
                -Message "ROOTDSE DUMP DETECTED — $ip at $timeStr" `
                -Detail "Explicit dump mode pings detected in netlogon.log — anonymous domain reconnaissance"
        }

        # ── Parallel connection burst (multi-server or --parallel flag) ───
        if ($session.Connections -ge 8 -and $session.DurationSeconds -le 1) {
            Write-Finding -Severity "MEDIUM" `
                -Message "HIGH PARALLEL CONNECTIONS — $ip at $timeStr" `
                -Detail "$($session.Connections) simultaneous connections within $([math]::Round($session.DurationSeconds,2))s — consistent with --parallel flag (ldapnomnom default is 8)"
        }

        # ── Honeytoken hit ─────────────────────────────────────────────────
        if ($session.HoneytokenHits -gt 0) {
            Write-Finding -Severity "CRITICAL" `
                -Message "HONEYTOKEN HIT — $ip at $timeStr" `
                -Detail "Canary account(s) queried and found valid: $($session.HoneytokenNames)"
            Write-Finding -Severity "CRITICAL" `
                -Message "This is high-confidence username enumeration" `
                -Detail "Source enumerated $($session.TotalQueries) account(s), found $($session.ValidAccounts) valid"
        }

        # ── High volume enumeration ────────────────────────────────────────
        elseif ($session.TotalQueries -ge $AlertThreshold) {
            Write-Finding -Severity "HIGH" `
                -Message "HIGH VOLUME LDAP PING — $ip at $timeStr" `
                -Detail "$($session.TotalQueries) queries ($($session.ValidAccounts) hits, $($session.UnknownAccounts) misses, $($session.DisabledAccounts) disabled) over $([math]::Round($session.DurationSeconds,1))s"
            if ($session.HitUsernames) {
                Write-Finding -Severity "HIGH" `
                    -Message "Valid accounts found: $($session.HitUsernames)" `
                    -Detail "Source: $ip"
            }
        }

        # ── Disabled account probing ───────────────────────────────────────
        if ($session.DisabledAccounts -gt 0 -and $session.HoneytokenHits -eq 0) {
            Write-Finding -Severity "MEDIUM" `
                -Message "DISABLED ACCOUNTS PROBED — $ip at $timeStr" `
                -Detail "Attacker received 'Unknown' but we see disabled accounts: $($session.DisabledUsernames)"
            Write-Finding -Severity "MEDIUM" `
                -Message "Defender visibility advantage: we know these accounts exist, attacker does not" `
                -Detail ""
        }

        # ── Uncorrelated (possible UDP cLDAP) ─────────────────────────────
        if ($session.CorrelationMethod -match "netlogon.log only") {
            if ($session.TotalQueries -ge 3) {
                Write-Finding -Severity "MEDIUM" `
                    -Message "LDAP PING ACTIVITY — no source IP (possible UDP cLDAP)" `
                    -Detail "$($session.TotalQueries) queries at $timeStr — enable Filtering Platform Connection auditing for attribution"
                if ($session.HitUsernames) {
                    Write-Finding -Severity "MEDIUM" `
                        -Message "Valid accounts found without attribution: $($session.HitUsernames)" `
                        -Detail "Consider: network IDS, MDI, or packet capture for source IP"
                }
            }
        }

        # ── TLS enumeration (port 636) ─────────────────────────────────────
        if ($session.Ports -contains '636' -and $session.TotalQueries -ge 5) {
            Write-Finding -Severity "MEDIUM" `
                -Message "TLS LDAP PING (port 636) — $ip at $timeStr" `
                -Detail "Encrypted enumeration attempt. Event 5156 still fires — source IP visible. Content not inspectable by IDS."
        }

        # ── Low volume / informational ─────────────────────────────────────
        if ($session.TotalQueries -gt 0 -and 
            $session.TotalQueries -lt $AlertThreshold -and 
            $session.HoneytokenHits -eq 0 -and
            $session.CorrelationMethod -notmatch "netlogon.log only") {
            Write-Finding -Severity "LOW" `
                -Message "LDAP PING ACTIVITY — $ip at $timeStr" `
                -Detail "$($session.TotalQueries) queries, $($session.ValidAccounts) valid accounts found"
        }
    }
}

#endregion

#region ── DETAILED OUTPUT ────────────────────────────────────────────────────────

function Show-DetailedResults {
    param([array]$Sessions)

    Write-Section "Detailed Session Results"

    if ($Sessions.Count -eq 0) {
        Write-Host "  No sessions to display" -ForegroundColor Gray
        return
    }

    foreach ($session in $Sessions) {
        $ip = $session.SourceIP.PadRight(22)
        $time = $session.WindowStart.ToString("MM/dd HH:mm:ss")
        $queries = "$($session.TotalQueries) queries".PadRight(12)
        $hits = "hits:$($session.ValidAccounts)".PadRight(8)
        $misses = "miss:$($session.UnknownAccounts)".PadRight(8)
        $disabled = "disabled:$($session.DisabledAccounts)"

        $lineColor = if     ($session.HoneytokenHits -gt 0)               { "Red" }
                     elseif ($session.TotalQueries -ge $AlertThreshold)    { "Yellow" }
                     elseif ($session.DisabledAccounts -gt 0)              { "Cyan" }
                     else                                                   { "Gray" }

        Write-Host "  [$time] $ip $queries $hits $misses $disabled" -ForegroundColor $lineColor

        if ($session.HitUsernames) {
            Write-Host "    Valid accounts: $($session.HitUsernames)" -ForegroundColor $(if ($session.HoneytokenHits -gt 0) {'Red'} else {'White'})
        }
        if ($session.DisabledUsernames) {
            Write-Host "    Disabled (invisible to attacker): $($session.DisabledUsernames)" -ForegroundColor Cyan
        }
        if ($session.CorrelationMethod -match "only") {
            Write-Host "    Note: $($session.CorrelationMethod)" -ForegroundColor DarkYellow
        }
    }
}

#endregion

#region ── STATISTICS ─────────────────────────────────────────────────────────────

function Show-Statistics {
    param(
        [array]$Events5156,
        [array]$PingEntries,
        [array]$Sessions
    )

    Write-Section "Summary Statistics"

    $totalHits     = @($PingEntries | Where-Object { $_.IsHit }).Count
    $totalMisses   = @($PingEntries | Where-Object { -not $_.IsHit -and -not $_.IsDisabled }).Count
    $totalDisabled = @($PingEntries | Where-Object { $_.IsDisabled }).Count
    $totalHoneys   = @($PingEntries | Where-Object { $_.IsHoneytoken -and $_.IsHit }).Count
    $uniqueIPs     = @($Events5156 | Select-Object -ExpandProperty SourceIP -Unique).Count
    $criticalCount = @($script:Findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount     = @($script:Findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $mediumCount   = @($script:Findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count

    Write-Host ""
    Write-Host "  Analysis window:    Last $HoursBack hour(s)" -ForegroundColor White
    Write-Host "  Event 5156 total:   $($Events5156.Count) connections from $uniqueIPs unique IP(s)" -ForegroundColor White
    Write-Host "  netlogon.log total: $($PingEntries.Count) LDAP Ping entries" -ForegroundColor White
    Write-Host "    Valid hits:       $totalHits" -ForegroundColor $(if ($totalHits -gt 0) {'Red'} else {'White'})
    Write-Host "    Misses:           $totalMisses" -ForegroundColor White
    Write-Host "    Disabled found:   $totalDisabled" -ForegroundColor $(if ($totalDisabled -gt 0) {'Yellow'} else {'White'})
    Write-Host "    Honeytoken hits:  $totalHoneys" -ForegroundColor $(if ($totalHoneys -gt 0) {'Red'} else {'White'})
    Write-Host "  Correlated sessions:$($Sessions.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Findings:" -ForegroundColor White
    Write-Host "    CRITICAL: $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) {'Red'} else {'White'})
    Write-Host "    HIGH:     $highCount"     -ForegroundColor $(if ($highCount -gt 0) {'Yellow'} else {'White'})
    Write-Host "    MEDIUM:   $mediumCount"   -ForegroundColor $(if ($mediumCount -gt 0) {'Cyan'} else {'White'})
    Write-Host "    LOW:      $(@($script:Findings | Where-Object { $_.Severity -eq 'LOW' }).Count)" -ForegroundColor White
}

#endregion

#region ── CSV EXPORT ─────────────────────────────────────────────────────────────

function Export-Results {
    param([array]$Sessions)

    if ([string]::IsNullOrEmpty($ExportPath)) { return }

    Write-Section "Exporting Results"
    try {
        $Sessions | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $ExportPath" -ForegroundColor Green
        Write-Host "  Sessions exported:   $($Sessions.Count)" -ForegroundColor Gray
    } catch {
        Write-Host "  [FAIL] Export failed: $_" -ForegroundColor Red
    }
}

#endregion

#region ── SIGMA RULES ────────────────────────────────────────────────────────────

function Show-SigmaRules {
    Write-Section "Detection Content (Sigma Rules)"

    Write-Host ""
    Write-Host "  ── Rule 1: Burst LDAP Ping connections (Event 5156) ────────" -ForegroundColor DarkGray
    Write-Host @'
title: LDAP Ping Username Enumeration via Burst TCP Connections
id: a4f3b2c1-8d7e-4f5a-b6c9-2e1d3f4a5b6c
status: experimental
description: >
    Detects burst of inbound TCP connections to DC LDAP port from single source,
    consistent with ldapnomnom or similar LDAP Ping username enumeration tools.
    Event 5156 requires Filtering Platform Connection auditing to be enabled.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5156
    Direction: '%%14592'   # Inbound
    DestPort:
      - '389'
      - '636'
    Application|endswith: '\lsass.exe'
  timeframe: 10s
  condition: selection | count() by SourceAddress > 5
falsepositives:
  - Legitimate LDAP clients connecting multiple times during startup
  - Load balancers
level: medium
'@ -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  ── Rule 2: LDAP Ping User= filter in netlogon.log ──────────" -ForegroundColor DarkGray
    Write-Host @'
title: LDAP Ping Username Enumeration Detected in Netlogon Debug Log
id: b5c4d3e2-9e8f-5g6b-c7d0-3f2e4g5b6c7d
status: experimental
description: >
    Detects LDAP Ping username enumeration in Netlogon debug log.
    Requires nltest /dbflag:0x2080ffff on DC and log shipping to SIEM.
    The 'Sam Logon Response Ex' response indicates a valid enabled account was found.
logsource:
  product: windows
  service: netlogon  # custom - requires netlogon.log ingestion
detection:
  selection_hit:
    Message|contains:
      - "Ping response 'Sam Logon Response Ex'"
      - 'on UDP LDAP'
  selection_burst:
    Message|contains: 'Received ping from (null)((null))'
  timeframe: 30s
  condition: selection_hit | count() > 3 or selection_burst | count() > 10
falsepositives:
  - Minimal - (null) source is specific to stripped LDAP Ping without Host= field
level: high
'@ -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  ── Rule 3: Honeytoken account queried ──────────────────────" -ForegroundColor DarkGray
    Write-Host @'
title: Honeytoken Account Queried via LDAP Ping
id: c6d5e4f3-0f9g-6h7c-d8e1-4g3f5h6c7d8e
status: stable
description: >
    Detects LDAP Ping hit on a designated honeytoken account.
    A 'Sam Logon Response Ex' response for an account that should never
    be legitimately queried anonymously is high-confidence enumeration.
    Configure your honeytoken account names in the Message contains list.
logsource:
  product: windows
  service: netlogon
detection:
  selection:
    Message|contains: "Ping response 'Sam Logon Response Ex'"
    Message|contains:
      - 'administrator'   # Replace with your honeytoken names
      - 'svc_backup'
      - 'helpdesk'
  condition: selection
falsepositives:
  - None if honeytoken accounts are properly isolated
level: critical
'@ -ForegroundColor DarkGray
}

#endregion

#region ── MONITOR MODE ──────────────────────────────────────────────────────────

function Invoke-MonitorMode {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║  MONITOR MODE — Real-time LDAP Ping Detection                ║" -ForegroundColor Magenta
    Write-Host "║  Polling every ${MonitorIntervalSeconds}s — Press Ctrl+C to stop             ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Watching: $LogPath" -ForegroundColor Gray
    Write-Host "  Alert threshold: $AlertThreshold unique usernames per window" -ForegroundColor Gray
    if ($script:HoneytokenList.Count -gt 0) {
        Write-Host "  Honeytokens: $($script:HoneytokenList -join ', ')" -ForegroundColor Yellow
    }
    Write-Host ""

    # Get DC IPs once to exclude self-queries
    $dcIPs = @()
    try {
        $dcIPs = @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                   Select-Object -ExpandProperty IPAddressToString)
    } catch {}

    # Seed last log position so we only read new lines
    $lastLogSize = [long]0
    if (Test-Path $LogPath) {
        $lastLogSize = (Get-Item $LogPath).Length
    }

    # Seed last 5156 RecordId so we only process new events
    $lastRecordId = [long]0
    try {
        $seedEvents = @(Get-WinEvent -LogName Security -MaxEvents 1 `
            -FilterXPath "*[System[EventID=5156]]" -ErrorAction SilentlyContinue)
        if ($seedEvents.Count -gt 0) {
            $lastRecordId = [long]$seedEvents[0].RecordId
        }
    } catch {}

    # Rolling buffers — plain arrays, rebuilt each poll from last 60 seconds
    $pingBuffer  = @()
    $ip5156Buffer = @()
    $alertCount  = 0
    $alreadyAlerted = @{}   # avoid duplicate alerts for same burst
    $currentYear = (Get-Date).Year

    Write-Host "  $(Get-Date -Format 'HH:mm:ss')  Baseline established. Monitoring..." -ForegroundColor Green
    Write-Host ""

    while ($true) {
        Start-Sleep -Seconds $MonitorIntervalSeconds
        $now     = Get-Date
        $cutoff  = $now.AddSeconds(-60)   # 60s rolling window

        # ── Poll Event 5156 ───────────────────────────────────────────────
        try {
            # Use MaxEvents to limit pull, then filter by RecordId
            # XPath timediff filter gets events from last 2 minutes to bound the query
            $xp = "*[System[EventID=5156 and TimeCreated[timediff(@SystemTime) <= 120000]]]"
            $newSecEvents = @(Get-WinEvent -LogName Security -FilterXPath $xp `
                -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object { ([long]$_.RecordId) -gt $lastRecordId })

            foreach ($evt in $newSecEvents) {
                $rid = [long]$evt.RecordId
                if ($rid -gt $lastRecordId) { $lastRecordId = $rid }

                try {
                    $xml  = [xml]$evt.ToXml()
                    $data = @{}
                    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

                    $destPort  = $data['DestPort']
                    $direction = $data['Direction']
                    if ($destPort -notin @('389','636')) { continue }
                    if ($direction -notmatch '%%14592|Inbound') { continue }

                    $srcIP = $data['SourceAddress']
                    if ([string]::IsNullOrEmpty($srcIP)) { continue }
                    if ($srcIP -in @('127.0.0.1','::1','0.0.0.0')) { continue }
                    if ($srcIP -match '^fe80:') { continue }
                    if ($srcIP -in $dcIPs) { continue }

                    $ip5156Buffer += [PSCustomObject]@{
                        Timestamp = $evt.TimeCreated
                        SourceIP  = $srcIP
                        DestPort  = $destPort
                    }
                } catch {}
            }
        } catch {}

        # ── Tail netlogon.log ─────────────────────────────────────────────
        if (Test-Path $LogPath) {
            $currentSize = [long](Get-Item $LogPath).Length

            # Log rotated?
            if ($currentSize -lt $lastLogSize) {
                Write-Host "  $(Get-Date -Format 'HH:mm:ss')  netlogon.log rotated — resetting" -ForegroundColor DarkYellow
                $lastLogSize = [long]0
            }

            if ($currentSize -gt $lastLogSize) {
                try {
                    $fs     = [System.IO.File]::Open($LogPath, 'Open', 'Read', 'ReadWrite')
                    $null   = $fs.Seek($lastLogSize, 'Begin')
                    $reader = New-Object System.IO.StreamReader($fs)
                    $newLines = @()
                    while (-not $reader.EndOfStream) { $newLines += $reader.ReadLine() }
                    $reader.Close(); $fs.Close()
                    $lastLogSize = $currentSize

                    foreach ($line in $newLines) {
                        if ($line -notmatch '\[MAILSLOT\]') { continue }
                        if ($line -notmatch '^(\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})') { continue }
                        try {
                            $ts = [DateTime]::ParseExact(
                                "$($Matches[1])/$currentYear $($Matches[2])",
                                "MM/dd/yyyy HH:mm:ss", $null)
                            if ($ts -gt $now.AddHours(1)) { $ts = $ts.AddYears(-1) }
                        } catch { continue }

                        # Dump mode: ping with no username
                        if ($line -match 'Received ping from \(null\)\(\(null\)\) \(null\) on (UDP LDAP|TCP LDAP)') {
                            $pingBuffer += [PSCustomObject]@{
                                Timestamp  = $ts
                                Username   = "__DUMP_MODE__"
                                IsHit      = $false
                                IsDisabled = $false
                                IsDump     = $true
                                IsHoneytoken = $false
                            }
                            continue
                        }

                        # Disabled account
                        if ($line -match 'NlSamVerifyUserAccountEnabled:\s+(.+?)\s+account is disabled') {
                            $u = $Matches[1].Trim()
                            $pingBuffer += [PSCustomObject]@{
                                Timestamp    = $ts
                                Username     = $u
                                IsHit        = $false
                                IsDisabled   = $true
                                IsDump       = $false
                                IsHoneytoken = ($script:HoneytokenList -contains $u.ToLower())
                            }
                            continue
                        }

                        # Ping response
                        if ($line -match "Ping response '(.+?)'\s+(.+?)\s+to") {
                            $responseType = $Matches[1].Trim()
                            $u = $Matches[2].Trim()
                            if ([string]::IsNullOrWhiteSpace($u) -or $u -eq '(null)' -or $u -eq '-') { continue }
                            $pingBuffer += [PSCustomObject]@{
                                Timestamp    = $ts
                                Username     = $u
                                IsHit        = ($responseType -eq 'Sam Logon Response Ex')
                                IsDisabled   = $false
                                IsDump       = $false
                                IsHoneytoken = ($script:HoneytokenList -contains $u.ToLower())
                            }
                        }
                    }
                } catch {}
            }
        }

        # ── Prune old entries from buffers ────────────────────────────────
        $pingBuffer   = @($pingBuffer   | Where-Object { $_.Timestamp -ge $cutoff })
        $ip5156Buffer = @($ip5156Buffer | Where-Object { $_.Timestamp -ge $cutoff })

        $uptime = [math]::Round(($now - $script:StartTime).TotalMinutes, 1)

        if ($pingBuffer.Count -eq 0 -and $ip5156Buffer.Count -eq 0) {
            Write-Host "  $(Get-Date -Format 'HH:mm:ss')  Monitoring... (${uptime}min | ping:0 | 5156:0 | alerts:$alertCount)" -ForegroundColor DarkGray
            continue
        }

        # Show buffer state only if there's unalerted activity
        $allAlerted = $true
        if ($pingBuffer.Count -gt 0) {
            $sortedCheck = @($pingBuffer | Sort-Object Timestamp)
            # Build windows quickly to check if any are unalerted
            $checkW = @($sortedCheck[0])
            for ($ci = 1; $ci -lt $sortedCheck.Count; $ci++) {
                $cgap = ($sortedCheck[$ci].Timestamp - $checkW[-1].Timestamp).TotalSeconds
                if ($cgap -le ($CorrelationWindowSeconds * 2)) { $checkW += $sortedCheck[$ci] }
                else {
                    $ck = ($checkW | Measure-Object Timestamp -Minimum).Minimum.ToString("yyyyMMddHHmmss")
                    if (-not $alreadyAlerted.ContainsKey($ck)) { $allAlerted = $false; break }
                    $checkW = @($sortedCheck[$ci])
                }
            }
            if ($allAlerted) {
                $ck = ($checkW | Measure-Object Timestamp -Minimum).Minimum.ToString("yyyyMMddHHmmss")
                if (-not $alreadyAlerted.ContainsKey($ck)) { $allAlerted = $false }
            }
        }
        if (-not $allAlerted) {
            Write-Host "  $(Get-Date -Format 'HH:mm:ss')  New activity — ping:$($pingBuffer.Count) 5156:$($ip5156Buffer.Count)" -ForegroundColor Cyan
        }

        if ($pingBuffer.Count -eq 0) { continue }

        # ── Group ping buffer into burst windows ──────────────────────────
        $sorted  = @($pingBuffer | Sort-Object Timestamp)
        $windows = @()
        $w       = @($sorted[0])

        for ($i = 1; $i -lt $sorted.Count; $i++) {
            $gap = ($sorted[$i].Timestamp - $w[-1].Timestamp).TotalSeconds
            if ($gap -le ($CorrelationWindowSeconds * 2)) {
                $w += $sorted[$i]
            } else {
                $windows += ,@($w)
                $w = @($sorted[$i])
            }
        }
        $windows += ,@($w)

        foreach ($win in $windows) {
            $wStart  = ($win | Measure-Object Timestamp -Minimum).Minimum
            $wEnd    = ($win | Measure-Object Timestamp -Maximum).Maximum
            $winKey  = $wStart.ToString("yyyyMMddHHmmss")

            if ($alreadyAlerted.ContainsKey($winKey)) { continue }

            # Correlate with 5156 buffer
            $matchedIPs = @($ip5156Buffer | Where-Object {
                $_.Timestamp -ge $wStart.AddSeconds(-$CorrelationWindowSeconds) -and
                $_.Timestamp -le $wEnd.AddSeconds($CorrelationWindowSeconds)
            } | Select-Object -ExpandProperty SourceIP -Unique)

            $hits      = @($win | Where-Object { $_.IsHit -and -not $_.IsDump })
            $disabled  = @($win | Where-Object { $_.IsDisabled })
            $honeyhits = @($win | Where-Object { $_.IsHoneytoken -and $_.IsHit })
            $dumpPings = @($win | Where-Object { $_.IsDump })

            # 5156 connections with zero ping entries = likely dump mode
            $isDumpOnly = ($matchedIPs.Count -gt 0 -and $win.Count -eq 0)

            # Alert threshold check
            $shouldAlert = (
                $honeyhits.Count -gt 0 -or
                $win.Count -ge $AlertThreshold -or
                ($disabled.Count -gt 0) -or
                ($win.Count -ge 3 -and $hits.Count -gt 0 -and $matchedIPs.Count -gt 0) -or
                $dumpPings.Count -gt 0
            )
            if (-not $shouldAlert) { continue }

            $alreadyAlerted[$winKey] = $true
            $alertCount++

            $srcDisplay = if ($matchedIPs.Count -gt 0) { $matchedIPs -join ',' } else { "(null) — no 5156 match" }
            $hitNames   = ($hits | Select-Object -ExpandProperty Username -Unique) -join ','
            $disNames   = ($disabled | Select-Object -ExpandProperty Username -Unique) -join ','
            $honeyNames = ($honeyhits | Select-Object -ExpandProperty Username -Unique) -join ','
            $timeStr    = $wStart.ToString("HH:mm:ss")

            Write-Host ""
            if ($dumpPings.Count -gt 0) {
                Write-Host "  [$timeStr] ⚠ MEDIUM — RootDSE Dump (ldapnomnom --dump)" -ForegroundColor Yellow
                Write-Host "             Source:  $srcDisplay" -ForegroundColor Yellow
                Write-Host "             Detail:  Anonymous domain recon — DC names, roles, site topology" -ForegroundColor White
                Write-Host "             Note:    No usernames enumerated — pre-credential reconnaissance" -ForegroundColor DarkGray
            } elseif ($honeyhits.Count -gt 0) {
                Write-Host "  [$timeStr] 🚨 CRITICAL — HONEYTOKEN HIT" -ForegroundColor Red
                Write-Host "             Source:   $srcDisplay" -ForegroundColor Red
                Write-Host "             Canary:   $honeyNames" -ForegroundColor Red
                Write-Host "             All hits: $hitNames" -ForegroundColor Red
                Write-Host "             Queries:  $($win.Count) total" -ForegroundColor Red
            } elseif ($win.Count -ge $AlertThreshold) {
                Write-Host "  [$timeStr] ⚠ HIGH — Burst LDAP Ping Enumeration" -ForegroundColor Yellow
                Write-Host "             Source:   $srcDisplay" -ForegroundColor Yellow
                Write-Host "             Queries:  $($win.Count) ($($hits.Count) hits, $($win.Count - $hits.Count - $disabled.Count) misses)" -ForegroundColor White
                if ($hitNames) { Write-Host "             Accounts: $hitNames" -ForegroundColor White }
                if ($matchedIPs.Count -eq 0) {
                    Write-Host "             NOTE: No 5156 match — enable FPC auditing for attribution" -ForegroundColor DarkYellow
                }
            } elseif ($disabled.Count -gt 0) {
                Write-Host "  [$timeStr] ℹ MEDIUM — Disabled accounts probed" -ForegroundColor Cyan
                Write-Host "             Source:    $srcDisplay" -ForegroundColor Cyan
                Write-Host "             Disabled:  $disNames (attacker sees Unknown)" -ForegroundColor Cyan
            } else {
                Write-Host "  [$timeStr] ○ LOW — LDAP Ping activity detected" -ForegroundColor Gray
                Write-Host "             Source:    $srcDisplay" -ForegroundColor Gray
                Write-Host "             Queries:   $($win.Count) ($($hits.Count) hits)" -ForegroundColor Gray
                if ($hitNames) { Write-Host "             Accounts:  $hitNames" -ForegroundColor DarkGray }
            }
        }

    }
}

#endregion

#region ── MAIN ───────────────────────────────────────────────────────────────────

function Main {
    Write-Banner

    # Enable logging if requested
    if ($EnableLogging) {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
            Write-Host "  [ERROR] -EnableLogging requires Administrator privileges" -ForegroundColor Red
            return
        }
        Enable-RequiredLogging
    }

    # Check prerequisites
    Test-Prerequisites

    # Branch: monitor mode vs historical analysis
    if ($Monitor) {
        Write-Host ""
        Write-Host "  Switching to real-time monitor mode..." -ForegroundColor Magenta
        Invoke-MonitorMode
        return   # never reached unless Ctrl+C
    }

    # Set analysis window
    $since = (Get-Date).AddHours(-$HoursBack)
    Write-Host ""
    Write-Host "  Analysis window: $($since.ToString('yyyy-MM-dd HH:mm:ss')) to $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

    # Collect data
    [array]$events5156  = Get-5156Events -Since $since
    [array]$pingEntries = Get-NetlogonPingEntries -Since $since

    # Correlate
    [array]$sessions = Invoke-Correlation -Events5156 $events5156 -PingEntries $pingEntries

    # Analyze
    Invoke-Analysis -Sessions $sessions

    # Show details
    Show-DetailedResults -Sessions $sessions

    # Statistics
    Show-Statistics -Events5156 $events5156 -PingEntries $pingEntries -Sessions $sessions

    # Export
    Export-Results -Sessions $sessions

    # Sigma rules
    Show-SigmaRules

    Write-Host ""
    Write-Host "  Runtime: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1))s" -ForegroundColor DarkGray
    Write-Host ""
}

Main

#endregion
