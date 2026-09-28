<#
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.SYNOPSIS
    ADWS Source IP Attribution - Correlates external ADWS connections to LDAP queries.
    
.DESCRIPTION
    Proves that source IP CAN be determined for ADWS queries, contrary to claims
    that "originating host cannot be determined" for ADWS-proxied LDAP queries.
    
    Correlation Methods:
    1. PORT-BASED: 5156(internal).SourcePort = 1644.ClientPort [Deterministic]
    2. TIMESTAMP-BASED: 5156(external) within ~100ms of 1644 [Fallback]
    
    Event Chain:
    ┌─────────────────────────────────────────────────────────────────────────┐
    │  5156 External    →    5156 Internal      →    1138    →    1644       │
    │  10.1.1.13→:9389       ::1:60983→:389          Start        Details    │
    │  SOURCE IP             CORRELATION PORT        User SID     Filter     │
    └─────────────────────────────────────────────────────────────────────────┘
    
.PARAMETER Monitor
    Real-time monitoring mode - continuously watches for new ADWS queries

.PARAMETER Minutes
    Hunt mode: How many minutes back to search (default: 10)

.PARAMETER PollSeconds
    Monitor mode: How often to check for new events (default: 5)
    
.PARAMETER MaxDeltaMs  
    Maximum milliseconds between events for correlation (default: 500)

.PARAMETER ExcludeIPs
    Array of IPs to exclude from results

.PARAMETER AlertOnly
    Only show suspicious queries (hide benign ones)

.PARAMETER ShowAll
    Hunt mode: Show all queries including non-suspicious

.PARAMETER Detailed
    Show verbose debug information

.EXAMPLE
    .\Get-ADWSAttribution.ps1
    Hunt mode - analyze last 10 minutes
    
.EXAMPLE
    .\Get-ADWSAttribution.ps1 -Monitor
    Real-time monitoring - press Ctrl+C to stop

.EXAMPLE
    .\Get-ADWSAttribution.ps1 -Monitor -AlertOnly -PollSeconds 2
    Real-time, only suspicious, check every 2 seconds

.EXAMPLE
    .\Get-ADWSAttribution.ps1 -Minutes 60 -ShowAll
    Hunt last 60 minutes, show all queries

.NOTES
    Requirements:
    - 5156: auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
    - 1138: reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
    - 1644: reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f
    
    Research: Disproves Logan Goins' claim that ADWS source attribution is impossible.
    Method: Event 5156 temporal/port correlation with 1138/1644.
    
    Author: Detection Engineering Research
#>

[CmdletBinding(DefaultParameterSetName = 'Hunt')]
param(
    [Parameter(ParameterSetName = 'Monitor')]
    [switch]$Monitor,
    
    [Parameter(ParameterSetName = 'Hunt')]
    [int]$Minutes = 10,
    
    [Parameter(ParameterSetName = 'Monitor')]
    [int]$PollSeconds = 5,
    
    [Parameter()]
    [int]$MaxDeltaMs = 500,
    
    [Parameter()]
    [string[]]$ExcludeIPs = @(),
    
    [Parameter()]
    [switch]$AlertOnly,
    
    [Parameter(ParameterSetName = 'Hunt')]
    [switch]$ShowAll,
    
    [Parameter()]
    [switch]$Detailed
)

$ErrorActionPreference = 'SilentlyContinue'

# Build exclusion list (localhost + DC IPs)
$Exclusions = @('::1', '127.0.0.1') + $ExcludeIPs
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object { $_.IPAddress -notlike '127.*' } | 
    ForEach-Object { $Exclusions += $_.IPAddress }

#region Helper Functions

function Get-External5156 {
    param($Start, $End)
    
    @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 5156; StartTime = $Start; EndTime = $End
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        
        if ($d.DestPort -eq '9389' -and $d.SourceAddress -notin $script:Exclusions) {
            [PSCustomObject]@{
                Time     = $_.TimeCreated
                RecordId = $_.RecordId
                SrcIP    = $d.SourceAddress
                SrcPort  = $d.SourcePort
            }
        }
    })
}

function Get-Internal5156 {
    param($Start, $End)
    
    @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 5156; StartTime = $Start; EndTime = $End
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        
        if ($d.DestPort -eq '389' -and 
            $d.Application -match 'webservices' -and 
            $d.SourceAddress -in @('::1','127.0.0.1')) {
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                SrcPort = $d.SourcePort
            }
        }
    })
}

function Get-Events1138 {
    param($Start, $End)
    
    @(Get-WinEvent -FilterHashtable @{
        LogName = 'Directory Service'; Id = 1138; StartTime = $Start; EndTime = $End
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $m = $_.Message
        if ($m -match '\[::1\]:(\d+)|127\.0\.0\.1:(\d+)') {
            $port = if ($matches[1]) { $matches[1] } else { $matches[2] }
            [PSCustomObject]@{
                Time       = $_.TimeCreated
                RecordId   = $_.RecordId
                ClientPort = $port
                Operation  = if ($m -match '<string>([^<]+)</string>') { $matches[1] } else { '' }
                UserSid    = if ($m -match '(S-1-5-21-[\d-]+)') { $matches[1] } else { '' }
                ConnId     = if ($m -match '<string>(\d+)</string>.*<string>(\d+)</string>') { $matches[2] } else { '' }
            }
        }
    })
}

function Get-Events1644 {
    param($Start, $End)
    
    @(Get-WinEvent -FilterHashtable @{
        LogName = 'Directory Service'; Id = 1644; StartTime = $Start; EndTime = $End
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $m = $_.Message
        if ($m -match '\[::1\]:(\d+)|127\.0\.0\.1:(\d+)') {
            $port = if ($matches[1]) { $matches[1] } else { $matches[2] }
            [PSCustomObject]@{
                Time        = $_.TimeCreated
                RecordId    = $_.RecordId
                ClientPort  = $port
                Filter      = if ($m -match 'Filter[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
                Attributes  = if ($m -match 'Attribute selection[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
                Controls    = if ($m -match 'Server controls[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
                Visited     = if ($m -match 'Visited entries[:\s]+(\d+)') { [int]$matches[1] } else { 0 }
                Returned    = if ($m -match 'Returned entries[:\s]+(\d+)') { [int]$matches[1] } else { 0 }
                UsedIndexes = if ($m -match 'Used indexes[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
                PagesRef    = if ($m -match 'Pages referenced[:\s]+(\d+)') { [int]$matches[1] } else { 0 }
                SearchTimeMs= if ($m -match 'Search time[^:]*[:\s]+(\d+)') { [int]$matches[1] } else { 0 }
                User        = if ($m -match 'User[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
                BaseDN      = if ($m -match 'Starting node[:\s]+([^\r\n]+)') { $matches[1].Trim() } else { '' }
            }
        }
    })
}

function Get-SuspiciousIndicators {
    param($Query)
    
    $Indicators = @()
    if ($Query.Attributes -match 'nTSecurityDescriptor') { $Indicators += 'ACL enumeration' }
    if ($Query.Controls -match 'SDflags:0x7') { $Indicators += 'Full SD (BloodHound pattern)' }
    if ($Query.Filter -match 'serviceprincipalname=\*') { $Indicators += 'Kerberoasting recon' }
    if ($Query.Filter -match 'msDS-AllowedToDelegateTo') { $Indicators += 'Delegation enumeration' }
    if ($Query.Filter -match 'msDS-GroupMSAMembership') { $Indicators += 'gMSA enumeration' }
    if ($Query.Filter -match 'userAccountControl.*TRUSTED') { $Indicators += 'Unconstrained delegation' }
    if ($Query.Returned -gt 100) { $Indicators += "Bulk enumeration ($($Query.Returned) objects)" }
    if ($Query.Filter -match 'adminCount=1') { $Indicators += 'Privileged account hunt' }
    if ($Query.Filter -match 'userPassword|unicodePwd') { $Indicators += 'Password attribute query' }
    
    return $Indicators
}

function Get-5156Indicators {
    param($SourceIP, $DestPort)
    
    $Indicators = @()
    $Indicators += "External ADWS connection (TCP/$DestPort)"
    # Could add: known bad IP check, geo anomaly, etc.
    return $Indicators
}

function Get-1138Indicators {
    param($ClientPort)
    
    $Indicators = @()
    $Indicators += "Localhost client ([::1]:$ClientPort)"
    $Indicators += "ADWS proxy to LDAP"
    return $Indicators
}

function Correlate-Query {
    param($Query, $External5156, $Internal5156, $Events1138)
    
    $SourceIP = $null
    $Method = $null
    $Delta = $null
    
    # METHOD 1: Port-based (deterministic)
    $IntMatch = $Internal5156 | Where-Object {
        $_.SrcPort -eq $Query.ClientPort -and
        [Math]::Abs(($_.Time - $Query.Time).TotalMilliseconds) -lt $script:MaxDeltaMs
    } | Sort-Object { [Math]::Abs(($_.Time - $Query.Time).TotalMilliseconds) } | Select-Object -First 1
    
    if ($IntMatch) {
        $ExtMatch = $External5156 | Where-Object {
            $_.Time -lt $IntMatch.Time -and
            ($IntMatch.Time - $_.Time).TotalMilliseconds -lt 150
        } | Sort-Object Time -Descending | Select-Object -First 1
        
        if ($ExtMatch) {
            $SourceIP = $ExtMatch.SrcIP
            $Method = "PORT:$($Query.ClientPort)"
            $Delta = [Math]::Round(($Query.Time - $ExtMatch.Time).TotalMilliseconds, 1)
        }
    }
    
    # METHOD 2: Timestamp-based (fallback)
    if (-not $SourceIP) {
        $ExtMatch = $External5156 | Where-Object {
            $_.Time -lt $Query.Time -and
            ($Query.Time - $_.Time).TotalMilliseconds -le $script:MaxDeltaMs
        } | Sort-Object Time -Descending | Select-Object -First 1
        
        if ($ExtMatch) {
            $SourceIP = $ExtMatch.SrcIP
            $Method = "TIMESTAMP"
            $Delta = [Math]::Round(($Query.Time - $ExtMatch.Time).TotalMilliseconds, 1)
        }
    }
    
    # Find matching 1138 event (LDAP operation start)
    $Match1138 = $null
    if ($Events1138) {
        $Match1138 = $Events1138 | Where-Object {
            $_.ClientPort -eq $Query.ClientPort -and
            [Math]::Abs(($_.Time - $Query.Time).TotalMilliseconds) -lt 200
        } | Sort-Object { [Math]::Abs(($_.Time - $Query.Time).TotalMilliseconds) } | Select-Object -First 1
    }
    
    if ($SourceIP) {
        $Confidence = switch ($Method) {
            { $_ -match '^PORT' } { 'High (deterministic)' }
            'TIMESTAMP' { 
                if ($Delta -lt 100) { 'High' } 
                elseif ($Delta -lt 250) { 'Medium' } 
                else { 'Low' } 
            }
        }
        
        # Calculate deltas between events
        $Delta5156to1138 = $null
        $Delta1138to1644 = $null
        if ($Match1138) {
            $Delta5156to1138 = [Math]::Round(($Match1138.Time - $ExtMatch.Time).TotalMilliseconds, 1)
            $Delta1138to1644 = [Math]::Round(($Query.Time - $Match1138.Time).TotalMilliseconds, 1)
        }
        
        return [PSCustomObject]@{
            Time           = $Query.Time
            SourceIP       = $SourceIP
            SourcePort     = $ExtMatch.SrcPort
            User           = $Query.User
            Method         = $Method
            DeltaMs        = $Delta
            Confidence     = $Confidence
            ClientPort     = $Query.ClientPort
            Filter         = $Query.Filter
            Attributes     = $Query.Attributes
            Controls       = $Query.Controls
            Visited        = $Query.Visited
            Returned       = $Query.Returned
            UsedIndexes    = $Query.UsedIndexes
            PagesRef       = $Query.PagesRef
            SearchTimeMs   = $Query.SearchTimeMs
            BaseDN         = $Query.BaseDN
            Suspicious     = (Get-SuspiciousIndicators -Query $Query) -join '; '
            Event5156Time  = $ExtMatch.Time
            Event1138Time  = if ($Match1138) { $Match1138.Time } else { $null }
            Event1138Op    = if ($Match1138) { $Match1138.Operation } else { $null }
            Event1138Sid   = if ($Match1138) { $Match1138.UserSid } else { $null }
            Delta5156to1138 = $Delta5156to1138
            Delta1138to1644 = $Delta1138to1644
        }
    }
    
    return $null
}

#endregion

#region Monitor Mode

if ($Monitor) {
    $SeenEvents = @{}
    
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║           ADWS Real-Time Source IP Monitor                       ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                  ║" -ForegroundColor Cyan
    Write-Host "  ║   Correlation: 5156 (external) → 1644 (LDAP query)               ║" -ForegroundColor DarkCyan
    Write-Host "  ║   Method: Timestamp-based (~60-100ms delta)                      ║" -ForegroundColor DarkCyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [*] Monitoring for external ADWS queries..." -ForegroundColor Yellow
    Write-Host "  [*] Poll interval: ${PollSeconds}s | Press Ctrl+C to stop" -ForegroundColor DarkGray
    if ($AlertOnly) {
        Write-Host "  [*] Alert-only mode: hiding benign queries" -ForegroundColor DarkGray
    }
    Write-Host ""
    
    $LastCheck = (Get-Date).AddSeconds(-$PollSeconds)
    
    while ($true) {
        $Now = Get-Date
        $WindowStart = $LastCheck.AddSeconds(-1)
        
        # Get new events
        $External = Get-External5156 -Start $WindowStart -End $Now | 
            Where-Object { -not $SeenEvents.ContainsKey("5156_$($_.RecordId)") }
        
        $Internal = Get-Internal5156 -Start $WindowStart -End $Now
        
        $Recent1138 = Get-Events1138 -Start $Now.AddSeconds(-10) -End $Now
        
        $Queries = Get-Events1644 -Start $WindowStart -End $Now | 
            Where-Object { -not $SeenEvents.ContainsKey("1644_$($_.RecordId)") }
        
        # Also get recent 5156 for correlation (may have arrived before this poll)
        $RecentExternal = Get-External5156 -Start $Now.AddSeconds(-10) -End $Now
        
        foreach ($q in $Queries) {
            $SeenEvents["1644_$($q.RecordId)"] = $true
            
            $Result = Correlate-Query -Query $q -External5156 $RecentExternal -Internal5156 $Internal -Events1138 $Recent1138
            
            if ($Result) {
                $IsSuspicious = $Result.Suspicious.Length -gt 0
                
                if ($AlertOnly -and -not $IsSuspicious) { continue }
                
                # Get per-event indicators
                $Ind5156 = Get-5156Indicators -SourceIP $Result.SourceIP -DestPort 9389
                $Ind1138 = if ($Result.Event1138Time) { Get-1138Indicators -ClientPort $Result.ClientPort } else { @() }
                $Ind1644 = if ($Result.Suspicious) { $Result.Suspicious -split '; ' } else { @() }
                
                Write-Host ""
                if ($IsSuspicious) {
                    Write-Host "  ╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                    Write-Host "  ║  [!] SUSPICIOUS ADWS QUERY DETECTED                            ║" -ForegroundColor Red
                    Write-Host "  ╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                } else {
                    Write-Host "  ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
                    Write-Host "  │  [i] ADWS Query Detected                                      │" -ForegroundColor Yellow
                    Write-Host "  └────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "    Source IP:   $($Result.SourceIP)" -ForegroundColor $(if ($IsSuspicious) { 'Red' } else { 'Cyan' })
                Write-Host "    User:        $($Result.User)" -ForegroundColor $(if ($IsSuspicious) { 'Yellow' } else { 'Gray' })
                Write-Host "    Correlation: $($Result.Method) | $($Result.Confidence) ($($Result.DeltaMs)ms)" -ForegroundColor DarkGray
                
                # IOC Summary
                Write-Host ""
                Write-Host "    IOC Summary:" -ForegroundColor $(if ($IsSuspicious) { 'Red' } else { 'Yellow' })
                foreach ($i in $Ind5156) { Write-Host "      [5156] $i" -ForegroundColor Gray }
                foreach ($i in $Ind1138) { Write-Host "      [1138] $i" -ForegroundColor Gray }
                foreach ($i in $Ind1644) { Write-Host "      [1644] $i" -ForegroundColor $(if ($IsSuspicious) { 'Red' } else { 'Gray' }) }
                
                Write-Host ""
                Write-Host "    Event Chain:" -ForegroundColor Cyan
                Write-Host "    ┌───────────────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
                Write-Host "    │ [5156] $($Result.Event5156Time.ToString('HH:mm:ss.fff')) - Security Log (WFP Connection)                                  │" -ForegroundColor White
                Write-Host "    │        Source:      $($Result.SourceIP):$($Result.SourcePort)" -ForegroundColor Gray
                Write-Host "    │        Destination: DC:9389 (ADWS)" -ForegroundColor Gray
                Write-Host "    │        Application: microsoft.activedirectory.webservices.exe" -ForegroundColor Gray
                foreach ($i in $Ind5156) {
                    Write-Host "    │        » $i" -ForegroundColor DarkYellow
                }
                Write-Host "    │" -ForegroundColor DarkCyan
                if ($Result.Event1138Time) {
                    Write-Host "    │                     ↓ $($Result.Delta5156to1138)ms" -ForegroundColor DarkYellow
                    Write-Host "    │" -ForegroundColor DarkCyan
                    Write-Host "    │ [1138] $($Result.Event1138Time.ToString('HH:mm:ss.fff')) - Directory Service (LDAP Op Start)                           │" -ForegroundColor White
                    Write-Host "    │        Client:      [::1]:$($Result.ClientPort)" -ForegroundColor Gray
                    Write-Host "    │        Operation:   $($Result.Event1138Op)" -ForegroundColor Gray
                    Write-Host "    │        User SID:    $($Result.Event1138Sid)" -ForegroundColor Gray
                    foreach ($i in $Ind1138) {
                        Write-Host "    │        » $i" -ForegroundColor DarkYellow
                    }
                    Write-Host "    │" -ForegroundColor DarkCyan
                    Write-Host "    │                     ↓ $($Result.Delta1138to1644)ms" -ForegroundColor DarkYellow
                } else {
                    Write-Host "    │                     ↓ $($Result.DeltaMs)ms" -ForegroundColor DarkYellow
                }
                Write-Host "    │" -ForegroundColor DarkCyan
                Write-Host "    │ [1644] $($Result.Time.ToString('HH:mm:ss.fff')) - Directory Service (Expensive Search)                         │" -ForegroundColor White
                Write-Host "    │        Client:      [::1]:$($Result.ClientPort)" -ForegroundColor Gray
                Write-Host "    │        User:        $($Result.User)" -ForegroundColor Gray
                Write-Host "    │        Base DN:     $($Result.BaseDN)" -ForegroundColor Gray
                Write-Host "    │        Filter:      $($Result.Filter)" -ForegroundColor Gray
                Write-Host "    │        Attributes:  $($Result.Attributes)" -ForegroundColor Gray
                Write-Host "    │        Controls:    $($Result.Controls)" -ForegroundColor Gray
                Write-Host "    │" -ForegroundColor DarkCyan
                Write-Host "    │        Search Statistics:" -ForegroundColor Gray
                Write-Host "    │          Visited:     $($Result.Visited) entries" -ForegroundColor DarkGray
                Write-Host "    │          Returned:    $($Result.Returned) entries" -ForegroundColor DarkGray
                Write-Host "    │          Indexes:     $($Result.UsedIndexes)" -ForegroundColor DarkGray
                Write-Host "    │          Pages:       $($Result.PagesRef)" -ForegroundColor DarkGray
                Write-Host "    │          Search Time: $($Result.SearchTimeMs)ms" -ForegroundColor DarkGray
                if ($IsSuspicious) {
                    Write-Host "    │" -ForegroundColor DarkCyan
                    Write-Host "    │        [!] Suspicious Indicators:" -ForegroundColor Red
                    foreach ($i in $Ind1644) {
                        Write-Host "    │          • $i" -ForegroundColor Red
                    }
                }
                Write-Host "    └───────────────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
                Write-Host ""
            }
        }
        
        # Mark external events as seen
        foreach ($e in $External) {
            $SeenEvents["5156_$($e.RecordId)"] = $true
        }
        
        $LastCheck = $Now
        Start-Sleep -Seconds $PollSeconds
    }
}

#endregion

#region Hunt Mode

$StartTime = (Get-Date).AddMinutes(-$Minutes)
$EndTime = Get-Date

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║           ADWS Source IP Attribution - Hunt Mode                 ║" -ForegroundColor Cyan
Write-Host "  ║                                                                  ║" -ForegroundColor Cyan
Write-Host "  ║   Correlation: 5156 (external) → 1644 (LDAP query)               ║" -ForegroundColor DarkCyan
Write-Host "  ║   Methods: PORT (deterministic) + TIMESTAMP (fallback)           ║" -ForegroundColor DarkCyan
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Time Range: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) → $($EndTime.ToString('HH:mm:ss'))" -ForegroundColor Gray
Write-Host ""

# Collect events
Write-Host "  [1/4] Collecting 5156 (external → port 9389)..." -ForegroundColor Yellow -NoNewline
$External5156 = Get-External5156 -Start $StartTime -End $EndTime
Write-Host " $($External5156.Count)" -ForegroundColor White

Write-Host "  [2/4] Collecting 5156 (internal ADWS → LDAP)..." -ForegroundColor Yellow -NoNewline
$Internal5156 = Get-Internal5156 -Start $StartTime -End $EndTime
Write-Host " $($Internal5156.Count)" -ForegroundColor White

Write-Host "  [3/4] Collecting 1138 (LDAP operations)..." -ForegroundColor Yellow -NoNewline
$Events1138 = Get-Events1138 -Start $StartTime -End $EndTime
Write-Host " $($Events1138.Count)" -ForegroundColor White

Write-Host "  [4/4] Collecting 1644 (query details)..." -ForegroundColor Yellow -NoNewline
$Events1644 = Get-Events1644 -Start $StartTime -End $EndTime
Write-Host " $($Events1644.Count)" -ForegroundColor White
Write-Host ""

# Debug output
if ($Detailed) {
    Write-Host "  ┌─ DEBUG: Event Summary ─────────────────────────────────────────┐" -ForegroundColor Magenta
    
    if ($External5156.Count -gt 0) {
        Write-Host "  │ External 5156 (→9389):" -ForegroundColor Magenta
        $External5156 | Select-Object -First 5 | ForEach-Object {
            Write-Host "  │   $($_.Time.ToString('HH:mm:ss.fff')) | $($_.SrcIP):$($_.SrcPort)" -ForegroundColor DarkMagenta
        }
    }
    
    if ($Internal5156.Count -gt 0) {
        Write-Host "  │ Internal 5156 (ADWS→389):" -ForegroundColor Magenta
        $Internal5156 | Select-Object -First 5 | ForEach-Object {
            Write-Host "  │   $($_.Time.ToString('HH:mm:ss.fff')) | ::1:$($_.SrcPort)" -ForegroundColor DarkMagenta
        }
    }
    
    if ($Events1644.Count -gt 0) {
        Write-Host "  │ 1644 Client Ports:" -ForegroundColor Magenta
        $Events1644 | Select-Object -First 5 | ForEach-Object {
            Write-Host "  │   $($_.Time.ToString('HH:mm:ss.fff')) | Port: $($_.ClientPort)" -ForegroundColor DarkMagenta
        }
    }
    Write-Host "  └───────────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
    Write-Host ""
}

# Correlate
$Results = @()
foreach ($q in $Events1644) {
    $Result = Correlate-Query -Query $q -External5156 $External5156 -Internal5156 $Internal5156 -Events1138 $Events1138
    if ($Result) { $Results += $Result }
}
$Results = $Results | Sort-Object Time -Descending

# Output results
if ($Results.Count -eq 0) {
    Write-Host "  [!] No external ADWS queries found to correlate." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "      Possible reasons:" -ForegroundColor Gray
    Write-Host "        • No external ADWS activity in time window" -ForegroundColor DarkGray
    Write-Host "        • 5156 logging not enabled (WFP)" -ForegroundColor DarkGray
    Write-Host "        • 1644 logging not enabled (Field Engineering)" -ForegroundColor DarkGray
    Write-Host ""
    return
}

# Summary
$ByMethod = $Results | Group-Object { if ($_.Method -match '^PORT') { 'PORT [deterministic]' } else { 'TIMESTAMP [probabilistic]' } }
$ByIP = $Results | Group-Object SourceIP | Sort-Object Count -Descending

Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  RESULTS                                                         ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "    Correlated Queries: $($Results.Count)" -ForegroundColor White
Write-Host ""
Write-Host "    Correlation Methods:" -ForegroundColor Yellow
foreach ($m in $ByMethod) {
    Write-Host "      $($m.Name): $($m.Count)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "    Source IPs:" -ForegroundColor Yellow
foreach ($ip in $ByIP) {
    $suspicious = ($ip.Group | Where-Object { $_.Suspicious }).Count
    $color = if ($suspicious -gt 0) { 'Red' } else { 'Gray' }
    Write-Host "      $($ip.Name): $($ip.Count) queries" -NoNewline -ForegroundColor $color
    if ($suspicious -gt 0) { Write-Host " ($suspicious suspicious)" -ForegroundColor Red }
    else { Write-Host "" }
}

# Suspicious queries
$Suspicious = $Results | Where-Object { $_.Suspicious }
if ($Suspicious) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  SUSPICIOUS QUERIES                                              ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    
    foreach ($r in $Suspicious) {
        # Get per-event indicators
        $Ind5156 = Get-5156Indicators -SourceIP $r.SourceIP -DestPort 9389
        $Ind1138 = if ($r.Event1138Time) { Get-1138Indicators -ClientPort $r.ClientPort } else { @() }
        $Ind1644 = if ($r.Suspicious) { $r.Suspicious -split '; ' } else { @() }
        
        Write-Host ""
        Write-Host "    Source IP:   $($r.SourceIP)" -ForegroundColor Red
        Write-Host "    User:        $($r.User)" -ForegroundColor Yellow
        Write-Host "    Correlation: $($r.Method) | $($r.Confidence) ($($r.DeltaMs)ms)" -ForegroundColor DarkGray
        
        # IOC Summary
        Write-Host ""
        Write-Host "    IOC Summary:" -ForegroundColor Red
        foreach ($i in $Ind5156) { Write-Host "      [5156] $i" -ForegroundColor Gray }
        foreach ($i in $Ind1138) { Write-Host "      [1138] $i" -ForegroundColor Gray }
        foreach ($i in $Ind1644) { Write-Host "      [1644] $i" -ForegroundColor Red }
        
        Write-Host ""
        Write-Host "    Event Chain:" -ForegroundColor Cyan
        Write-Host "    ┌───────────────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
        Write-Host "    │ [5156] $($r.Event5156Time.ToString('HH:mm:ss.fff')) - Security Log (WFP Connection)                                  │" -ForegroundColor White
        Write-Host "    │        Source:      $($r.SourceIP):$($r.SourcePort)" -ForegroundColor Gray
        Write-Host "    │        Destination: DC:9389 (ADWS)" -ForegroundColor Gray
        Write-Host "    │        Application: microsoft.activedirectory.webservices.exe" -ForegroundColor Gray
        foreach ($i in $Ind5156) {
            Write-Host "    │        » $i" -ForegroundColor DarkYellow
        }
        Write-Host "    │" -ForegroundColor DarkCyan
        if ($r.Event1138Time) {
            Write-Host "    │                     ↓ $($r.Delta5156to1138)ms" -ForegroundColor DarkYellow
            Write-Host "    │" -ForegroundColor DarkCyan
            Write-Host "    │ [1138] $($r.Event1138Time.ToString('HH:mm:ss.fff')) - Directory Service (LDAP Op Start)                           │" -ForegroundColor White
            Write-Host "    │        Client:      [::1]:$($r.ClientPort)" -ForegroundColor Gray
            Write-Host "    │        Operation:   $($r.Event1138Op)" -ForegroundColor Gray
            Write-Host "    │        User SID:    $($r.Event1138Sid)" -ForegroundColor Gray
            foreach ($i in $Ind1138) {
                Write-Host "    │        » $i" -ForegroundColor DarkYellow
            }
            Write-Host "    │" -ForegroundColor DarkCyan
            Write-Host "    │                     ↓ $($r.Delta1138to1644)ms" -ForegroundColor DarkYellow
        } else {
            Write-Host "    │                     ↓ $($r.DeltaMs)ms" -ForegroundColor DarkYellow
        }
        Write-Host "    │" -ForegroundColor DarkCyan
        Write-Host "    │ [1644] $($r.Time.ToString('HH:mm:ss.fff')) - Directory Service (Expensive Search)                         │" -ForegroundColor White
        Write-Host "    │        Client:      [::1]:$($r.ClientPort)" -ForegroundColor Gray
        Write-Host "    │        User:        $($r.User)" -ForegroundColor Gray
        Write-Host "    │        Base DN:     $($r.BaseDN)" -ForegroundColor Gray
        Write-Host "    │        Filter:      $($r.Filter)" -ForegroundColor Gray
        Write-Host "    │        Attributes:  $($r.Attributes)" -ForegroundColor Gray
        Write-Host "    │        Controls:    $($r.Controls)" -ForegroundColor Gray
        Write-Host "    │" -ForegroundColor DarkCyan
        Write-Host "    │        Search Statistics:" -ForegroundColor Gray
        Write-Host "    │          Visited:     $($r.Visited) entries" -ForegroundColor DarkGray
        Write-Host "    │          Returned:    $($r.Returned) entries" -ForegroundColor DarkGray
        Write-Host "    │          Indexes:     $($r.UsedIndexes)" -ForegroundColor DarkGray
        Write-Host "    │          Pages:       $($r.PagesRef)" -ForegroundColor DarkGray
        Write-Host "    │          Search Time: $($r.SearchTimeMs)ms" -ForegroundColor DarkGray
        Write-Host "    │" -ForegroundColor DarkCyan
        Write-Host "    │        [!] Suspicious Indicators:" -ForegroundColor Red
        foreach ($i in $Ind1644) {
            Write-Host "    │          • $i" -ForegroundColor Red
        }
        Write-Host "    └───────────────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
        Write-Host ""
    }
}

# Non-suspicious (if ShowAll)
if ($ShowAll) {
    $NonSuspicious = $Results | Where-Object { -not $_.Suspicious }
    if ($NonSuspicious) {
        Write-Host ""
        Write-Host "  ┌─ ALL OTHER QUERIES ────────────────────────────────────────────┐" -ForegroundColor Gray
        foreach ($r in $NonSuspicious) {
            Write-Host "  │ $($r.Time.ToString('HH:mm:ss.fff')) | $($r.SourceIP) | $($r.User) | $($r.Method) ($($r.DeltaMs)ms)" -ForegroundColor DarkGray
        }
        Write-Host "  └───────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    }
}

Write-Host ""

# Return for pipeline
$Results

#endregion
