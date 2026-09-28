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
#>

<#
.SYNOPSIS
    LDAP Client-Side Log Collector (LDAPMon)
    
.DESCRIPTION
    Collects and analyzes LDAP client-side logs from LDAPMon for obfuscation hunting.
    
    REQUIRES: LDAPMon from https://github.com/jonny-jhnson/LDAPMon
    
    WHY CLIENT-SIDE LOGGING?
    LDAPMon captures RAW LDAP queries BEFORE the Domain Controller normalizes them.
    This is the ONLY way to detect encoding-based obfuscation that Event 1644 cannot see:
    
    - Hex encoding:     (name=\44omain \41dmins)  → DC sees: (name=Domain Admins)
    - OID attributes:   (1.2.840.113556.1.4.1=x)  → DC sees: (name=x)
    - Null bytes:       (name=kr\00btgt)          → DC sees: (name=krbtgt)
    - Invalid bytes:    (name=\80kr\90btgt)       → DC sees: (name=krbtgt)
    
    Use this script on the CLIENT/WORKSTATION that initiates LDAP queries.
    For Domain Controller logs (Event 1644), use Get-DCLDAPLogs.ps1 instead.

.NOTES
    Author: MaLDAPtive Detection Project
    Purpose: LDAP client-side log collection for security testing and hunting
    License: MIT

.EXAMPLE
    # Load the script
    . .\Get-LDAPClientLogs.ps1

    # Check if LDAPMon is running
    Get-LDAPLogStatus

    # Hunt for obfuscation (exclude normal Windows traffic)
    Search-LDAPLogs -ObfuscationType All -ExcludeProcess lsass

    # Watch logs in real-time
    Watch-LDAPLogs -DurationSeconds 120

    # Export logs to EVTX
    Export-LDAPLogs -Path ".\logs" -StartTime (Get-Date).AddHours(-1)
#>

#Requires -Version 5.1

#region Configuration

# Log configuration - LDAPMon is the only reliable source for raw LDAP filter capture
$script:LDAPLogConfig = @{
    LDAPMon = @{
        Name = "LDAPMon/Operational"
        Description = "LDAPMon ETW events (https://github.com/jonny-jhnson/LDAPMon)"
        ProcessName = "LDAPMonitor"
        RequiresEnable = $false
    }
}

# Client-side obfuscation patterns
# These detect encoding-based obfuscation that is DECODED before Event 1644 sees it
$script:ClientObfuscationPatterns = @{
    HexEncoding = @{
        Description = "Hex-encoded characters (\XX format)"
        Pattern = '\\[0-9a-fA-F]{2}'
        Example = '(name=\44omain \41dmins)'
        DecodedAs = '(name=Domain Admins)'
    }
    NullByteInjection = @{
        Description = "Null byte injection (\00)"
        Pattern = '\\00'
        Example = '(name=kr\00btgt)'
        DecodedAs = '(name=krbtgt)'
    }
    InvalidByteInjection = @{
        Description = "Invalid UTF-8 bytes (\80-\FF range)"
        Pattern = '\\[89a-fA-F][0-9a-fA-F]'
        Example = '(name=\80kr\90btgt\ff)'
        DecodedAs = '(name=krbtgt)'
    }
    OIDAttribute = @{
        Description = "OID instead of attribute name"
        Pattern = '\(1\.2\.840\.113556\.[0-9.]+='
        Example = '(1.2.840.113556.1.4.1=krbtgt)'
        DecodedAs = '(name=krbtgt)'
    }
    OIDWithHex = @{
        Description = "OID attribute with hex-encoded value"
        Pattern = '\(1\.2\.840\.113556\.[0-9.]+=\\[0-9a-fA-F]{2}'
        Example = '(1.2.840.113556.1.4.1=\6b\72\62\74\67\74)'
        DecodedAs = '(name=krbtgt)'
    }
    LeadingZeros = @{
        Description = "Leading zeros in numeric values"
        Pattern = '=0{2,}\d+'
        Example = '(sAMAccountType=0000805306368)'
        DecodedAs = '(sAMAccountType=805306368)'
    }
    # Structural patterns (also visible in Event 1644, included for completeness)
    DoubleNegation = @{
        Description = "Double NOT operators"
        Pattern = '\(\s*!\s*\(\s*!'
        Example = '(!(!(name=krbtgt)))'
        DecodedAs = 'Same (structural)'
    }
    DeMorganTransform = @{
        Description = "De Morgan boolean transform"
        Pattern = '\(\s*!\s*\(\s*[|&]'
        Example = '(!(&(name=x)(name=y)))'
        DecodedAs = 'Same (structural)'
    }
    ExcessiveWildcards = @{
        Description = "Multiple wildcards fragmenting values"
        Pattern = '\*[^*)]+\*[^*)]+\*'
        Example = '(name=*D*o*m*a*i*n*)'
        DecodedAs = 'Same (structural)'
    }
    FakeMatchingRule = @{
        Description = "Fake/invalid extensible matching rule"
        Pattern = ':[a-zA-Z]+:'
        Example = '(objectCategory:theisfrom:=Computer)'
        DecodedAs = 'Same (structural)'
    }
    BooleanPadding = @{
        Description = "Unnecessary boolean padding (meaningless conditions added to filter)"
        # Match !invalidAttr=* (non-existent attribute negation) which is always true
        # Don't match standalone (objectClass=*) as that's a normal rootDSE query
        Pattern = '!invalidAttr=\*|!\s*\(\s*invalidAttr'
        Example = '(&(name=x)(!invalidAttr=*))'
        DecodedAs = 'Same (structural)'
    }
    RangeOperator = @{
        Description = "Range operators instead of equality"
        Pattern = '[<>]=?[^)]+\)'
        Example = '(sAMAccountType>=805306367)'
        DecodedAs = 'Same (structural)'
    }
}

#endregion

#region Parsing Functions

# Scope mapping (same as LDAP standard)
$script:ScopeMap = @{
    "0" = "base"
    "1" = "onelevel"  
    "2" = "subtree"
}

function Parse-LDAPMonEvent {
    <#
    .SYNOPSIS
        Parse LDAPMon event into structured object
    .DESCRIPTION
        Extracts fields from LDAPMon event message into a consistent format
        similar to Parse-Event1644 in the DC script.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Event
    )
    
    process {
        $msg = $Event.Message
        
        # Parse each field from the message
        $eventTime = $null
        $scope = $null
        $scopeName = "unknown"
        $filter = $null
        $baseDN = $null
        $attributes = $null
        $processId = $null
        
        # EventTime: 2025-12-12T15:55:08.195525800Z
        if ($msg -match 'EventTime:\s*([^\r\n]+)') {
            $eventTime = $Matches[1].Trim()
        }
        
        # ScopeOfSearch: 0/1/2
        if ($msg -match 'ScopeOfSearch:\s*(\d+)') {
            $scope = $Matches[1].Trim()
            $scopeName = if ($script:ScopeMap.ContainsKey($scope)) { $script:ScopeMap[$scope] } else { $scope }
        }
        
        # SearchFilter: (objectClass=*)
        if ($msg -match 'SearchFilter:\s*([^\r\n]+)') {
            $filter = $Matches[1].Trim()
        }
        
        # DistinguishedName: CN=...,DC=marvel,DC=local (this is the Base DN / search base)
        if ($msg -match 'DistinguishedName:\s*([^\r\n]*)') {
            $baseDN = $Matches[1].Trim()
        }
        # Always default to <rootDSE> if empty or not found
        if ([string]::IsNullOrWhiteSpace($baseDN)) {
            $baseDN = "<rootDSE>"
        }
        
        # AttributeList: attr1;attr2;attr3
        if ($msg -match 'AttributeList:\s*([^\r\n]*)') {
            $attributes = $Matches[1].Trim()
            if ([string]::IsNullOrWhiteSpace($attributes)) {
                $attributes = "[all]"
            }
        }
        
        # ProcessId: 6056
        if ($msg -match 'ProcessId:\s*(\d+)') {
            $processId = [int]$Matches[1]
        }
        
        # Try to get process name from PID (only works if process is still running)
        $processName = $null
        if ($processId) {
            try {
                $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($proc) {
                    $processName = $proc.ProcessName
                }
            } catch {}
        }
        
        # Get user from event Security element (UserID is a SID)
        $user = $null
        try {
            $userSid = $Event.UserId
            if ($userSid) {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($userSid)
                $user = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            }
        } catch {
            # If SID translation fails, show raw SID
            if ($Event.UserId) {
                $user = $Event.UserId.ToString()
            }
        }
        
        [PSCustomObject]@{
            TimeCreated    = $Event.TimeCreated
            RecordId       = $Event.RecordId
            EventId        = $Event.Id
            LogSource      = "LDAPMon"
            Filter         = $filter
            BaseDN         = $baseDN
            Scope          = $scopeName
            ScopeNum       = $scope
            Attributes     = $attributes
            ProcessId      = $processId
            ProcessName    = $processName
            User           = $user
            RawMessage     = $msg
            RawEvent       = $Event
        }
    }
}

function Format-LDAPMonEvent {
    <#
    .SYNOPSIS
        Display a parsed LDAPMon event in formatted output
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $ParsedEvent,
        
        [switch]$ShowRaw,
        
        [switch]$ShowSource
    )
    
    process {
        Write-Host ("─" * 80) -ForegroundColor DarkGray
        
        # Show log source if requested or if it's not LDAPMon (to highlight Debug logs)
        if ($ShowSource -or ($ParsedEvent.LogSource -and $ParsedEvent.LogSource -ne "LDAPMon")) {
            Write-Host "  Source:      " -NoNewline -ForegroundColor Gray
            $sourceColor = if ($ParsedEvent.LogSource -eq "LDAPMon") { "Magenta" } else { "DarkCyan" }
            Write-Host $ParsedEvent.LogSource -ForegroundColor $sourceColor
        }
        
        Write-Host "  Time:        " -NoNewline -ForegroundColor Gray
        Write-Host $ParsedEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff") -ForegroundColor White
        
        # Show User if available
        if ($ParsedEvent.User) {
            Write-Host "  User:        " -NoNewline -ForegroundColor Gray
            Write-Host $ParsedEvent.User -ForegroundColor Cyan
        }
        
        if ($ParsedEvent.ProcessId) {
            Write-Host "  Process:     " -NoNewline -ForegroundColor Gray
            $procInfo = "PID $($ParsedEvent.ProcessId)"
            if ($ParsedEvent.ProcessName) {
                $procInfo += " ($($ParsedEvent.ProcessName))"
            }
            Write-Host $procInfo -ForegroundColor Cyan
        }
        
        Write-Host "  Base DN:     " -NoNewline -ForegroundColor Gray
        $baseDN = if ([string]::IsNullOrWhiteSpace($ParsedEvent.BaseDN)) { "<rootDSE>" } else { $ParsedEvent.BaseDN }
        Write-Host $baseDN -ForegroundColor White
        
        Write-Host "  Scope:       " -NoNewline -ForegroundColor Gray
        Write-Host $ParsedEvent.Scope -ForegroundColor White
        
        Write-Host "  Filter:      " -NoNewline -ForegroundColor Gray
        Write-Host $ParsedEvent.Filter -ForegroundColor Yellow
        
        Write-Host "  Attributes:  " -NoNewline -ForegroundColor Gray
        $attrDisplay = if ([string]::IsNullOrWhiteSpace($ParsedEvent.Attributes)) { "[all]" } else { $ParsedEvent.Attributes }
        # Truncate long attribute lists
        if ($attrDisplay.Length -gt 60) {
            $attrDisplay = $attrDisplay.Substring(0, 57) + "..."
        }
        Write-Host $attrDisplay -ForegroundColor White
        
        if ($ShowRaw) {
            Write-Host ""
            Write-Host "  --- RAW MESSAGE ---" -ForegroundColor DarkMagenta
            Write-Host $ParsedEvent.RawMessage -ForegroundColor DarkGray
            Write-Host "  --- END RAW ---" -ForegroundColor DarkMagenta
        }
        
        Write-Host ""
    }
}

#endregion

function Get-LDAPLogStatus {
    <#
    .SYNOPSIS
        Check the status of LDAPMon logging
    .DESCRIPTION
        Displays whether LDAPMon is installed and logging events.
        Shows event counts and provides setup instructions if needed.
    .EXAMPLE
        Get-LDAPLogStatus
    #>
    [CmdletBinding()]
    param()
    
    $computerName = $env:COMPUTERNAME
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  LDAP CLIENT LOG STATUS (LDAPMon)" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Computer: $computerName" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    $ldapMonLogName = $script:LDAPLogConfig.LDAPMon.Name
    $ldapMonReady = $false
    
    Write-Host "  LDAPMon/Operational" -ForegroundColor White
    Write-Host "    Channel: $ldapMonLogName" -ForegroundColor Cyan
    
    # Check if channel exists
    $ldapMonExists = $false
    $ldapMonConfig = ""
    try {
        $ldapMonConfigRaw = & wevtutil gl $ldapMonLogName 2>&1
        $ldapMonConfig = $ldapMonConfigRaw -join "`n"
        if ($LASTEXITCODE -eq 0 -and $ldapMonConfig -notmatch "not found|does not exist|failed") {
            $ldapMonExists = $true
        }
    }
    catch {
        $ldapMonExists = $false
    }
    
    Write-Host "    Channel Exists: " -NoNewline -ForegroundColor Gray
    if ($ldapMonExists) {
        Write-Host "YES" -ForegroundColor Green
        
        # Parse enabled status
        $ldapMonEnabled = $false
        if ($ldapMonConfig -match "enabled:\s*(true|false)") {
            $ldapMonEnabled = $Matches[1] -eq "true"
        }
        
        Write-Host "    Logging: " -NoNewline -ForegroundColor Gray
        if ($ldapMonEnabled) {
            Write-Host "ENABLED" -ForegroundColor Green
        } else {
            Write-Host "DISABLED" -ForegroundColor Yellow
        }
        
        # Get event count
        try {
            $events = Get-WinEvent -LogName $ldapMonLogName -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($events) {
                Write-Host "    Events: " -NoNewline -ForegroundColor Gray
                Write-Host "Available" -ForegroundColor Green
            } else {
                Write-Host "    Events: 0" -ForegroundColor DarkYellow
            }
        }
        catch {
            if ($_.Exception.Message -match "No events were found") {
                Write-Host "    Events: 0" -ForegroundColor DarkYellow
            }
        }
    } else {
        Write-Host "NO (LDAPMon not installed)" -ForegroundColor Yellow
    }
    
    # Check if LDAPMonitor.exe is running
    Write-Host "    LDAPMonitor.exe: " -NoNewline -ForegroundColor Gray
    $ldapMonProcess = Get-Process -Name "LDAPMonitor" -ErrorAction SilentlyContinue
    if ($ldapMonProcess) {
        Write-Host "RUNNING (PID: $($ldapMonProcess.Id))" -ForegroundColor Green
        $ldapMonReady = $ldapMonExists
    } else {
        Write-Host "NOT RUNNING" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    # ============================================
    # Summary and Recommendations
    # ============================================
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  STATUS SUMMARY" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    if ($ldapMonExists -and $ldapMonProcess) {
        Write-Host "  LDAPMon: " -NoNewline -ForegroundColor Gray
        Write-Host "READY" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Available commands:" -ForegroundColor Green
        Write-Host "    Get-LDAPLogs             - Retrieve historical logs" -ForegroundColor White
        Write-Host "    Watch-LDAPLogs           - Real-time monitoring" -ForegroundColor White
        Write-Host "    Search-LDAPLogs          - Hunt for obfuscation patterns" -ForegroundColor White
        Write-Host "    Export-LDAPLogs          - Export to file" -ForegroundColor White
        Write-Host ""
    } elseif ($ldapMonExists) {
        Write-Host "  LDAPMon: " -NoNewline -ForegroundColor Gray
        Write-Host "INSTALLED BUT NOT RUNNING" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Start LDAPMon with:" -ForegroundColor Yellow
        Write-Host "    LDAPMonitor.exe" -ForegroundColor White
        Write-Host ""
        Write-Host "  If you get Error 183, first run:" -ForegroundColor DarkGray
        Write-Host "    logman stop LDAPMon -ets" -ForegroundColor White
        Write-Host ""
    } else {
        Write-Host "  LDAPMon: " -NoNewline -ForegroundColor Gray
        Write-Host "NOT INSTALLED" -ForegroundColor Red
        Write-Host ""
        Write-Host "  LDAPMon is required for client-side LDAP filter capture." -ForegroundColor Yellow
        Write-Host "  Download from: " -NoNewline -ForegroundColor Gray
        Write-Host "https://github.com/jonny-jhnson/LDAPMon" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Why LDAPMon?" -ForegroundColor Gray
        Write-Host "    - Captures RAW LDAP filters before DC normalization" -ForegroundColor DarkGray
        Write-Host "    - Detects encoding-based obfuscation (hex, OID, null bytes)" -ForegroundColor DarkGray
        Write-Host "    - Event 1644 on DCs cannot see this obfuscation" -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

#endregion

#region Log Retrieval Functions

function Get-LDAPLogs {
    <#
    .SYNOPSIS
        Retrieve LDAP client logs from LDAPMon
    .DESCRIPTION
        Gets events from LDAPMon log with optional filtering.
        Displays parsed and formatted output.
    .PARAMETER MaxEvents
        Maximum events to retrieve (default: 100)
    .PARAMETER StartTime
        Only get events after this time (default: 1 hour ago)
    .PARAMETER EndTime
        Only get events before this time (default: now)
    .PARAMETER Raw
        Return raw event objects instead of formatted output
    .PARAMETER ShowRaw
        Show raw message in formatted output
    .EXAMPLE
        Get-LDAPLogs -MaxEvents 50
    .EXAMPLE
        Get-LDAPLogs -StartTime (Get-Date).AddMinutes(-30)
    #>
    [CmdletBinding()]
    param(
        [int]$MaxEvents = 100,
        
        [DateTime]$StartTime = (Get-Date).AddHours(-1),
        
        [DateTime]$EndTime = (Get-Date),
        
        [switch]$Raw,
        
        [switch]$ShowRaw
    )
    
    $logName = $script:LDAPLogConfig.LDAPMon.Name
    
    if (-not $Raw) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  LDAP CLIENT LOGS (LDAPMon)" -ForegroundColor White
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
        Write-Host "  Time Range: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host "  Log Source: $logName" -ForegroundColor Magenta
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
    
    $allParsedEvents = @()
    
    try {
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="$logName">
    <Select Path="$logName">*[System[TimeCreated[@SystemTime >= '$($StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))' and @SystemTime &lt;= '$($EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))']]]</Select>
  </Query>
</QueryList>
"@
        
        $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $MaxEvents -ErrorAction Stop
        
        if (-not $Raw) {
            Write-Host ""
            Write-Host "Found $($events.Count) events" -ForegroundColor Green
        }
        
        foreach ($event in $events) {
            # Parse LDAPMon event into structured format
            $parsed = Parse-LDAPMonEvent -Event $event
            $allParsedEvents += $parsed
            
            if (-not $Raw) {
                Format-LDAPMonEvent -ParsedEvent $parsed -ShowRaw:$ShowRaw
            }
        }
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            if (-not $Raw) {
                Write-Host ""
                Write-Host "No events found in time range" -ForegroundColor DarkYellow
            }
        } elseif ($_.Exception.Message -match "could not be found") {
            if (-not $Raw) {
                Write-Host ""
                Write-Host "LDAPMon log not available - is LDAPMon installed?" -ForegroundColor Red
                Write-Host "Get it from: https://github.com/jonny-jhnson/LDAPMon" -ForegroundColor Cyan
            }
        } else {
            if (-not $Raw) {
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    if (-not $Raw) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Total events: $($allParsedEvents.Count)" -ForegroundColor Green
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
    
    # Return events when -Raw is specified (for pipeline/scripting use)
    if ($Raw) {
        return $allParsedEvents
    }
}

function Search-LDAPLogs {
    <#
    .SYNOPSIS
        Search LDAPMon logs for obfuscation patterns
    .DESCRIPTION
        Hunts through LDAPMon logs looking for obfuscation patterns.
        Client-side logs capture RAW queries before DC normalization, making this
        the only way to detect encoding-based obfuscation (hex, OID, null bytes).
    .PARAMETER ObfuscationType
        Built-in obfuscation pattern to search for. Use "All" to check all patterns.
        Use Get-ClientObfuscationPatterns to see available patterns.
    .PARAMETER FilterPattern
        Custom regex pattern to search for in LDAP filters
    .PARAMETER StartTime
        Search start time (default: 24 hours ago)
    .PARAMETER EndTime
        Search end time (default: now)
    .PARAMETER ProcessName
        Filter to only include events from matching process name (e.g., "powershell*")
    .PARAMETER ExcludeProcess
        Exclude events from matching process names. Accepts array of patterns.
        Common exclusion: @("lsass", "svchost") to filter out normal Windows traffic.
    .PARAMETER NoDedupe
        Disable automatic deduplication. By default, duplicate events (same filter 
        within 1 second) are removed because LDAPMon logs each query twice.
    .EXAMPLE
        # Search for ALL obfuscation patterns
        Search-LDAPLogs -ObfuscationType All
    .EXAMPLE
        # Search for hex encoding specifically
        Search-LDAPLogs -ObfuscationType HexEncoding
    .EXAMPLE
        # Exclude normal Windows processes (lsass DC locator queries)
        Search-LDAPLogs -ObfuscationType All -ExcludeProcess @("lsass", "svchost")
    .EXAMPLE
        # Custom regex search
        Search-LDAPLogs -FilterPattern "krbtgt|adminCount"
    .EXAMPLE
        # Filter by process, include duplicates
        Search-LDAPLogs -ObfuscationType All -ProcessName "*powershell*" -NoDedupe
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("All", "HexEncoding", "NullByteInjection", "InvalidByteInjection", 
                     "OIDAttribute", "OIDWithHex", "LeadingZeros", "DoubleNegation",
                     "DeMorganTransform", "ExcessiveWildcards", "FakeMatchingRule",
                     "BooleanPadding", "RangeOperator")]
        [string]$ObfuscationType,
        
        [string]$FilterPattern,
        
        [DateTime]$StartTime = (Get-Date).AddDays(-1),
        
        [DateTime]$EndTime = (Get-Date),
        
        [string]$ProcessName,
        
        [string[]]$ExcludeProcess,
        
        [switch]$NoDedupe
    )
    
    # Auto-dedupe unless disabled (LDAPMon logs duplicates)
    $Dedupe = -not $NoDedupe
    
    $logName = $script:LDAPLogConfig.LDAPMon.Name
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  LDAP CLIENT OBFUSCATION HUNT" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "  Log source: " -NoNewline -ForegroundColor Gray
    Write-Host $logName -ForegroundColor Magenta
    Write-Host "  Time range: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    if ($ObfuscationType) {
        Write-Host "  Obfuscation: " -NoNewline -ForegroundColor Gray
        Write-Host $ObfuscationType -ForegroundColor Yellow
    }
    if ($FilterPattern) { 
        Write-Host "  Custom Pattern: " -NoNewline -ForegroundColor Gray
        Write-Host $FilterPattern -ForegroundColor Yellow
    }
    if ($ProcessName) {
        Write-Host "  Include Process: " -NoNewline -ForegroundColor Gray
        Write-Host $ProcessName -ForegroundColor Cyan
    }
    if ($ExcludeProcess) {
        Write-Host "  Exclude Process: " -NoNewline -ForegroundColor Gray
        Write-Host ($ExcludeProcess -join ", ") -ForegroundColor DarkYellow
    }
    # Show dedupe status with explanation
    Write-Host "  Dedupe: " -NoNewline -ForegroundColor Gray
    if ($Dedupe) {
        Write-Host "ON " -NoNewline -ForegroundColor Green
        Write-Host "(LDAPMon logs each query twice)" -ForegroundColor DarkGray
    } else {
        Write-Host "OFF" -ForegroundColor DarkYellow
    }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    # Build pattern list
    $patternsToCheck = @{}
    if ($ObfuscationType -eq "All") {
        $patternsToCheck = $script:ClientObfuscationPatterns.Clone()
    } elseif ($ObfuscationType -and $script:ClientObfuscationPatterns.ContainsKey($ObfuscationType)) {
        $patternsToCheck[$ObfuscationType] = $script:ClientObfuscationPatterns[$ObfuscationType]
    }
    
    if ($FilterPattern) {
        $patternsToCheck["CustomPattern"] = @{ 
            Description = "Custom regex pattern"
            Pattern = $FilterPattern 
        }
    }
    
    if ($patternsToCheck.Count -eq 0) {
        Write-Host "ERROR: Specify -ObfuscationType or -FilterPattern" -ForegroundColor Red
        Write-Host "       Use Get-ClientObfuscationPatterns to see available patterns" -ForegroundColor Gray
        return @()
    }
    
    # Get all parsed events from LDAPMon
    $events = Get-LDAPLogs -StartTime $StartTime -EndTime $EndTime -MaxEvents 10000 -Raw
    
    # Deduplicate if requested (same filter within 1 second window)
    $originalCount = if ($events) { $events.Count } else { 0 }
    if ($Dedupe -and $events -and $events.Count -gt 0) {
        $dedupedEvents = @()
        $seen = @{}
        foreach ($evt in $events) {
            $filter = if ($evt.PSObject.Properties['Filter']) { $evt.Filter } else { "" }
            $timeKey = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")  # 1-second granularity
            $dedupeKey = "$filter|$timeKey"
            if (-not $seen.ContainsKey($dedupeKey)) {
                $seen[$dedupeKey] = $true
                $dedupedEvents += $evt
            }
        }
        $events = $dedupedEvents
    }
    
    # Handle case where no events found
    if (-not $events -or $events.Count -eq 0) {
        Write-Host ""
        Write-Host "No events found in LDAPMon log" -ForegroundColor DarkYellow
        Write-Host "Make sure LDAPMon is running: Get-LDAPLogStatus" -ForegroundColor Gray
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return @()
    }
    
    # Display event count
    Write-Host "Events found: " -NoNewline -ForegroundColor Cyan
    Write-Host $events.Count -NoNewline -ForegroundColor Green
    if ($Dedupe -and $originalCount -ne $events.Count) {
        Write-Host " (deduped from $originalCount)" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
    Write-Host ""
    
    # Use different variable name to avoid collision with $Matches automatic variable
    $matchedEvents = @()
    $matchCounts = @{}
    foreach ($key in $patternsToCheck.Keys) { $matchCounts[$key] = 0 }
    
    foreach ($event in $events) {
        # Get filter from parsed LDAPMon event
        $filter = $event.Filter
        $timeCreated = $event.TimeCreated
        $processId = $event.ProcessId
        $procName = $event.ProcessName
        
        # Apply process include filter
        if ($ProcessName -and $procName -and $procName -notlike $ProcessName) { continue }
        
        # Apply process exclude filter
        if ($ExcludeProcess -and $procName) {
            $excluded = $false
            foreach ($excludePattern in $ExcludeProcess) {
                if ($procName -like $excludePattern -or $procName -eq $excludePattern) {
                    $excluded = $true
                    break
                }
            }
            if ($excluded) { continue }
        }
        
        # Check patterns
        $matchedPatterns = @()
        foreach ($patternName in $patternsToCheck.Keys) {
            $patternInfo = $patternsToCheck[$patternName]
            if ($filter -and $filter -match $patternInfo.Pattern) {
                $matchedPatterns += $patternName
                $matchCounts[$patternName]++
            }
        }
        
        if ($matchedPatterns.Count -gt 0) {
            $event | Add-Member -NotePropertyName "MatchedPatterns" -NotePropertyValue $matchedPatterns -Force
            $matchedEvents += $event
            
            # Display formatted match
            Write-Host ("─" * 80) -ForegroundColor Green
            Write-Host "  MATCH: " -NoNewline -ForegroundColor Green
            Write-Host ($matchedPatterns -join ", ") -ForegroundColor Yellow
            Write-Host "  Time:      $($timeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))" -ForegroundColor White
            
            # Show User if available
            if ($event.PSObject.Properties['User'] -and $event.User) {
                Write-Host "  User:      $($event.User)" -ForegroundColor Cyan
            }
            
            if ($processId) {
                $procInfo = "PID $processId"
                if ($procName) { $procInfo += " ($procName)" }
                Write-Host "  Process:   $procInfo" -ForegroundColor Cyan
            }
            
            # Show Base DN - handle empty/null cases
            $baseDNValue = if ($event.PSObject.Properties['BaseDN']) { $event.BaseDN } else { $null }
            if ([string]::IsNullOrWhiteSpace($baseDNValue)) {
                $baseDNValue = "<rootDSE>"
            }
            Write-Host "  Base DN:   $baseDNValue" -ForegroundColor Gray
            
            # Show Scope if available
            if ($event.PSObject.Properties['Scope']) {
                Write-Host "  Scope:     $($event.Scope)" -ForegroundColor Gray
            }
            
            # Show Filter prominently
            if ($filter) {
                Write-Host "  Filter:    " -NoNewline -ForegroundColor Gray
                Write-Host $filter -ForegroundColor Yellow
            }
            
            # Show what DC would see for encoding-based obfuscation
            $encodingPatterns = @("HexEncoding", "NullByteInjection", "InvalidByteInjection", 
                                  "OIDAttribute", "OIDWithHex", "LeadingZeros")
            $hasEncodingMatch = $matchedPatterns | Where-Object { $encodingPatterns -contains $_ }
            if ($hasEncodingMatch) {
                Write-Host "  DC sees:   " -NoNewline -ForegroundColor DarkGray
                Write-Host "(decoded/normalized - encoding stripped)" -ForegroundColor DarkRed
            }
            Write-Host ""
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Events searched: " -NoNewline -ForegroundColor Gray
    Write-Host $events.Count -NoNewline -ForegroundColor White
    if ($Dedupe -and $originalCount -ne $events.Count) {
        Write-Host " (deduped from $originalCount)" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
    
    Write-Host "  Matches found:   " -NoNewline -ForegroundColor Gray
    Write-Host $matchedEvents.Count -ForegroundColor $(if ($matchedEvents.Count -gt 0) { "Green" } else { "Yellow" })
    Write-Host ""
    
    if ($matchedEvents.Count -gt 0) {
        Write-Host "  Matches by pattern:" -ForegroundColor Yellow
        foreach ($patternName in $matchCounts.Keys | Sort-Object) {
            if ($matchCounts[$patternName] -gt 0) {
                $desc = $patternsToCheck[$patternName].Description
                Write-Host "    $($patternName.PadRight(25)) : " -NoNewline -ForegroundColor White
                Write-Host "$($matchCounts[$patternName].ToString().PadLeft(4))" -NoNewline -ForegroundColor Green
                Write-Host " - $desc" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    return $matchedEvents
}

function Get-ClientObfuscationPatterns {
    <#
    .SYNOPSIS
        List available client-side obfuscation detection patterns
    .DESCRIPTION
        Shows all built-in patterns that can be used with Search-LDAPLogs.
        Client-side patterns detect encoding-based obfuscation that the DC
        decodes before logging in Event 1644.
    .EXAMPLE
        Get-ClientObfuscationPatterns
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  CLIENT-SIDE OBFUSCATION PATTERNS" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  These patterns detect obfuscation BEFORE DC normalization." -ForegroundColor Gray
    Write-Host "  Event 1644 on the DC will NOT see these - only LDAPMon captures them." -ForegroundColor Gray
    Write-Host ""
    
    # Separate encoding patterns from structural patterns
    $encodingPatterns = @("HexEncoding", "NullByteInjection", "InvalidByteInjection", 
                          "OIDAttribute", "OIDWithHex", "LeadingZeros")
    
    Write-Host "  === ENCODING-BASED (Client-only detection) ===" -ForegroundColor Magenta
    Write-Host ""
    
    foreach ($name in $encodingPatterns) {
        if ($script:ClientObfuscationPatterns.ContainsKey($name)) {
            $info = $script:ClientObfuscationPatterns[$name]
            Write-Host "  $name" -ForegroundColor Yellow
            Write-Host "    $($info.Description)" -ForegroundColor Gray
            Write-Host "    Example: $($info.Example)" -ForegroundColor DarkCyan
            Write-Host "    DC sees: $($info.DecodedAs)" -ForegroundColor DarkGray
            Write-Host ""
        }
    }
    
    Write-Host "  === STRUCTURAL (Also visible in Event 1644) ===" -ForegroundColor Magenta
    Write-Host ""
    
    foreach ($name in $script:ClientObfuscationPatterns.Keys | Sort-Object) {
        if ($encodingPatterns -notcontains $name) {
            $info = $script:ClientObfuscationPatterns[$name]
            Write-Host "  $name" -ForegroundColor Yellow
            Write-Host "    $($info.Description)" -ForegroundColor Gray
            Write-Host "    Example: $($info.Example)" -ForegroundColor DarkCyan
            Write-Host ""
        }
    }
    
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  Usage: Search-LDAPLogs -ObfuscationType <PatternName>" -ForegroundColor Gray
    Write-Host "         Search-LDAPLogs -ObfuscationType All" -ForegroundColor Gray
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    return $script:ClientObfuscationPatterns
}

#endregion

#region Export Functions

function Export-LDAPLogs {
    <#
    .SYNOPSIS
        Export LDAP client logs to EVTX files
    .DESCRIPTION
        Exports events from LDAP client logs to EVTX format for offline analysis
        or archival.
    .PARAMETER Path
        Output directory (default: current directory)
    .PARAMETER StartTime
        Only export events after this time (default: 1 hour ago)
    .PARAMETER LogName
        Which log to export: "Debug", "Operational", "LDAPMon", or "All" (default)
    .PARAMETER Prefix
        Filename prefix (default: "LDAPClient")
    .EXAMPLE
        Export-LDAPLogs -Path ".\logs"
    .EXAMPLE
        Export-LDAPLogs -Path "C:\Evidence" -StartTime (Get-Date).AddDays(-1) -LogName Debug
    #>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        
        [DateTime]$StartTime = (Get-Date).AddHours(-1),
        
        [ValidateSet("Debug", "LDAPMon", "All")]
        [string]$LogName = "All",
        
        [string]$Prefix = "LDAPClient"
    )
    
    # Ensure output directory exists
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $startTimeStr = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    
    $logsToExport = if ($LogName -eq "All") {
        $script:LDAPLogConfig.Keys
    } else {
        @($LogName)
    }
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  EXPORTING LDAP CLIENT LOGS" -ForegroundColor White
    Write-Host "  Output: $Path" -ForegroundColor Gray
    Write-Host "  Time filter: >= $StartTime" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    $exportedFiles = @()
    
    foreach ($logKey in $logsToExport) {
        $logInfo = $script:LDAPLogConfig[$logKey]
        $logFullName = $logInfo.Name
        $safeLogName = $logKey
        $outputFile = Join-Path $Path "${Prefix}_${safeLogName}_${timestamp}.evtx"
        
        Write-Host "Exporting: $logFullName" -ForegroundColor Yellow
        
        try {
            $query = "*[System[TimeCreated[@SystemTime >= '$startTimeStr']]]"
            $result = & wevtutil epl $logFullName $outputFile /q:$query 2>&1
            
            if ($LASTEXITCODE -eq 0 -and (Test-Path $outputFile)) {
                $fileSize = (Get-Item $outputFile).Length
                if ($fileSize -gt 69632) {  # Empty EVTX is ~68KB
                    # Count events
                    $eventCount = 0
                    try {
                        $eventCount = (Get-WinEvent -Path $outputFile -ErrorAction SilentlyContinue | Measure-Object).Count
                    } catch {}
                    
                    Write-Host "  SUCCESS: $outputFile" -ForegroundColor Green
                    Write-Host "  Size: $([math]::Round($fileSize/1KB, 2)) KB | Events: $eventCount" -ForegroundColor Gray
                    $exportedFiles += [PSCustomObject]@{
                        LogName = $logFullName
                        FilePath = $outputFile
                        Size = $fileSize
                        Events = $eventCount
                    }
                } else {
                    Write-Host "  No events to export (empty)" -ForegroundColor DarkGray
                    Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
                }
            } else {
                Write-Host "  Export failed or log unavailable" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    Write-Host ("=" * 70) -ForegroundColor Cyan
    if ($exportedFiles.Count -gt 0) {
        Write-Host "  EXPORT COMPLETE: $($exportedFiles.Count) file(s)" -ForegroundColor Green
    } else {
        Write-Host "  No events exported" -ForegroundColor Yellow
    }
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    return $exportedFiles
}

#endregion

#region Real-Time Monitoring

function Watch-LDAPLogs {
    <#
    .SYNOPSIS
        Watch LDAP logs in real-time
    .DESCRIPTION
        Monitors LDAP client logs and displays events as they occur.
        For LDAPMon events, shows parsed and formatted output.
        Press Ctrl+C to stop.
    .PARAMETER DurationSeconds
        How long to watch (default: 60 seconds, 0 = indefinite)
    .PARAMETER LogName
        Which log to watch: "Debug", "LDAPMon", or "All"
    .PARAMETER Quiet
        Only show events, no status messages
    .PARAMETER Compact
        Show compact one-line output instead of full details
    .EXAMPLE
        Watch-LDAPLogs -DurationSeconds 120
    .EXAMPLE
        Watch-LDAPLogs -LogName LDAPMon -DurationSeconds 0 -Compact
    #>
    [CmdletBinding()]
    param(
        [int]$DurationSeconds = 60,
        
        [ValidateSet("Debug", "LDAPMon", "All")]
        [string]$LogName = "LDAPMon",
        
        [switch]$Quiet,
        
        [switch]$Compact
    )
    
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  LDAP CLIENT LOG WATCHER" -ForegroundColor White
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
        $durationText = if ($DurationSeconds -eq 0) { "indefinite" } else { "$DurationSeconds seconds" }
        Write-Host "  Duration: $durationText" -ForegroundColor Gray
        Write-Host "  Log source: $LogName" -ForegroundColor Gray
        Write-Host "  Press Ctrl+C to stop" -ForegroundColor DarkGray
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Watching for events..." -ForegroundColor Cyan
        Write-Host ""
    }
    
    $logsToWatch = if ($LogName -eq "All") {
        $script:LDAPLogConfig.Keys | ForEach-Object { $script:LDAPLogConfig[$_].Name }
    } else {
        @($script:LDAPLogConfig[$LogName].Name)
    }
    
    $startTime = Get-Date
    $endTime = if ($DurationSeconds -eq 0) { [DateTime]::MaxValue } else { $startTime.AddSeconds($DurationSeconds) }
    $lastCheck = $startTime
    $eventCount = 0
    
    try {
        while ((Get-Date) -lt $endTime) {
            foreach ($log in $logsToWatch) {
                $isLDAPMon = $log -match "LDAPMon"
                
                try {
                    $filterXml = @"
<QueryList>
  <Query Id="0" Path="$log">
    <Select Path="$log">*[System[TimeCreated[@SystemTime >= '$($lastCheck.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))']]]</Select>
  </Query>
</QueryList>
"@
                    $events = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue
                    
                    foreach ($event in $events) {
                        $eventCount++
                        
                        if ($isLDAPMon) {
                            # Parse and format LDAPMon event
                            $parsed = Parse-LDAPMonEvent -Event $event
                            
                            if ($Compact) {
                                # Compact one-line output
                                Write-Host "[$($parsed.TimeCreated.ToString("HH:mm:ss.fff"))] " -NoNewline -ForegroundColor DarkGray
                                $procInfo = "PID $($parsed.ProcessId)"
                                if ($parsed.ProcessName) { $procInfo = $parsed.ProcessName }
                                Write-Host "[$procInfo] " -NoNewline -ForegroundColor Cyan
                                
                                $filter = if ($parsed.Filter.Length -gt 60) {
                                    $parsed.Filter.Substring(0, 57) + "..."
                                } else {
                                    $parsed.Filter
                                }
                                Write-Host $filter -ForegroundColor Yellow
                            } else {
                                # Full formatted output
                                Format-LDAPMonEvent -ParsedEvent $parsed
                            }
                        } else {
                            # Debug log - show compact format
                            $shortLogName = $log.Split('/')[-1]
                            Write-Host "[$($event.TimeCreated.ToString("HH:mm:ss.fff"))] " -NoNewline -ForegroundColor DarkGray
                            Write-Host "[$shortLogName] " -NoNewline -ForegroundColor Cyan
                            Write-Host "ID:$($event.Id) " -NoNewline -ForegroundColor Yellow
                            
                            $shortMsg = if ($event.Message.Length -gt 60) {
                                $event.Message.Substring(0, 60).Replace("`r`n", " ").Replace("`n", " ") + "..."
                            } else {
                                $event.Message.Replace("`r`n", " ").Replace("`n", " ")
                            }
                            Write-Host $shortMsg -ForegroundColor Gray
                        }
                    }
                }
                catch {
                    # Ignore errors during watch
                }
            }
            
            $lastCheck = Get-Date
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        # Handle Ctrl+C gracefully
    }
    
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Watch complete. Events captured: $eventCount" -ForegroundColor Green
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
    
    return $eventCount
}

#endregion

#region Session Capture

$script:CaptureStartTime = $null

function Start-LDAPCapture {
    <#
    .SYNOPSIS
        Start a log capture session
    .DESCRIPTION
        Marks the current time as the start of a capture session.
        Use Stop-LDAPCapture to retrieve and optionally export events.
    .EXAMPLE
        Start-LDAPCapture
        # ... run some LDAP queries ...
        Stop-LDAPCapture -ExportPath ".\logs"
    #>
    [CmdletBinding()]
    param()
    
    $script:CaptureStartTime = Get-Date
    Write-Host "LDAP capture started at $($script:CaptureStartTime)" -ForegroundColor Cyan
    Write-Host "Run your LDAP queries, then call Stop-LDAPCapture" -ForegroundColor Gray
}

function Stop-LDAPCapture {
    <#
    .SYNOPSIS
        Stop capture session and retrieve events
    .PARAMETER ExportPath
        Optional: Export captured logs to this directory
    .EXAMPLE
        Stop-LDAPCapture
    .EXAMPLE
        Stop-LDAPCapture -ExportPath ".\evidence"
    #>
    [CmdletBinding()]
    param(
        [string]$ExportPath
    )
    
    if (-not $script:CaptureStartTime) {
        Write-Host "No capture in progress. Run Start-LDAPCapture first." -ForegroundColor Yellow
        return $null
    }
    
    $endTime = Get-Date
    Write-Host "Stopping capture. Retrieving events from $($script:CaptureStartTime) to $endTime" -ForegroundColor Cyan
    
    # Small delay to ensure logs are written
    Start-Sleep -Milliseconds 500
    
    $events = Get-LDAPLogs -StartTime $script:CaptureStartTime -EndTime $endTime -MaxEvents 10000
    
    if ($ExportPath) {
        Export-LDAPLogs -Path $ExportPath -StartTime $script:CaptureStartTime
    }
    
    $script:CaptureStartTime = $null
    return $events
}

#endregion

#region Main - Show usage when script is loaded

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  LDAP CLIENT LOG COLLECTOR (LDAPMon)" -ForegroundColor White
Write-Host "  Client-side LDAP log collection and obfuscation hunting" -ForegroundColor Gray
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""
Write-Host "Requires: " -NoNewline -ForegroundColor Gray
Write-Host "LDAPMon from https://github.com/jonny-jhnson/LDAPMon" -ForegroundColor Cyan
Write-Host ""
Write-Host "Setup:" -ForegroundColor Magenta
Write-Host "  Get-LDAPLogStatus                    " -NoNewline -ForegroundColor White
Write-Host "Check if LDAPMon is running" -ForegroundColor Gray
Write-Host ""
Write-Host "Obfuscation Hunting:" -ForegroundColor Yellow
Write-Host "  Search-LDAPLogs -ObfuscationType All " -NoNewline -ForegroundColor White
Write-Host "Hunt for ALL obfuscation patterns" -ForegroundColor Gray
Write-Host "  Search-LDAPLogs -ObfuscationType All -ExcludeProcess lsass" -ForegroundColor White
Write-Host "                                       " -NoNewline
Write-Host "Exclude normal Windows traffic" -ForegroundColor Gray
Write-Host "  Get-ClientObfuscationPatterns        " -NoNewline -ForegroundColor White
Write-Host "List available detection patterns" -ForegroundColor Gray
Write-Host ""
Write-Host "Log Retrieval:" -ForegroundColor Green
Write-Host "  Get-LDAPLogs [-MaxEvents 100]        " -NoNewline -ForegroundColor White
Write-Host "Retrieve recent LDAP events" -ForegroundColor Gray
Write-Host "  Watch-LDAPLogs [-DurationSeconds 60] " -NoNewline -ForegroundColor White
Write-Host "Real-time monitoring" -ForegroundColor Gray
Write-Host "  Export-LDAPLogs -Path '.\logs'       " -NoNewline -ForegroundColor White
Write-Host "Export to EVTX file" -ForegroundColor Gray
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  This script is for CLIENT-SIDE logs." -ForegroundColor Yellow
Write-Host "  For DC Event 1644 logs, use Get-DCLDAPLogs.ps1" -ForegroundColor Yellow
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

#endregion
