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
    Domain Controller LDAP Log Collector
    
.DESCRIPTION
    Collects and exports LDAP-related logs from Domain Controllers,
    focusing on Event ID 1644 (expensive/inefficient LDAP searches).
    
    Features:
    - Remote collection from DCs via WinRM or local execution
    - Real-time monitoring with Watch-Event1644
    - Filter by user, client IP, or LDAP filter patterns
    - Hunt for MaLDAPtive obfuscation patterns
    - Full raw message display option
    - EVTX export for offline analysis

.NOTES
    Author: MaLDAPtive Detection Project
    License: MIT
    
    Event 1644 Properties (by index):
    [0]  Starting Node (Base DN)
    [1]  Filter
    [2]  Returned Entries
    [3]  Visited Entries
    [4]  Client IP:Port
    [5]  Search Scope Name
    [6]  Attributes Requested
    [7]  Server Controls
    [8]  Indexes Used
    [9]  Pages Referenced
    [10] Pages Read
    [11] Pages Pre-read
    [12] Pages Dirtied
    [13] Search Time (ms)
    [14] Sort Time (ms)
    [15] User

.EXAMPLE
    . .\Get-DCLDAPLogs.ps1
    Get-Event1644 -User "*loki*" -ShowRaw
    Watch-Event1644 -DurationSeconds 120
    Search-Event1644 -ObfuscationType HexEncoding
#>

#Requires -Version 5.1

#region Configuration

$script:LDAPEventIds = @{
    1644 = "Expensive/Inefficient LDAP search"
    2886 = "LDAP signing not required"
    2887 = "LDAP signing statistics"
    2888 = "LDAP channel binding"
    2889 = "Unsigned LDAP bind"
    3040 = "LDAP over SSL/TLS"
}

# MaLDAPtive obfuscation detection patterns
# NOTE: Event 1644 logs the PROCESSED filter, not raw. Hex encoding gets decoded.
# These patterns detect structural obfuscation that survives normalization.
$script:ObfuscationPatterns = @{
    DoubleNegation = @{
        Description = "Double NOT operators - ( ! ( ! ... ) )"
        Pattern = '\(\s*!\s*\(\s*!'
    }
    DeMorganTransform = @{
        Description = "De Morgan transform - !( | or !( & with FALSE/negations"
        Pattern = '!\s*\(\s*\||\(\s*!\s*\(\s*FALSE\s*\)\s*\)'
    }
    ExcessiveWildcards = @{
        Description = "Multiple wildcards fragmenting values - *x*y*z*"
        Pattern = '\*[^)]*\*[^)]*\*'
    }
    ANRAttribute = @{
        Description = "Ambiguous Name Resolution - (anr=...)"
        Pattern = '\(anr\s*='
    }
    ApproximateMatch = @{
        Description = "Approximate/phonetic match - (~=)"
        Pattern = '~='
    }
    RangeOperators = @{
        Description = "Range operators instead of equality - (>=) or (<=)"
        Pattern = '(?<![><])>=|(?<![><])<='
    }
    ExtensibleMatchOID = @{
        Description = "Extensible match with bitwise OID rules"
        Pattern = ':\d+\.\d+\.\d+\.\d+\.\d+:'
    }
    BitwiseOperator = @{
        Description = "Bitwise AND/OR operators (| or &) in filter values"
        Pattern = '\([^=]+[|&]\d+\)'
    }
    ExcessiveSpacing = @{
        Description = "Unusual whitespace in filter structure"
        Pattern = '\(\s{2,}|\s{2,}\)|\s{2,}='
    }
    FalseCondition = @{
        Description = "FALSE literal in filter (unusual)"
        Pattern = '\(FALSE\)'
    }
    LargeNumericValue = @{
        Description = "Large numeric values (possible UAC flags)"
        Pattern = '=\d{6,}'
    }
    TimestampFilter = @{
        Description = "Timestamp-based filtering (whenCreated, whenChanged)"
        Pattern = '\(when(?:Created|Changed)[><=]'
    }
    ServicePrincipalName = @{
        Description = "SPN enumeration pattern"
        Pattern = '\(servicePrincipalName'
    }
    UserAccountControl = @{
        Description = "UAC flag queries"
        Pattern = '\(userAccountControl'
    }
    AdminCount = @{
        Description = "AdminCount enumeration (privileged accounts)"
        Pattern = '\(adminCount'
    }
}

#endregion

#region Helper Functions

function Get-TargetDC {
    param([string]$ComputerName)
    
    if ($ComputerName) { return $ComputerName }
    
    try {
        return (Get-ADDomainController -Discover -ErrorAction Stop).HostName
    } catch {
        return $env:COMPUTERNAME
    }
}

function Get-LoggingStatusQuiet {
    <#
    .SYNOPSIS
        Get Event 1644 logging status without output (internal helper)
    #>
    param([string]$ComputerName)
    
    $scriptBlock = {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
        $result = @{ 
            FieldEngineering = 0
            ExpensiveThreshold = 10000
            InefficientThreshold = 1000
            SearchTimeThreshold = 30000
            IsEnabled = $false 
        }
        
        try { 
            $val = (Get-ItemProperty -Path $regPath -Name "15 Field Engineering" -ErrorAction SilentlyContinue)."15 Field Engineering"
            if ($val) { $result.FieldEngineering = $val }
        } catch {}
        try { 
            $val = (Get-ItemProperty -Path $paramPath -Name "Expensive Search Results Threshold" -ErrorAction SilentlyContinue)."Expensive Search Results Threshold"
            if ($val) { $result.ExpensiveThreshold = $val }
        } catch {}
        try { 
            $val = (Get-ItemProperty -Path $paramPath -Name "Inefficient Search Results Threshold" -ErrorAction SilentlyContinue)."Inefficient Search Results Threshold"
            if ($val) { $result.InefficientThreshold = $val }
        } catch {}
        try { 
            $val = (Get-ItemProperty -Path $paramPath -Name "Search Time Threshold (msecs)" -ErrorAction SilentlyContinue)."Search Time Threshold (msecs)"
            if ($val) { $result.SearchTimeThreshold = $val }
        } catch {}
        
        $result.IsEnabled = ($result.FieldEngineering -ge 5)
        return $result
    }
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or -not $ComputerName) { 
            return (& $scriptBlock)
        } else { 
            return (Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop)
        }
    }
    catch {
        return @{ FieldEngineering = 0; ExpensiveThreshold = "?"; InefficientThreshold = "?"; SearchTimeThreshold = "?"; IsEnabled = $false }
    }
}

function Parse-Event1644 {
    <#
    .SYNOPSIS
        Parse Event 1644 properties into structured object
    #>
    param($Event)
    
    $props = $Event.Properties
    
    # Event 1644 property indices (verified from actual event):
    # [0] Starting Node (Base DN)
    # [1] Filter
    # [2] Visited Entries
    # [3] Returned Entries (from index) 
    # [4] Client IP:Port
    # [5] Search Scope
    # [6] Attributes requested
    # [7] Server Controls
    # [8] Indexes Used
    # [9] Pages Referenced
    # [10] Pages Read
    # [11] Pages Preread
    # [12] Pages Dirtied
    # [13] Search Time (ms)
    # [14] Sort Time (ms)
    # [15] Attributes in filter
    # [16] User (DOMAIN\user)
    
    $parsed = [PSCustomObject]@{
        TimeCreated     = $Event.TimeCreated
        EventId         = $Event.Id
        RecordId        = $Event.RecordId
        StartingNode    = if ($props.Count -gt 0) { $props[0].Value } else { $null }
        Filter          = if ($props.Count -gt 1) { $props[1].Value } else { $null }
        VisitedEntries  = if ($props.Count -gt 2) { $props[2].Value } else { $null }
        ReturnedEntries = if ($props.Count -gt 3) { $props[3].Value } else { $null }
        ClientIP        = if ($props.Count -gt 4) { $props[4].Value } else { $null }
        SearchScope     = if ($props.Count -gt 5) { $props[5].Value } else { $null }
        Attributes      = if ($props.Count -gt 6) { $props[6].Value } else { $null }
        ServerControls  = if ($props.Count -gt 7) { $props[7].Value } else { $null }
        IndexesUsed     = if ($props.Count -gt 8) { $props[8].Value } else { $null }
        SearchTimeMs    = if ($props.Count -gt 13) { $props[13].Value } else { $null }
        FilterAttribs   = if ($props.Count -gt 15) { $props[15].Value } else { $null }
        User            = if ($props.Count -gt 16) { $props[16].Value } else { $null }
        RawMessage      = $Event.Message
        RawEvent        = $Event
    }
    
    return $parsed
}

#endregion

#region Enable/Disable Event 1644 Logging

function Enable-Event1644Logging {
    <#
    .SYNOPSIS
        Enable Event ID 1644 logging on a Domain Controller
    .PARAMETER ComputerName
        Target Domain Controller (default: auto-detect)
    .PARAMETER ExpensiveThreshold
        Log searches returning more than this many results (default: 1)
    .PARAMETER InefficientThreshold
        Log searches visiting more than this many entries (default: 1)
    .PARAMETER SearchTimeThresholdMs
        Log searches taking longer than this in ms (default: 1)
    .EXAMPLE
        Enable-Event1644Logging -ComputerName "Earth-DC"
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int]$ExpensiveThreshold = 1,
        [int]$InefficientThreshold = 1,
        [int]$SearchTimeThresholdMs = 1
    )
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  ENABLING EVENT 1644 LOGGING" -ForegroundColor White
    Write-Host "  Target DC: $targetDC" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    $scriptBlock = {
        param($ExpensiveThreshold, $InefficientThreshold, $SearchTimeThresholdMs)
        
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
        try {
            Set-ItemProperty -Path $regPath -Name "15 Field Engineering" -Value 5 -Type DWord -Force
            
            if (-not (Test-Path $paramPath)) {
                New-Item -Path $paramPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $paramPath -Name "Expensive Search Results Threshold" -Value $ExpensiveThreshold -Type DWord -Force
            Set-ItemProperty -Path $paramPath -Name "Inefficient Search Results Threshold" -Value $InefficientThreshold -Type DWord -Force
            Set-ItemProperty -Path $paramPath -Name "Search Time Threshold (msecs)" -Value $SearchTimeThresholdMs -Type DWord -Force
            
            return @{
                Success = $true
                FieldEngineering = (Get-ItemProperty -Path $regPath -Name "15 Field Engineering" -ErrorAction SilentlyContinue)."15 Field Engineering"
                ExpensiveThreshold = (Get-ItemProperty -Path $paramPath -Name "Expensive Search Results Threshold" -ErrorAction SilentlyContinue)."Expensive Search Results Threshold"
                InefficientThreshold = (Get-ItemProperty -Path $paramPath -Name "Inefficient Search Results Threshold" -ErrorAction SilentlyContinue)."Inefficient Search Results Threshold"
                SearchTimeThreshold = (Get-ItemProperty -Path $paramPath -Name "Search Time Threshold (msecs)" -ErrorAction SilentlyContinue)."Search Time Threshold (msecs)"
            }
        }
        catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    
    try {
        if ($targetDC -eq $env:COMPUTERNAME) {
            $result = & $scriptBlock $ExpensiveThreshold $InefficientThreshold $SearchTimeThresholdMs
        } else {
            $result = Invoke-Command -ComputerName $targetDC -ScriptBlock $scriptBlock -ArgumentList $ExpensiveThreshold, $InefficientThreshold, $SearchTimeThresholdMs
        }
        
        if ($result.Success) {
            Write-Host "SUCCESS: Event 1644 logging configured" -ForegroundColor Green
            Write-Host ""
            Write-Host "Settings:" -ForegroundColor Yellow
            Write-Host "  15 Field Engineering:           $($result.FieldEngineering)" -ForegroundColor White
            Write-Host "  Expensive Search Threshold:     $($result.ExpensiveThreshold) results" -ForegroundColor White
            Write-Host "  Inefficient Search Threshold:   $($result.InefficientThreshold) entries" -ForegroundColor White
            Write-Host "  Search Time Threshold:          $($result.SearchTimeThreshold) ms" -ForegroundColor White
            Write-Host ""
            Write-Host "Changes take effect immediately" -ForegroundColor Cyan
        } else {
            Write-Host "ERROR: $($result.Error)" -ForegroundColor Red
        }
        return $result
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Requires Administrator on DC and WinRM for remote" -ForegroundColor Yellow
        return $null
    }
}

function Disable-Event1644Logging {
    <#
    .SYNOPSIS
        Disable Event ID 1644 logging on a Domain Controller
    #>
    [CmdletBinding()]
    param([string]$ComputerName)
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    $scriptBlock = {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering" -Value 0 -Type DWord -Force
        return $true
    }
    
    try {
        if ($targetDC -eq $env:COMPUTERNAME) { & $scriptBlock }
        else { Invoke-Command -ComputerName $targetDC -ScriptBlock $scriptBlock }
        Write-Host "Event 1644 logging disabled on $targetDC" -ForegroundColor Yellow
        return $true
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-Event1644Status {
    <#
    .SYNOPSIS
        Check Event 1644 logging configuration
    #>
    [CmdletBinding()]
    param([string]$ComputerName)
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  EVENT 1644 LOGGING STATUS" -ForegroundColor White
    Write-Host "  Target DC: $targetDC" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    $scriptBlock = {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        
        $result = @{ FieldEngineering = $null; ExpensiveThreshold = $null; InefficientThreshold = $null; SearchTimeThreshold = $null; IsEnabled = $false }
        
        try { $result.FieldEngineering = (Get-ItemProperty -Path $regPath -Name "15 Field Engineering" -ErrorAction SilentlyContinue)."15 Field Engineering" } catch {}
        try { $result.ExpensiveThreshold = (Get-ItemProperty -Path $paramPath -Name "Expensive Search Results Threshold" -ErrorAction SilentlyContinue)."Expensive Search Results Threshold" } catch {}
        try { $result.InefficientThreshold = (Get-ItemProperty -Path $paramPath -Name "Inefficient Search Results Threshold" -ErrorAction SilentlyContinue)."Inefficient Search Results Threshold" } catch {}
        try { $result.SearchTimeThreshold = (Get-ItemProperty -Path $paramPath -Name "Search Time Threshold (msecs)" -ErrorAction SilentlyContinue)."Search Time Threshold (msecs)" } catch {}
        
        $result.IsEnabled = ($result.FieldEngineering -ge 5)
        return $result
    }
    
    try {
        $result = if ($targetDC -eq $env:COMPUTERNAME) { & $scriptBlock } else { Invoke-Command -ComputerName $targetDC -ScriptBlock $scriptBlock }
        
        $statusColor = if ($result.IsEnabled) { "Green" } else { "Yellow" }
        $statusText = if ($result.IsEnabled) { "ENABLED" } else { "DISABLED" }
        
        Write-Host "Status: " -NoNewline -ForegroundColor Gray
        Write-Host $statusText -ForegroundColor $statusColor
        Write-Host ""
        Write-Host "Registry Settings:" -ForegroundColor Yellow
        Write-Host "  15 Field Engineering:         $(if($null -eq $result.FieldEngineering){'(not set)'}else{$result.FieldEngineering})" -ForegroundColor White
        Write-Host "  Expensive Search Threshold:   $(if($null -eq $result.ExpensiveThreshold){'(not set - default 10000)'}else{$result.ExpensiveThreshold})" -ForegroundColor White
        Write-Host "  Inefficient Search Threshold: $(if($null -eq $result.InefficientThreshold){'(not set - default 1000)'}else{$result.InefficientThreshold})" -ForegroundColor White
        Write-Host "  Search Time Threshold:        $(if($null -eq $result.SearchTimeThreshold){'(not set - default 30000 ms)'}else{"$($result.SearchTimeThreshold) ms"})" -ForegroundColor White
        Write-Host ""
        
        return $result
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

#endregion

#region Log Retrieval Functions

function Get-Event1644 {
    <#
    .SYNOPSIS
        Retrieve Event ID 1644 entries from a Domain Controller
    .PARAMETER ComputerName
        Target Domain Controller (default: auto-detect)
    .PARAMETER MaxEvents
        Maximum events to retrieve (default: 50)
    .PARAMETER StartTime
        Only get events after this time (default: 1 hour ago)
    .PARAMETER User
        Filter by user account (supports wildcards)
    .PARAMETER ShowRaw
        Display full raw event message
    .EXAMPLE
        Get-Event1644 -MaxEvents 20
    .EXAMPLE
        Get-Event1644 -User "*loki*" -ShowRaw
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int]$MaxEvents = 50,
        [DateTime]$StartTime = (Get-Date).AddHours(-1),
        [string]$User,
        [switch]$ShowRaw
    )
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    # Get logging status silently
    $status = Get-LoggingStatusQuiet -ComputerName $targetDC
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  EVENT 1644 - EXPENSIVE LDAP SEARCHES" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  DC: $targetDC" -ForegroundColor Gray
    
    # Show logging status inline
    $statusColor = if ($status.IsEnabled) { "Green" } else { "Red" }
    $statusText = if ($status.IsEnabled) { "ON (Level $($status.FieldEngineering))" } else { "OFF" }
    Write-Host "  Logging: " -NoNewline -ForegroundColor Gray
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    if ($status.IsEnabled) {
        Write-Host " | Thresholds: " -NoNewline -ForegroundColor Gray
        Write-Host "Exp=$($status.ExpensiveThreshold) Ineff=$($status.InefficientThreshold) Time=$($status.SearchTimeThreshold)ms" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
    
    Write-Host "  Time Range: $($StartTime.ToString("yyyy-MM-dd HH:mm:ss")) to $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -ForegroundColor Gray
    if ($User) { Write-Host "  User Filter: $User" -ForegroundColor Yellow }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $filterHash = @{ LogName = 'Directory Service'; Id = 1644; StartTime = $StartTime }
        $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents ($MaxEvents * 2) -ComputerName $targetDC -ErrorAction Stop
        
        $parsedEvents = @()
        
        foreach ($event in $events) {
            $parsed = Parse-Event1644 -Event $event
            
            # Apply user filter
            if ($User -and $parsed.User -notlike $User) { continue }
            
            $parsedEvents += $parsed
            
            if ($parsedEvents.Count -ge $MaxEvents) { break }
        }
        
        Write-Host "Found $($parsedEvents.Count) events" -ForegroundColor Green
        Write-Host ""
        
        foreach ($parsed in $parsedEvents) {
            Write-Host ("─" * 80) -ForegroundColor DarkGray
            Write-Host "  Time:        " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff") -ForegroundColor White
            Write-Host "  User:        " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.User -ForegroundColor Cyan
            Write-Host "  Client:      " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.ClientIP -ForegroundColor White
            Write-Host "  Base DN:     " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.StartingNode -ForegroundColor White
            Write-Host "  Scope:       " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.SearchScope -ForegroundColor White
            Write-Host "  Filter:      " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.Filter -ForegroundColor Yellow
            Write-Host "  Returned:    " -NoNewline -ForegroundColor Gray
            Write-Host "$($parsed.ReturnedEntries) entries" -ForegroundColor White
            Write-Host "  Visited:     " -NoNewline -ForegroundColor Gray
            Write-Host "$($parsed.VisitedEntries) entries" -ForegroundColor White
            Write-Host "  Search Time: " -NoNewline -ForegroundColor Gray
            Write-Host "$($parsed.SearchTimeMs) ms" -ForegroundColor White
            Write-Host "  Indexes:     " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.IndexesUsed -ForegroundColor DarkGray
            
            if ($ShowRaw) {
                Write-Host ""
                Write-Host "  ┌─ RAW MESSAGE " -NoNewline -ForegroundColor DarkMagenta
                Write-Host ("─" * 62) -ForegroundColor DarkMagenta
                # Indent raw message
                $parsed.RawMessage -split "`n" | ForEach-Object {
                    Write-Host "  │ $_" -ForegroundColor DarkGray
                }
                Write-Host "  └" -NoNewline -ForegroundColor DarkMagenta
                Write-Host ("─" * 76) -ForegroundColor DarkMagenta
            }
            Write-Host ""
        }
        
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Total: $($parsedEvents.Count) events" -ForegroundColor Gray
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return $parsedEvents
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Host "No Event 1644 entries found" -ForegroundColor Yellow
            Write-Host "Tips: Check logging with Get-Event1644Status" -ForegroundColor Gray
        } else {
            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
        return @()
    }
}

function Search-Event1644 {
    <#
    .SYNOPSIS
        Hunt through Event 1644 logs for obfuscation patterns
    .PARAMETER ComputerName
        Target Domain Controller
    .PARAMETER ObfuscationType
        Predefined obfuscation pattern to search for
    .PARAMETER FilterPattern
        Custom regex pattern to search in LDAP filters
    .PARAMETER User
        Filter by user account
    .PARAMETER ClientIP
        Filter by client IP address
    .PARAMETER StartTime
        Search start time (default: 24 hours ago)
    .PARAMETER MaxEvents
        Maximum events to search (default: 1000)
    .PARAMETER ShowRaw
        Show full raw message for matches
    .EXAMPLE
        Search-Event1644 -ObfuscationType HexEncoding
    .EXAMPLE
        Search-Event1644 -User "*loki*" -ObfuscationType All
    .EXAMPLE
        Search-Event1644 -FilterPattern "admin|krbtgt" -ShowRaw
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        
        [ValidateSet("DoubleNegation", "DeMorganTransform", "ExcessiveWildcards", "ANRAttribute", 
                     "ApproximateMatch", "RangeOperators", "ExtensibleMatchOID", "BitwiseOperator",
                     "ExcessiveSpacing", "FalseCondition", "LargeNumericValue", "TimestampFilter",
                     "ServicePrincipalName", "UserAccountControl", "AdminCount", "All")]
        [string]$ObfuscationType,
        
        [string]$FilterPattern,
        [string]$User,
        [string]$ClientIP,
        [DateTime]$StartTime = (Get-Date).AddDays(-1),
        [int]$MaxEvents = 1000,
        [switch]$ShowRaw
    )
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    # Get logging status
    $status = Get-LoggingStatusQuiet -ComputerName $targetDC
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  EVENT 1644 OBFUSCATION HUNT" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  DC: $targetDC" -ForegroundColor Gray
    
    # Show logging status
    $statusColor = if ($status.IsEnabled) { "Green" } else { "Red" }
    $statusText = if ($status.IsEnabled) { "ON (Level $($status.FieldEngineering))" } else { "OFF" }
    Write-Host "  Logging: " -NoNewline -ForegroundColor Gray
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    if ($status.IsEnabled) {
        Write-Host " | Thresholds: " -NoNewline -ForegroundColor Gray
        Write-Host "Exp=$($status.ExpensiveThreshold) Ineff=$($status.InefficientThreshold) Time=$($status.SearchTimeThreshold)ms" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
    
    Write-Host "  Time Range: >= $($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor Gray
    if ($ObfuscationType) { Write-Host "  Obfuscation: $ObfuscationType" -ForegroundColor Yellow }
    if ($FilterPattern) { Write-Host "  Custom Pattern: $FilterPattern" -ForegroundColor Yellow }
    if ($User) { Write-Host "  User Filter: $User" -ForegroundColor Yellow }
    if ($ClientIP) { Write-Host "  Client IP: $ClientIP" -ForegroundColor Yellow }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    # Build pattern list
    $patternsToCheck = @{}
    if ($ObfuscationType -eq "All") {
        $patternsToCheck = $script:ObfuscationPatterns.Clone()
    } elseif ($ObfuscationType -and $script:ObfuscationPatterns.ContainsKey($ObfuscationType)) {
        $patternsToCheck[$ObfuscationType] = $script:ObfuscationPatterns[$ObfuscationType]
    }
    
    if ($FilterPattern) {
        $patternsToCheck["CustomPattern"] = @{ Description = "Custom regex pattern"; Pattern = $FilterPattern }
    }
    
    if ($patternsToCheck.Count -eq 0) {
        Write-Host "ERROR: Specify -ObfuscationType or -FilterPattern" -ForegroundColor Red
        return @()
    }
    
    # Get events
    try {
        $filterHash = @{ LogName = 'Directory Service'; Id = 1644; StartTime = $StartTime }
        $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ComputerName $targetDC -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Host "No Event 1644 entries found in time range" -ForegroundColor Yellow
        } else {
            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
        return @()
    }
    
    Write-Host "Searching $($events.Count) events..." -ForegroundColor Cyan
    Write-Host ""
    
    $matchedEvents = @()
    $matchCounts = @{}
    foreach ($key in $patternsToCheck.Keys) { $matchCounts[$key] = 0 }
    
    foreach ($event in $events) {
        $parsed = Parse-Event1644 -Event $event
        
        # Apply pre-filters
        if ($User -and $parsed.User -notlike $User) { continue }
        if ($ClientIP -and $parsed.ClientIP -notlike "*$ClientIP*") { continue }
        
        # Check patterns
        $matchedPatterns = @()
        foreach ($patternName in $patternsToCheck.Keys) {
            $patternInfo = $patternsToCheck[$patternName]
            $isMatch = $parsed.Filter -match $patternInfo.Pattern
            if ($isMatch) {
                $matchedPatterns += $patternName
                $matchCounts[$patternName]++
            }
        }
        
        if ($matchedPatterns.Count -gt 0) {
            $parsed | Add-Member -NotePropertyName "MatchedPatterns" -NotePropertyValue $matchedPatterns -Force
            $matchedEvents += $parsed
            
            Write-Host ("─" * 80) -ForegroundColor Green
            Write-Host "  MATCH: " -NoNewline -ForegroundColor Green
            Write-Host ($matchedPatterns -join ", ") -ForegroundColor Yellow
            Write-Host "  Time:   $($parsed.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor White
            Write-Host "  User:   $($parsed.User)" -ForegroundColor Cyan
            Write-Host "  Client: $($parsed.ClientIP)" -ForegroundColor Gray
            Write-Host "  Filter: " -NoNewline -ForegroundColor Gray
            Write-Host $parsed.Filter -ForegroundColor Yellow
            
            if ($ShowRaw) {
                Write-Host ""
                Write-Host "  --- RAW MESSAGE ---" -ForegroundColor DarkMagenta
                Write-Host $parsed.RawMessage -ForegroundColor DarkGray
                Write-Host "  --- END RAW ---" -ForegroundColor DarkMagenta
            }
            Write-Host ""
        }
    }
    
    # Summary
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor White
    Write-Host "  Total events searched: $($events.Count)" -ForegroundColor Gray
    Write-Host "  Matches found: $($matchedEvents.Count)" -ForegroundColor $(if($matchedEvents.Count -gt 0){"Green"}else{"Yellow"})
    Write-Host ""
    if ($matchedEvents.Count -gt 0) {
        Write-Host "  Matches by pattern:" -ForegroundColor Yellow
        foreach ($patternName in $matchCounts.Keys | Sort-Object) {
            if ($matchCounts[$patternName] -gt 0) {
                $desc = $patternsToCheck[$patternName].Description
                Write-Host "    $patternName : $($matchCounts[$patternName]) - $desc" -ForegroundColor White
            }
        }
    }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    # Clear the automatic $Matches variable to prevent output leak  
    $null = "" -match ""
}

function Get-ObfuscationPatterns {
    <#
    .SYNOPSIS
        List available obfuscation detection patterns
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  AVAILABLE OBFUSCATION PATTERNS" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($name in $script:ObfuscationPatterns.Keys | Sort-Object) {
        $info = $script:ObfuscationPatterns[$name]
        Write-Host "  $name" -ForegroundColor Yellow
        Write-Host "    $($info.Description)" -ForegroundColor Gray
        Write-Host "    Pattern: $($info.Pattern)" -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Usage: Search-Event1644 -ObfuscationType <name>" -ForegroundColor Gray
    Write-Host "         Search-Event1644 -ObfuscationType All" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
}

#endregion

#region Export Functions

function Export-DCLDAPLogs {
    <#
    .SYNOPSIS
        Export Directory Service logs to EVTX file
    .PARAMETER Path
        Output directory
    .PARAMETER ComputerName
        Target Domain Controller
    .PARAMETER StartTime
        Only export events after this time
    .PARAMETER EventId
        Event ID(s) to export (default: 1644)
    .EXAMPLE
        Export-DCLDAPLogs -Path ".\logs"
    #>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [string]$ComputerName,
        [DateTime]$StartTime = (Get-Date).AddHours(-1),
        [int[]]$EventId = @(1644),
        [string]$Prefix = "DC_Event1644"
    )
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $Path "${Prefix}_${timestamp}.evtx"
    
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  EXPORTING EVENT 1644 LOGS" -ForegroundColor White
    Write-Host "  Target DC: $targetDC" -ForegroundColor Gray
    Write-Host "  Output: $outputFile" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $startTimeStr = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
        $idFilter = ($EventId | ForEach-Object { "EventID=$_" }) -join " or "
        $query = "*[System[TimeCreated[@SystemTime >= '$startTimeStr'] and ($idFilter)]]"
        
        if ($targetDC -eq $env:COMPUTERNAME) {
            $result = & wevtutil epl "Directory Service" $outputFile /q:$query 2>&1
        } else {
            $result = & wevtutil epl "Directory Service" $outputFile /q:$query /r:$targetDC 2>&1
        }
        
        if ($LASTEXITCODE -eq 0 -and (Test-Path $outputFile)) {
            $fileSize = (Get-Item $outputFile).Length
            if ($fileSize -gt 69632) {
                $eventCount = (Get-WinEvent -Path $outputFile -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-Host "SUCCESS: $outputFile" -ForegroundColor Green
                Write-Host "Size: $([math]::Round($fileSize/1KB, 2)) KB | Events: $eventCount" -ForegroundColor Gray
                return [PSCustomObject]@{ FilePath = $outputFile; Size = $fileSize; Events = $eventCount }
            } else {
                Write-Host "No events to export" -ForegroundColor Yellow
                Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "Export failed: $result" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    return $null
}

#endregion

#region Real-Time Monitoring

function Watch-Event1644 {
    <#
    .SYNOPSIS
        Watch for Event 1644 entries in real-time
    .PARAMETER ComputerName
        Target Domain Controller
    .PARAMETER DurationSeconds
        How long to watch (default: 60, 0 = indefinite)
    .PARAMETER User
        Only show events for this user
    .PARAMETER ShowRaw
        Display full raw message
    .EXAMPLE
        Watch-Event1644 -DurationSeconds 120
    .EXAMPLE
        Watch-Event1644 -User "*loki*" -DurationSeconds 0
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int]$DurationSeconds = 60,
        [string]$User,
        [switch]$ShowRaw
    )
    
    $targetDC = Get-TargetDC -ComputerName $ComputerName
    $isLocal = ($targetDC -eq $env:COMPUTERNAME) -or (-not $ComputerName)
    
    # Get logging status
    $status = Get-LoggingStatusQuiet -ComputerName $targetDC
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  EVENT 1644 REAL-TIME MONITOR" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  DC: $targetDC $(if($isLocal){'(local)'}else{'(remote)'})" -ForegroundColor Gray
    
    # Show logging status
    $statusColor = if ($status.IsEnabled) { "Green" } else { "Red" }
    $statusText = if ($status.IsEnabled) { "ON (Level $($status.FieldEngineering))" } else { "OFF" }
    Write-Host "  Logging: " -NoNewline -ForegroundColor Gray
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    if ($status.IsEnabled) {
        Write-Host " | Thresholds: " -NoNewline -ForegroundColor Gray
        Write-Host "Exp=$($status.ExpensiveThreshold) Ineff=$($status.InefficientThreshold) Time=$($status.SearchTimeThreshold)ms" -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "  WARNING: Event 1644 logging is DISABLED - no events will appear!" -ForegroundColor Red
    }
    
    $durationText = if ($DurationSeconds -eq 0) { "indefinite (Ctrl+C to stop)" } else { "$DurationSeconds seconds" }
    Write-Host "  Duration: $durationText" -ForegroundColor Gray
    if ($User) { Write-Host "  User Filter: $User" -ForegroundColor Yellow }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Watching for events... (Ctrl+C to stop)" -ForegroundColor Cyan
    Write-Host ""
    
    $watchStart = Get-Date
    $endTime = if ($DurationSeconds -eq 0) { [DateTime]::MaxValue } else { $watchStart.AddSeconds($DurationSeconds) }
    $lastCheck = $watchStart.AddSeconds(-1)  # Start 1 second in the past to catch immediate events
    $eventCount = 0
    $seenRecordIds = @{}
    $pollInterval = 1000  # 1 second
    
    try {
        while ((Get-Date) -lt $endTime) {
            $checkTime = Get-Date
            
            try {
                # Build filter - use StartTime slightly before lastCheck to ensure we don't miss events
                $filterHash = @{
                    LogName = 'Directory Service'
                    Id = 1644
                    StartTime = $lastCheck
                }
                
                # Get events - handle local vs remote
                if ($isLocal) {
                    $newEvents = @(Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ErrorAction SilentlyContinue)
                } else {
                    $newEvents = @(Get-WinEvent -FilterHashtable $filterHash -MaxEvents 100 -ComputerName $targetDC -ErrorAction SilentlyContinue)
                }
                
                # Process events in chronological order (oldest first)
                $newEvents = $newEvents | Sort-Object TimeCreated
                
                foreach ($event in $newEvents) {
                    # Skip duplicates using RecordId
                    if ($seenRecordIds.ContainsKey($event.RecordId)) { continue }
                    $seenRecordIds[$event.RecordId] = $true
                    
                    $parsed = Parse-Event1644 -Event $event
                    
                    # Apply user filter
                    if ($User -and $parsed.User -notlike $User) { continue }
                    
                    $eventCount++
                    
                    Write-Host ("─" * 80) -ForegroundColor Green
                    Write-Host "  [$($parsed.TimeCreated.ToString("HH:mm:ss.fff"))] " -NoNewline -ForegroundColor White
                    Write-Host "EVENT 1644" -ForegroundColor Yellow
                    Write-Host "  User:        " -NoNewline -ForegroundColor Gray
                    Write-Host $parsed.User -ForegroundColor Cyan
                    Write-Host "  Client:      " -NoNewline -ForegroundColor Gray
                    Write-Host $parsed.ClientIP -ForegroundColor White
                    Write-Host "  Base DN:     " -NoNewline -ForegroundColor Gray
                    Write-Host $parsed.StartingNode -ForegroundColor White
                    Write-Host "  Filter:      " -NoNewline -ForegroundColor Gray
                    Write-Host $parsed.Filter -ForegroundColor Yellow
                    Write-Host "  Results:     " -NoNewline -ForegroundColor Gray
                    Write-Host "$($parsed.ReturnedEntries) returned, $($parsed.VisitedEntries) visited, $($parsed.SearchTimeMs) ms" -ForegroundColor White
                    
                    if ($ShowRaw) {
                        Write-Host ""
                        Write-Host "  ┌─ RAW " -NoNewline -ForegroundColor DarkMagenta
                        Write-Host ("─" * 70) -ForegroundColor DarkMagenta
                        $parsed.RawMessage -split "`n" | ForEach-Object {
                            Write-Host "  │ $_" -ForegroundColor DarkGray
                        }
                        Write-Host "  └" -NoNewline -ForegroundColor DarkMagenta
                        Write-Host ("─" * 76) -ForegroundColor DarkMagenta
                    }
                    Write-Host ""
                }
            }
            catch {
                # Only show error if it's not "no events found"
                if ($_.Exception.Message -notmatch "No events were found") {
                    Write-Host "  [Poll error: $($_.Exception.Message)]" -ForegroundColor DarkRed
                }
            }
            
            # Update last check time
            $lastCheck = $checkTime
            
            # Show a dot every 10 seconds to indicate we're still watching
            $elapsed = ((Get-Date) - $watchStart).TotalSeconds
            if ([int]$elapsed % 10 -eq 0 -and [int]$elapsed -gt 0) {
                $remaining = if ($DurationSeconds -eq 0) { "∞" } else { "$([int]($DurationSeconds - $elapsed))s" }
                Write-Host "`r  [Watching... $([int]$elapsed)s elapsed, $remaining remaining, $eventCount events]    " -NoNewline -ForegroundColor DarkGray
            }
            
            Start-Sleep -Milliseconds $pollInterval
        }
    }
    catch {
        # Handle Ctrl+C gracefully
        Write-Host "" # New line after any partial output
    }
    finally {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  Monitoring stopped after $([int]((Get-Date) - $watchStart).TotalSeconds) seconds" -ForegroundColor Gray
        Write-Host "  Events captured: $eventCount" -ForegroundColor Green
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
    
    return $eventCount
}

#endregion

#region Main

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  DC LDAP LOG COLLECTOR" -ForegroundColor White
Write-Host "  Domain Controller Event 1644 Collection & Hunting" -ForegroundColor Gray
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""
Write-Host "Setup:" -ForegroundColor Magenta
Write-Host "  Get-Event1644Status [-ComputerName 'DC']" -ForegroundColor White
Write-Host "  Enable-Event1644Logging [-ComputerName 'DC']" -ForegroundColor White
Write-Host "  Disable-Event1644Logging [-ComputerName 'DC']" -ForegroundColor White
Write-Host ""
Write-Host "Retrieval:" -ForegroundColor Yellow
Write-Host "  Get-Event1644 [-User '*loki*'] [-ShowRaw] [-MaxEvents 50]" -ForegroundColor White
Write-Host "  Export-DCLDAPLogs -Path '.\logs'" -ForegroundColor White
Write-Host ""
Write-Host "Obfuscation Hunting:" -ForegroundColor Red
Write-Host "  Get-ObfuscationPatterns                           # List patterns" -ForegroundColor White
Write-Host "  Search-Event1644 -ObfuscationType HexEncoding     # Single pattern" -ForegroundColor White
Write-Host "  Search-Event1644 -ObfuscationType All             # All patterns" -ForegroundColor White
Write-Host "  Search-Event1644 -User '*loki*' -ObfuscationType All -ShowRaw" -ForegroundColor White
Write-Host "  Search-Event1644 -FilterPattern 'admin|krbtgt'    # Custom regex" -ForegroundColor White
Write-Host ""
Write-Host "Real-Time:" -ForegroundColor Green
Write-Host "  Watch-Event1644 [-DurationSeconds 120] [-User '*loki*'] [-ShowRaw]" -ForegroundColor White
Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  For CLIENT logs, use Get-LDAPClientLogs.ps1" -ForegroundColor Gray
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""

#endregion
