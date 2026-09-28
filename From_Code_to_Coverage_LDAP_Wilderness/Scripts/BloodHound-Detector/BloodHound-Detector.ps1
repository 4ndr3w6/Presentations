<#
.SYNOPSIS
    BloodHound Detector v2.8.0 - All-In-One LDAP Reconnaissance Detection

.DESCRIPTION
    Unified script for detecting BloodHound and other LDAP reconnaissance tools
    through statistical analysis of Event ID 1644 (LDAP Search Statistics).
    
    Features:
    - Optional baseline (can work without it)
    - Flexible time increments (minutes, hours, days)
    - Real-time monitoring with simple or statistical detection
    - Historical analysis
    - Enhanced HTML reports with Chart.js visualizations
    - Alert analysis and reporting (HTML, CSV)
    - Improved detection for modern SharpHound (0% efficiency detection)
    - Dual-threshold alerting: Log all alerts >= 0.5, display only CRITICAL >= 0.7
    - Pattern-based detection for object enumeration, ADCS, SDFlags queries
    - Universal pause after all menu operations for better UX
    
    Detection Matrix:
    ┌─────────────────────────────────────────────────────────────┐
    │ SharpHound    │ ✓ │ SDFlags, Efficiency, Volume, Patterns  │
    │ BloodHound.py │ ✓ │ Patterns, Ancestors_index, objectClass │
    │ SOAPHound     │ ✓ │ !(FALSE) pattern, Zero efficiency      │
    │ ADExplorer    │ ✓ │ objectClass=*, High volume queries     │
    │ Custom Tools  │ ✓ │ Behavioral anomalies, Statistics       │
    └─────────────────────────────────────────────────────────────┘
    
.NOTES
    Author: Andrew Schwartz
    Version: 2.8.0
    Date: June 2026
    Requires: PowerShell 5.1+, Domain Controller access
    License: MIT
    
.EXAMPLE
    .\BloodHound-Detector.ps1
    Launches interactive menu
    
.LINK
    https://github.com/4ndr3w6/Presentations/tree/main/From_Code_to_Coverage_LDAP_Wilderness/Scripts/BloodHound-Detector
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

#region Configuration

$script:Config = @{
    Version = "2.8.0"
    BaselineFile = ".\ldap_baseline.json"
    AlertLogFile = "C:\Windows\debug\bloodhound_alerts.jsonl"
    EventLog = "Directory Service"
    EventID = 1644
    
    # Detection Thresholds
    Thresholds = @{
        # Simple mode (no baseline)
        SimpleEfficiencyCritical = 5.0       # < 5% is very suspicious
        SimpleEfficiencyWarning = 10.0       # < 10% is suspicious
        SimpleVolumeThreshold = 10           # Queries in time window
        
        # Statistical mode (with baseline)
        EfficiencyCritical = 5.0             # < 5% is suspicious
        EfficiencyWarning = 15.0             # < 15% is concerning
        StandardDeviations = 3.0             # Sigma threshold for volume anomaly
        
        # Pages per object ratios
        HighPagesPerObject = 10.0            # High page access
        CriticalPagesPerObject = 50.0        # Excessive page access
    }
    
    # Alert severity scoring
    AlertLevels = @{
        Critical = 0.7    # Display threshold (shown on screen)
        High = 0.5        # Log threshold (silent logging)
        Medium = 0.3
        Low = 0.1
    }
    
    # Dual-threshold alerting
    AlertLogThreshold = 0.5      # Log everything >= 0.5
    AlertDisplayThreshold = 0.7  # Display only CRITICAL >= 0.7
    
    # Pattern detection weights
    Weights = @{
        Efficiency = 0.3
        Volume = 0.25
        Pages = 0.20
        Index = 0.15
        Pattern = 0.10
    }
}

#endregion

#region Helper Functions

function Write-ColoredHeader {
    param(
        [string]$Text,
        [string]$Color = "Cyan"
    )
    
    $border = "═" * ($Text.Length + 4)
    Write-Host ""
    Write-Host "    ╔$border╗" -ForegroundColor $Color
    Write-Host "    ║  $Text  ║" -ForegroundColor $Color
    Write-Host "    ╚$border╝" -ForegroundColor $Color
    Write-Host ""
}

function Pause-ForUser {
    <#
    .SYNOPSIS
        Universal pause function used after all menu operations
    .DESCRIPTION
        Provides consistent user experience by pausing before returning to menu
    #>
    Write-Host ""
    Write-Host "Press Enter to return to menu..." -ForegroundColor Gray
    Read-Host
}
function Write-DFIRLog {
    param(
        [hashtable]$EventData,
        [hashtable]$DetectionData
    )
    
    try {
        $dfirEntry = [ordered]@{
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            EventID = 1644
            Severity = if ($DetectionData.Score -ge 0.8) { "CRITICAL" } 
                      elseif ($DetectionData.Score -ge 0.6) { "HIGH" }
                      elseif ($DetectionData.Score -ge 0.4) { "MEDIUM" }
                      else { "LOW" }
            UserContext = "$env:USERDOMAIN\$env:USERNAME"
            EventData = $EventData
            Detection = $DetectionData
            Context = @{
                AlertThreshold = $script:Config.CompositeAlertThreshold
                DisplayThreshold = $script:Config.CompositeDisplayThreshold
            }
        }
        
        $jsonLine = $dfirEntry | ConvertTo-Json -Compress -Depth 10
        Add-Content -Path $script:Config.DFIRLogFile -Value $jsonLine -ErrorAction SilentlyContinue
    } catch {
        # Silent failure
    }
}


function Get-DiagnosticLevel {
    <#
    .SYNOPSIS
        Check NTDS Diagnostic Level for Event ID 1644
    #>
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $value = Get-ItemProperty -Path $regPath -Name "15 Field Engineering" -ErrorAction Stop
        return $value."15 Field Engineering"
    }
    catch {
        return 0
    }
}

function Test-Baseline {
    <#
    .SYNOPSIS
        Check if baseline exists and is valid
    #>
    if (-not (Test-Path $script:Config.BaselineFile)) {
        return $false
    }
    
    try {
        $baseline = Get-Content $script:Config.BaselineFile | ConvertFrom-Json
        return ($null -ne $baseline.Mean -and $null -ne $baseline.StdDev)
    }
    catch {
        return $false
    }
}

#endregion

function Parse-Event1644 {
    <#
    .SYNOPSIS
        Parse Event 1644 for your DC's specific field order
    .DESCRIPTION
        Your DC format:
        [0] = Search Base (DN)
        [1] = Filter  
        [4] = Client IP (IPv4 or IPv6)
        [5] = Scope
        [6] = Attributes
        [7] = Server Controls
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Event
    )
    
    try {
        $props = $Event.Properties
        
        if ($props.Count -lt 7) {
            return $null
        }
        
        $searchBase = $props[0].Value
        $filter = $props[1].Value
        $clientIPRaw = $props[4].Value
        $scope = if ($props.Count -gt 5) { $props[5].Value } else { "" }
        $attributes = if ($props.Count -gt 6) { $props[6].Value } else { "" }
        $serverControls = if ($props.Count -gt 7) { $props[7].Value } else { "" }
        
        # Extract Client IP from field 4
        $clientIP = $null
        
        # IPv6 with brackets: [::1]:61751
        if ($clientIPRaw -match '^\[([0-9a-fA-F:]+(?:%\d+)?)\]:\d+$') {
            $clientIP = $matches[1]
        }
        # IPv6 with port: ::1:61751
        elseif ($clientIPRaw -match '^([0-9a-fA-F:]+):\d+$' -and $clientIPRaw -match '::') {
            $clientIP = $matches[1]
        }
        # IPv4 with port: 10.1.1.14:61759
        elseif ($clientIPRaw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$') {
            $clientIP = $matches[1]
        }
        # Plain IPv4
        elseif ($clientIPRaw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $clientIP = $clientIPRaw
        }
        # Plain IPv6
        elseif ($clientIPRaw -match '^[0-9a-fA-F:]+$' -and $clientIPRaw -match '::') {
            $clientIP = $clientIPRaw
        }
        
        # If no valid IP found, skip
        if (-not $clientIP) {
            return $null
        }
        
        # Skip internal events (NTDSAPI, SAM - not external clients)
        if ($clientIPRaw -in @("NTDSAPI", "SAM", "LSASS") -or $filter -eq "NTDSAPI") {
            return $null
        }
        
        # Parse numeric fields
        $visitedEntries = if ($props[2].Value -match '^\d+$') { [int]$props[2].Value } else { 0 }
        $returnedEntries = if ($props[3].Value -match '^\d+$') { [int]$props[3].Value } else { 0 }
        $pagesReferenced = if ($props.Count -gt 9 -and $props[9].Value -match '^\d+$') { [int]$props[9].Value } else { 0 }
        $usedIndexes = if ($props.Count -gt 8) { $props[8].Value } else { "" }
        
        return [PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            ClientIP = $clientIP
            SearchBase = $searchBase
            Filter = $filter
            VisitedEntries = $visitedEntries
            ReturnedEntries = $returnedEntries
            Scope = $scope
            UsedIndexes = $usedIndexes
            PagesReferenced = $pagesReferenced
            Attributes = $attributes
            ServerControls = $serverControls
            Message = $Event.Message
        }
        
    } catch {
        return $null
    }
}

#endregion

#region Core Detection Functions

function Get-SuspicionScore {
    <#
    .SYNOPSIS
        Calculate composite suspicion score for LDAP query
    .DESCRIPTION
        Combines multiple detection factors into single score 0-1+
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ParsedEvent,
        
        [Parameter(Mandatory=$false)]
        $Baseline,
        
        [Parameter(Mandatory=$false)]
        [int]$QueryCount = 1
    )
    
    $score = 0.0
    $reasons = @()
    
    # Parse event properties
    $clientIP = $ParsedEvent.ClientIP
    $visitedEntries = $ParsedEvent.VisitedEntries
    $returnedEntries = $ParsedEvent.ReturnedEntries
    $usedIndexes = $ParsedEvent.UsedIndexes
    $pagesReferenced = $ParsedEvent.PagesReferenced
    $filter = $ParsedEvent.Filter
    $attributeList = $ParsedEvent.Attributes
    
    # Calculate efficiency ratio
    $efficiency = if ($visitedEntries -gt 0) {
        ($returnedEntries / $visitedEntries) * 100
    } else {
        100.0
    }
    
    # 1. EFFICIENCY ANALYSIS
    if ($efficiency -eq 0) {
        # Special case: 0% efficiency (visited entries but returned nothing)
        $score += 0.3
        $reasons += "Zero efficiency (visited $visitedEntries, returned 0)"
    }
    elseif ($efficiency -lt $script:Config.Thresholds.EfficiencyCritical) {
        $score += 0.3
        $reasons += "Critical efficiency: $([math]::Round($efficiency, 2))%"
    }
    elseif ($efficiency -lt $script:Config.Thresholds.EfficiencyWarning) {
        $score += 0.2
        $reasons += "Low efficiency: $([math]::Round($efficiency, 2))%"
    }
    
    # 2. VOLUME ANALYSIS
    if ($Baseline) {
        $zScore = ($returnedEntries - $Baseline.Mean) / $Baseline.StdDev
        if ($zScore -gt $script:Config.Thresholds.StandardDeviations) {
            $score += 0.25
            $reasons += "Volume anomaly: $([math]::Round($zScore, 2))σ above baseline"
        }
    }
    elseif ($returnedEntries -gt 1000) {
        $score += 0.25
        $reasons += "High volume: $returnedEntries entries"
    }
    
    # 3. PAGES ANALYSIS
    if ($visitedEntries -gt 0) {
        $pagesPerObject = $pagesReferenced / $visitedEntries
        if ($pagesPerObject -gt $script:Config.Thresholds.CriticalPagesPerObject) {
            $score += 0.2
            $reasons += "Excessive pages/object: $([math]::Round($pagesPerObject, 2))"
        }
        elseif ($pagesPerObject -gt $script:Config.Thresholds.HighPagesPerObject) {
            $score += 0.15
            $reasons += "High pages/object: $([math]::Round($pagesPerObject, 2))"
        }
    }
    
    # 4. INDEX ANALYSIS
    if ([string]::IsNullOrWhiteSpace($usedIndexes) -or $usedIndexes -eq "0" -or $usedIndexes -eq "<unknown>") {
        $score += 0.15
        $reasons += "No index usage (table scan)"
    }
    
    # 5. PATTERN DETECTION
    $patternScore = Test-SuspiciousPatterns -Filter $filter -Attributes $attributeList -ParsedEvent $ParsedEvent
    if ($patternScore.Score -gt 0) {
        $score += $patternScore.Score
        $reasons += $patternScore.Reasons
    }
    
    return @{
        Score = $score
        Reasons = $reasons
        Efficiency = $efficiency
        Volume = $returnedEntries
        Pages = $pagesReferenced
        Client = $clientIP
    }
}

function Test-SuspiciousPatterns {
    <#
    .SYNOPSIS
        Pattern-based detection for known reconnaissance techniques
    .DESCRIPTION
        Identifies specific query patterns used by BloodHound and similar tools
    #>
    param(
        [string]$Filter,
        [string]$Attributes,
        $ParsedEvent
    )
    
    $score = 0.0
    $reasons = @()
    
    # Get server controls if available
   $serverControls = $ParsedEvent.ServerControls

    
    # Pattern 1: Base scope + objectclass=* (object enumeration)
    if ($Filter -match '\(objectclass=\*\)' -and $ParsedEvent.Message -match 'base') {
        if ($Attributes -match 'samaccounttype|objectsid|objectguid|msds-groupmsamembership') {
            $score += 0.5
            $reasons += "Base scope object enumeration detected"
        }
    }
    
    # Pattern 2: SDFlags enumeration (ACL harvesting)
    if ($serverControls -match 'SDFlags:0x[45]' -or $Filter -match 'SDFlags') {
        $score += 0.4
        $reasons += "SDFlags ACL enumeration detected"
    }
    
    # Pattern 3: sAMAccountType enumeration (group/user targeting)
    if ($Filter -match 'sAMAccountType=268435456|sAMAccountType=268435457|sAMAccountType=536870912|sAMAccountType=536870913') {
        $score += 0.4
        $reasons += "sAMAccountType enumeration (group targeting)"
    }
    elseif ($Filter -match 'samaccounttype') {
        $score += 0.3
        $reasons += "sAMAccountType query detected"
    }
    
    # Pattern 4: ADCS/PKI infrastructure queries
    $adcsKeywords = @('pki-enrollment-service', 'certificationauthority', 'certificatetemplates', 'pkicertificatetemplate')
    $adcsMatch = $false
    foreach ($keyword in $adcsKeywords) {
        if ($Filter -match $keyword -or $Attributes -match $keyword) {
            $adcsMatch = $true
            break
        }
    }
    if ($adcsMatch) {
        $score += 0.3
        $reasons += "ADCS/PKI infrastructure enumeration"
    }
    
    # Pattern 5: Excessive attributes (data exfiltration)
    if (-not [string]::IsNullOrWhiteSpace($Attributes)) {
        $attrCount = ($Attributes -split ',').Count
        if ($attrCount -gt 30) {
            $score += 0.2
            $reasons += "Excessive attributes requested: $attrCount"
        }
    }
    
    # Pattern 6: Configuration container queries
    if ($Filter -match 'cn=configuration' -and ($Filter -match 'cn=services' -or $Filter -match 'public key services')) {
        $score += 0.2
        $reasons += "Configuration container infrastructure discovery"
    }
    
    # Pattern 7: Foreign security principals (trust enumeration)
    if ($Filter -match 'cn=foreignsecurityprincipals' -or $Filter -match 'S-1-5-.*' -and $ParsedEvent.Message -match 'base') {
        $score += 0.2
        $reasons += "Foreign security principals enumeration"
    }
    
    return @{
        Score = $score
        Reasons = $reasons
    }
}

function Write-Alert {
    <#
    .SYNOPSIS
        Write alert to log file and optionally display
    .DESCRIPTION
        Implements dual-threshold alerting (log vs display)
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ParsedEvent,
        
        [Parameter(Mandatory=$true)]
        [double]$Score,
        
        [Parameter(Mandatory=$true)]
        [array]$Reasons,
        
        [Parameter(Mandatory=$true)]
        [string]$Client,
        
        [Parameter(Mandatory=$true)]
        [double]$Efficiency
    )
    
    # Determine severity
    $severity = if ($Score -ge $script:Config.AlertLevels.Critical) {
        "CRITICAL"
    } elseif ($Score -ge $script:Config.AlertLevels.High) {
        "HIGH"
    } elseif ($Score -ge $script:Config.AlertLevels.Medium) {
        "MEDIUM"
    } else {
        "LOW"
    }
    
    # Create alert object
    $alert = [PSCustomObject]@{
        Timestamp = $ParsedEvent.TimeCreated
        Severity = $severity
        Score = [math]::Round($Score, 3)
        Client = $Client
        Efficiency = [math]::Round($Efficiency, 2)
        Reasons = ($Reasons -join "; ")
        Filter = $ParsedEvent.Filter
        VisitedEntries = $ParsedEvent.VisitedEntries
        ReturnedEntries = $ParsedEvent.ReturnedEntries
        PagesReferenced = $ParsedEvent.PagesReferenced
    }
    
    # Always log if above log threshold
    if ($Score -ge $script:Config.AlertLogThreshold) {
        $alertJson = $alert | ConvertTo-Json -Compress
        $alertJson | Out-File -FilePath $script:Config.AlertLogFile -Append -Encoding UTF8
    }
    
    # Display based on display threshold
    if ($Score -ge $script:Config.AlertDisplayThreshold) {
        # CRITICAL - Big alert
        Write-Host ""
        Write-Host "    ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "    ║  [$severity] BloodHound Activity Detected                    ║" -ForegroundColor Red
        Write-Host "    ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Time: " -NoNewline -ForegroundColor White
        Write-Host $ParsedEvent.TimeCreated -ForegroundColor Cyan
        Write-Host "    Client: " -NoNewline -ForegroundColor White
        Write-Host $Client -ForegroundColor Yellow
        Write-Host "    Score: " -NoNewline -ForegroundColor White
        Write-Host ([math]::Round($Score, 2)) -ForegroundColor Red
        Write-Host "    Efficiency: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($Efficiency, 2))%" -ForegroundColor $(if ($Efficiency -lt 10) { "Red" } else { "Yellow" })
        Write-Host ""
        Write-Host "    Detection Reasons:" -ForegroundColor White
        foreach ($reason in $Reasons) {
            Write-Host "    • $reason" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    elseif ($Score -ge $script:Config.AlertLogThreshold) {
        # HIGH - Silent logging with subtle indicator
        $timestamp = $ParsedEvent.TimeCreated.ToString("HH:mm:ss")
        Write-Host "    [$timestamp] " -NoNewline -ForegroundColor Gray
        Write-Host "[$severity] " -NoNewline -ForegroundColor Yellow
        Write-Host "Logged - Client: $Client, Eff: $([math]::Round($Efficiency, 2))%, Score: $([math]::Round($Score, 2))" -ForegroundColor Gray
    }
}

#endregion

#region Baseline Functions

function Build-Baseline {
    <#
    .SYNOPSIS
        Build baseline from normal LDAP traffic
    #>
    param([int]$Hours = 24)
    
    Clear-Host
    Write-ColoredHeader "Building Baseline" "Cyan"
    
    Write-Host "    Analyzing LDAP query patterns over the last $Hours hour(s)..." -ForegroundColor White
    Write-Host "    This establishes normal behavior for your environment." -ForegroundColor Gray
    Write-Host ""
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        Write-Host "    [*] Collecting Event ID 1644 entries..." -ForegroundColor Cyan
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $script:Config.EventLog
            ID = $script:Config.EventID
            StartTime = $startTime
        } -ErrorAction Stop
        
        if ($events.Count -eq 0) {
            Write-Host ""
            Write-Host "    [!] No events found in the specified timeframe." -ForegroundColor Yellow
            Write-Host "    [!] Make sure Event ID 1644 logging is enabled." -ForegroundColor Yellow
            Pause-ForUser
            return
        }
        
        Write-Host "    [✓] Found $($events.Count) events" -ForegroundColor Green
        Write-Host ""
        Write-Host "    [*] Calculating statistics..." -ForegroundColor Cyan
        
        # CRITICAL: Parse events first
        $returnedCounts = @()
        $skippedCount = 0
        
        foreach ($event in $events) {
            $parsedEvent = Parse-Event1644 -Event $event
            
            if ($null -eq $parsedEvent) {
                $skippedCount++
                continue
            }
            
            $returnedCounts += $parsedEvent.ReturnedEntries
        }
        
        if ($returnedCounts.Count -eq 0) {
            Write-Host ""
            Write-Host "    [!] No valid events found after parsing." -ForegroundColor Yellow
            Write-Host "    [i] All $($events.Count) events were skipped (internal/localhost)." -ForegroundColor Gray
            Pause-ForUser
            return
        }
        
        # Calculate statistics
        $mean = ($returnedCounts | Measure-Object -Average).Average
        $stdDev = if ($returnedCounts.Count -gt 1) {
            $variance = ($returnedCounts | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
            [math]::Sqrt($variance)
        } else {
            0
        }
        
        $baseline = [PSCustomObject]@{
            CreatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            DurationHours = $Hours
            TotalEvents = $returnedCounts.Count
            Mean = [math]::Round($mean, 2)
            StdDev = [math]::Round($stdDev, 2)
        }
        
        $baseline | ConvertTo-Json | Out-File -FilePath $script:Config.BaselineFile -Encoding UTF8
        
        Write-Host "    [✓] Baseline created successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Statistics:" -ForegroundColor White
        Write-Host "    ───────────" -ForegroundColor DarkGray
        Write-Host "    • Raw Events Found: " -NoNewline -ForegroundColor Gray
        Write-Host $events.Count -ForegroundColor White
        Write-Host "    • Valid Events Used: " -NoNewline -ForegroundColor Gray
        Write-Host $returnedCounts.Count -ForegroundColor Green
        
        if ($skippedCount -gt 0) {
            Write-Host "    • Skipped Events: " -NoNewline -ForegroundColor Gray
            Write-Host $skippedCount -ForegroundColor Yellow -NoNewline
            Write-Host " (internal/localhost)" -ForegroundColor Gray
        }
        
        Write-Host "    • Mean Entries: " -NoNewline -ForegroundColor Gray
        Write-Host $baseline.Mean -ForegroundColor White
        Write-Host "    • Std Deviation: " -NoNewline -ForegroundColor Gray
        Write-Host $baseline.StdDev -ForegroundColor White
        Write-Host "    • Time Period: " -NoNewline -ForegroundColor Gray
        Write-Host "$Hours hours" -ForegroundColor White
        Write-Host ""
        Write-Host "    Baseline saved to: " -NoNewline -ForegroundColor Gray
        Write-Host $script:Config.BaselineFile -ForegroundColor Cyan
        
    }
    catch {
        Write-Host ""
        Write-Host "    [!] Error building baseline: $_" -ForegroundColor Red
    }
    
    Pause-ForUser
}

#endregion

#region Monitoring Functions

function Start-Monitoring {
    <#
    .SYNOPSIS
        Real-time monitoring of LDAP queries
    #>
    
    Clear-Host
    Write-ColoredHeader "Real-Time LDAP Monitoring" "Cyan"
    
    $hasBaseline = Test-Baseline
    $mode = if ($hasBaseline) { "Statistical (with baseline)" } else { "Simple (no baseline)" }
    
    Write-Host "    Detection Mode: " -NoNewline -ForegroundColor White
    Write-Host $mode -ForegroundColor $(if ($hasBaseline) { "Green" } else { "Yellow" })
    Write-Host ""
    
    if (-not $hasBaseline) {
        Write-Host "    [i] Running without baseline - using simple thresholds" -ForegroundColor Yellow
        Write-Host "    [i] Build a baseline (Option 1) for more accurate detection" -ForegroundColor Yellow
        Write-Host ""
    }
    
    Write-Host "    Press Ctrl+C to stop monitoring..." -ForegroundColor Gray
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $baseline = if ($hasBaseline) {
        Get-Content $script:Config.BaselineFile | ConvertFrom-Json
    } else {
        $null
    }
    
    # Get current latest event time
    try {
        $lastEvent = Get-WinEvent -FilterHashtable @{
            LogName = $script:Config.EventLog
            ID = $script:Config.EventID
        } -MaxEvents 1 -ErrorAction Stop
        $lastEventTime = $lastEvent.TimeCreated
    }
    catch {
        $lastEventTime = Get-Date
    }
    
   $alertCount = 0
$processedEvents = @{}  # Track processed events

while ($true) {
    Start-Sleep -Seconds 2
    
    try {
        $newEvents = Get-WinEvent -FilterHashtable @{
            LogName = $script:Config.EventLog
            ID = $script:Config.EventID
            StartTime = $lastEventTime
        } -ErrorAction SilentlyContinue
        
        if ($newEvents) {
            foreach ($event in $newEvents) {
                # Create unique key for this event
                $eventKey = "$($event.TimeCreated.Ticks)-$($event.RecordId)"
                
                # Skip if already processed
                if ($processedEvents.ContainsKey($eventKey)) {
                    continue
                }
                
                # Mark as processed
                $processedEvents[$eventKey] = $true
                
                # Parse and analyze
                $parsedEvent = Parse-Event1644 -Event $event
                
                if ($null -eq $parsedEvent) {
                    continue
                }
                
                $analysis = Get-SuspicionScore -ParsedEvent $parsedEvent -Baseline $baseline
                
                if ($analysis.Score -ge $script:Config.AlertLogThreshold) {
                    $alertCount++
                    Write-Alert -ParsedEvent $parsedEvent -Score $analysis.Score -Reasons $analysis.Reasons -Client $analysis.Client -Efficiency $analysis.Efficiency
                }
            }
            
            # Update last event time
            $lastEventTime = $newEvents[0].TimeCreated.AddSeconds(1)
            
            # Clean up old processed events (keep last 1000)
            if ($processedEvents.Count -gt 1000) {
                $processedEvents.Clear()
            }
        }
    }
    catch {
        # Silent error handling
    }
}
}

#endregion

#region Analysis Functions

function Analyze-History {
    <#
    .SYNOPSIS
        Analyze historical LDAP events
    #>
    param([int]$Hours = 2)
    
    Clear-Host
    Write-ColoredHeader "Historical Analysis" "Cyan"
    
    Write-Host "    Analyzing last $Hours hour(s) of LDAP activity..." -ForegroundColor White
    Write-Host ""
    
    $hasBaseline = Test-Baseline
    $baseline = if ($hasBaseline) {
        Get-Content $script:Config.BaselineFile | ConvertFrom-Json
    } else {
        $null
    }
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        Write-Host "    [*] Loading events..." -ForegroundColor Cyan
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $script:Config.EventLog
            ID = $script:Config.EventID
            StartTime = $startTime
        } -ErrorAction Stop
        
        Write-Host "    [✓] Found $($events.Count) events" -ForegroundColor Green
        Write-Host ""
        
        if ($events.Count -eq 0) {
            Write-Host "    [!] No events found in timeframe" -ForegroundColor Yellow
            Pause-ForUser
            return
        }
        
        Write-Host "    [*] Analyzing events..." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        
        $validEvents = 0
        $skippedEvents = 0
        $alertCount = 0
        
        foreach ($event in $events) {
            # CRITICAL: Parse event first
            $parsedEvent = Parse-Event1644 -Event $event
            
            if ($null -eq $parsedEvent) {
                $skippedEvents++
                continue
            }
            
            $validEvents++
            
            # Now use parsed event (not raw event)
            $analysis = Get-SuspicionScore -ParsedEvent $parsedEvent -Baseline $baseline
            
            if ($analysis.Score -ge $script:Config.AlertLogThreshold) {
                $alertCount++
                Write-Alert -ParsedEvent $parsedEvent -Score $analysis.Score -Reasons $analysis.Reasons -Client $analysis.Client -Efficiency $analysis.Efficiency
            }
        }
        
        Write-Host ""
        Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Analysis Complete:" -ForegroundColor Green
        Write-Host "    • Total Events Found: " -NoNewline -ForegroundColor Gray
        Write-Host $events.Count -ForegroundColor White
        Write-Host "    • Valid Events Analyzed: " -NoNewline -ForegroundColor Gray
        Write-Host $validEvents -ForegroundColor Green
        Write-Host "    • Skipped (internal/IPv6 localhost): " -NoNewline -ForegroundColor Gray
        Write-Host $skippedEvents -ForegroundColor Yellow
        Write-Host "    • Alerts Generated: " -NoNewline -ForegroundColor Gray
        Write-Host $alertCount -ForegroundColor $(if ($alertCount -gt 0) { "Red" } else { "Green" })
        
    }
    catch {
        Write-Host ""
        Write-Host "    [!] Error analyzing history: $_" -ForegroundColor Red
    }
    
    Pause-ForUser
}

#endregion

function Show-AlertAnalysis {
    <#
    .SYNOPSIS
        Analyze logged alerts
    #>
    
    if (-not (Test-Path $script:Config.AlertLogFile)) {
        Clear-Host
        Write-ColoredHeader "Alert Analysis" "Cyan"
        Write-Host "    [!] No alerts found" -ForegroundColor Yellow
        Write-Host "    [i] Alerts will appear here after detection occurs" -ForegroundColor Gray
        Pause-ForUser
        return
    }
    
    # Load alerts
    $alerts = Get-Content $script:Config.AlertLogFile | ForEach-Object {
        $_ | ConvertFrom-Json
    }
    
    if ($alerts.Count -eq 0) {
        Clear-Host
        Write-ColoredHeader "Alert Analysis" "Cyan"
        Write-Host "    [!] No alerts found" -ForegroundColor Yellow
        Pause-ForUser
        return
    }
    
    # Show alert analysis menu
    do {
        Clear-Host
        Write-Host ""
        Write-Host "    ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "    │                    Alert Analysis                        │" -ForegroundColor Cyan
        Write-Host "    └──────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Loading alert log... " -NoNewline -ForegroundColor Gray
        Write-Host "Done!" -ForegroundColor Green
        Write-Host ""
        Write-Host "    [✓] Total Alerts: " -NoNewline -ForegroundColor Green
        Write-Host $alerts.Count -ForegroundColor White
        Write-Host ""
        Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Alert Analysis Options:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    [1] " -NoNewline -ForegroundColor White
        Write-Host "Summary Statistics" -ForegroundColor Cyan
        Write-Host "    [2] " -NoNewline -ForegroundColor White
        Write-Host "Alerts by Time" -ForegroundColor Cyan
        Write-Host "    [3] " -NoNewline -ForegroundColor White
        Write-Host "Alerts by Client/IP" -ForegroundColor Cyan
        Write-Host "    [4] " -NoNewline -ForegroundColor White
        Write-Host "Alerts by Detection Pattern" -ForegroundColor Cyan
        Write-Host "    [5] " -NoNewline -ForegroundColor White
        Write-Host "Export to HTML Report" -ForegroundColor Yellow
        Write-Host "    [6] " -NoNewline -ForegroundColor White
        Write-Host "Export to CSV" -ForegroundColor Yellow
        Write-Host "    [0] " -NoNewline -ForegroundColor White
        Write-Host "Back to Main Menu" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "    Select option (0-6)"
        
        switch ($choice) {
            '1' { Show-AlertSummary -Alerts $alerts; Pause-ForUser }
            '2' { Show-AlertsByTime -Alerts $alerts; Pause-ForUser }
            '3' { Show-AlertsByClient -Alerts $alerts; Pause-ForUser }
            '4' { Show-AlertsByPattern -Alerts $alerts; Pause-ForUser }
            '5' { Export-HTMLReport -Alerts $alerts }
            '6' { Export-CSVReport -Alerts $alerts; Pause-ForUser }
            '0' { return }
            default {
                Write-Host ""
                Write-Host "    [!] Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($choice -ne '0')
}

function Show-AlertSummary {
    param([array]$Alerts)
    
    Clear-Host
    Write-ColoredHeader "Alert Summary Statistics" "Cyan"
    
    $critical = ($Alerts | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = ($Alerts | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = ($Alerts | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $low = ($Alerts | Where-Object { $_.Severity -eq "LOW" }).Count
    
    Write-Host "    Total Alerts: " -NoNewline -ForegroundColor White
    Write-Host $Alerts.Count -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    By Severity:" -ForegroundColor White
    Write-Host "    ────────────" -ForegroundColor DarkGray
    Write-Host "    • CRITICAL: " -NoNewline -ForegroundColor Red
    Write-Host $critical -ForegroundColor White
    Write-Host "    • HIGH:     " -NoNewline -ForegroundColor Yellow
    Write-Host $high -ForegroundColor White
    Write-Host "    • MEDIUM:   " -NoNewline -ForegroundColor Cyan
    Write-Host $medium -ForegroundColor White
    Write-Host "    • LOW:      " -NoNewline -ForegroundColor Gray
    Write-Host $low -ForegroundColor White
    Write-Host ""
    
    $avgScore = ($Alerts | Measure-Object -Property Score -Average).Average
    Write-Host "    Average Score: " -NoNewline -ForegroundColor White
    Write-Host ([math]::Round($avgScore, 3)) -ForegroundColor Cyan
    Write-Host ""
    
    $uniqueClients = ($Alerts | Select-Object -Property Client -Unique).Count
    Write-Host "    Unique Clients: " -NoNewline -ForegroundColor White
    Write-Host $uniqueClients -ForegroundColor Cyan
}

function Show-AlertsByTime {
    param([array]$Alerts)
    
    Clear-Host
    Write-ColoredHeader "Alerts by Time" "Cyan"
    
    $alertsByHour = $Alerts | Group-Object { 
        [DateTime]::Parse($_.Timestamp).ToString("yyyy-MM-dd HH:00")
    } | Sort-Object Name
    
    Write-Host "    Time Period                  Alerts" -ForegroundColor White
    Write-Host "    ────────────────────────────────────" -ForegroundColor DarkGray
    
    foreach ($group in $alertsByHour) {
        $critCount = ($group.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount = ($group.Group | Where-Object { $_.Severity -eq "HIGH" }).Count
        
        Write-Host "    $($group.Name)          " -NoNewline -ForegroundColor Gray
        Write-Host $group.Count -NoNewline -ForegroundColor White
        
        if ($critCount -gt 0) {
            Write-Host " ($critCount CRIT)" -NoNewline -ForegroundColor Red
        }
        if ($highCount -gt 0) {
            Write-Host " ($highCount HIGH)" -NoNewline -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

function Show-AlertsByClient {
    param([array]$Alerts)
    
    Clear-Host
    Write-ColoredHeader "Alerts by Client IP" "Cyan"
    
    $alertsByClient = $Alerts | Group-Object Client | Sort-Object Count -Descending
    
    Write-Host "    Client IP              Alerts    Avg Score" -ForegroundColor White
    Write-Host "    ───────────────────────────────────────────" -ForegroundColor DarkGray
    
    foreach ($group in $alertsByClient | Select-Object -First 20) {
        $avgScore = ($group.Group | Measure-Object -Property Score -Average).Average
        $critCount = ($group.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        
        $color = if ($critCount -gt 5) { "Red" } elseif ($critCount -gt 0) { "Yellow" } else { "Gray" }
        
        Write-Host "    $($group.Name.PadRight(20)) " -NoNewline -ForegroundColor $color
        Write-Host "$($group.Count.ToString().PadLeft(6))    " -NoNewline -ForegroundColor White
        Write-Host ([math]::Round($avgScore, 2)) -ForegroundColor Cyan
    }
}

function Show-AlertsByPattern {
    param([array]$Alerts)
    
    Clear-Host
    Write-ColoredHeader "Alerts by Detection Pattern" "Cyan"
    
    $patternStats = @{}
    
    foreach ($alert in $Alerts) {
        $reasons = $alert.Reasons -split '; '
        foreach ($reason in $reasons) {
            if (-not $patternStats.ContainsKey($reason)) {
                $patternStats[$reason] = 0
            }
            $patternStats[$reason]++
        }
    }
    
    $sortedPatterns = $patternStats.GetEnumerator() | Sort-Object Value -Descending
    
    Write-Host "    Detection Pattern                                      Count" -ForegroundColor White
    Write-Host "    ──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    foreach ($pattern in $sortedPatterns | Select-Object -First 15) {
        $displayText = if ($pattern.Key.Length -gt 50) {
            $pattern.Key.Substring(0, 47) + "..."
        } else {
            $pattern.Key.PadRight(50)
        }
        
        Write-Host "    $displayText " -NoNewline -ForegroundColor Gray
        Write-Host $pattern.Value -ForegroundColor Cyan
    }
}


function Export-HTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Alerts,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:USERPROFILE\Desktop\BloodHound-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )
    
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                   GENERATING ENHANCED HTML REPORT                " -ForegroundColor Cyan
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Alerts.Count -eq 0) {
        Write-Host "    [!] No alerts to report" -ForegroundColor Yellow
        return
    }
    
    # ═══════════════════════════════════════════════════════════════
    # HELPER FUNCTION FOR TIMESTAMP PARSING
    # ═══════════════════════════════════════════════════════════════
    
    function Parse-Timestamp {
        param($timestamp)
        
        if ($timestamp -is [DateTime]) {
            return $timestamp
        }
        elseif ($timestamp -match '/Date\((\d+)\)/') {
            $ticks = [long]$matches[1]
            return [DateTime]::FromFileTimeUtc($ticks)
        }
        else {
            return [DateTime]::Parse($timestamp)
        }
    }
    
    # ═══════════════════════════════════════════════════════════════
    # CALCULATE EXECUTIVE METRICS
    # ═══════════════════════════════════════════════════════════════
    
    $totalAlerts = $Alerts.Count
    $criticalAlerts = ($Alerts | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highAlerts = ($Alerts | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $mediumAlerts = ($Alerts | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    
    # Calculate detection types
    $signatureDetections = ($Alerts | Where-Object { $_.Reasons -match 'SDFlags|ADCS|Kerberoastable|adminCount|ASREPRoastable|Confidential|constrained delegation|ms-Mcs-AdmPwd' }).Count
    $statisticalDetections = ($Alerts | Where-Object { $_.Reasons -match 'High pages|Zero efficiency|No index|Excessive attributes|outlier' }).Count
    $hybridDetections = $totalAlerts - $signatureDetections - $statisticalDetections
    
    if ($hybridDetections -lt 0) { $hybridDetections = 0 }
    
    $signaturePercent = if ($totalAlerts -gt 0) { [math]::Round(($signatureDetections / $totalAlerts) * 100, 1) } else { 0 }
    $statisticalPercent = if ($totalAlerts -gt 0) { [math]::Round(($statisticalDetections / $totalAlerts) * 100, 1) } else { 0 }
    $hybridPercent = if ($totalAlerts -gt 0) { [math]::Round(($hybridDetections / $totalAlerts) * 100, 1) } else { 0 }
    
    # Calculate attack velocity using helper function
    $firstTime = Parse-Timestamp $Alerts[0].Timestamp
    $lastTime = Parse-Timestamp $Alerts[-1].Timestamp
    $timeSpan = $lastTime.Subtract($firstTime)
    $attackVelocity = if ($timeSpan.TotalMinutes -gt 0) { 
        [math]::Round($totalAlerts / $timeSpan.TotalMinutes, 2) 
    } else { 
        0 
    }
    
    # Detect attack bursts (5+ alerts within 2 minutes)
    $burstCount = 0
    if ($Alerts.Count -ge 5) {
        for ($i = 0; $i -lt $Alerts.Count - 4; $i++) {
            try {
                $windowStart = Parse-Timestamp $Alerts[$i].Timestamp
                $windowEnd = Parse-Timestamp $Alerts[$i+4].Timestamp
                
                if (($windowEnd - $windowStart).TotalMinutes -le 2) {
                    $burstCount++
                }
            } catch {
                # Skip if timestamp parsing fails
                continue
            }
        }
    }
    
    # Top threat clients
    $topThreats = $Alerts | Group-Object Client | 
        Sort-Object Count -Descending | 
        Select-Object -First 5 @{Name='Client';Expression={$_.Name}}, 
                                  @{Name='Alerts';Expression={$_.Count}}, 
                                  @{Name='AvgScore';Expression={[math]::Round(($_.Group | Measure-Object Score -Average).Average, 2)}}
    
    # Average efficiency
    $avgEfficiency = [math]::Round(($Alerts | Measure-Object Efficiency -Average).Average, 2)
    
    Write-Host "    [*] Processing $totalAlerts alerts..." -ForegroundColor White
    Write-Host "    [*] Time range: $($firstTime.ToString('HH:mm:ss')) - $($lastTime.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "    [*] Detection mix: $signaturePercent% signature, $statisticalPercent% statistical, $hybridPercent% hybrid" -ForegroundColor White
    Write-Host "    [*] Attack velocity: $attackVelocity alerts/minute" -ForegroundColor White
    Write-Host "    [*] Attack bursts detected: $burstCount" -ForegroundColor White
    
    # ═══════════════════════════════════════════════════════════════
    # PREPARE CHART DATA
    # ═══════════════════════════════════════════════════════════════
    
    # Timeline data
    $timelineLabels = @()
    $timelineScores = @()
    foreach ($alert in $Alerts) {
        try {
            $time = Parse-Timestamp $alert.Timestamp
            $timelineLabels += "'$($time.ToString('HH:mm:ss'))'"
            $timelineScores += $alert.Score
        } catch {
            Write-Host "    [!] Warning: Could not parse timestamp for alert" -ForegroundColor Yellow
        }
    }
    $timelineLabelsStr = $timelineLabels -join ','
    $timelineScoresStr = $timelineScores -join ','
    
    # Top clients data
    $clientLabels = ($topThreats | ForEach-Object { "'$($_.Client)'" }) -join ','
    $clientCounts = ($topThreats | ForEach-Object { $_.Alerts }) -join ','
    
    # Efficiency distribution
    $eff0_20 = ($Alerts | Where-Object { $_.Efficiency -ge 0 -and $_.Efficiency -lt 20 }).Count
    $eff20_40 = ($Alerts | Where-Object { $_.Efficiency -ge 20 -and $_.Efficiency -lt 40 }).Count
    $eff40_60 = ($Alerts | Where-Object { $_.Efficiency -ge 40 -and $_.Efficiency -lt 60 }).Count
    $eff60_80 = ($Alerts | Where-Object { $_.Efficiency -ge 60 -and $_.Efficiency -lt 80 }).Count
    $eff80_100 = ($Alerts | Where-Object { $_.Efficiency -ge 80 }).Count
    $efficiencyValues = "$eff0_20,$eff20_40,$eff40_60,$eff60_80,$eff80_100"
    
    # Pattern analysis
    $patternData = $Alerts | ForEach-Object { $_.Reasons -split '; ' } | 
        Group-Object | 
        Sort-Object Count -Descending | 
        Select-Object -First 8
    $patternLabels = ($patternData | ForEach-Object { 
        $label = $_.Name -replace "'", ""
        "'$label'"
    }) -join ','
    $patternCounts = ($patternData | ForEach-Object { $_.Count }) -join ','
    
    Write-Host "    [*] Building HTML structure..." -ForegroundColor White
    
    # ═══════════════════════════════════════════════════════════════
    # BUILD HTML (PART 1 - HEADER AND STYLES)
    # ═══════════════════════════════════════════════════════════════
    
    $monitoringPeriod = "$($firstTime.ToString('HH:mm')) - $($lastTime.ToString('HH:mm')) ($([math]::Round($timeSpan.TotalMinutes, 1)) min)"
    
    $htmlPart1 = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BloodHound Detection Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .subtitle { font-size: 1.1em; opacity: 0.9; }
        .executive-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; border-bottom: 3px solid #e9ecef; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #667eea; transition: transform 0.2s; }
        .metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .metric-card.critical { border-left-color: #dc3545; }
        .metric-card.high { border-left-color: #fd7e14; }
        .metric-card.medium { border-left-color: #ffc107; }
        .metric-value { font-size: 2.5em; font-weight: bold; color: #667eea; margin: 10px 0; }
        .metric-card.critical .metric-value { color: #dc3545; }
        .metric-card.high .metric-value { color: #fd7e14; }
        .metric-card.medium .metric-value { color: #ffc107; }
        .metric-label { font-size: 0.9em; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; }
        .metric-subtext { font-size: 0.85em; color: #6c757d; margin-top: 5px; }
        .detection-efficacy { padding: 30px; background: white; }
        .section-title { font-size: 1.8em; color: #1e3c72; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e9ecef; }
        .efficacy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .efficacy-item { padding: 15px; border-radius: 8px; text-align: center; font-weight: bold; }
        .efficacy-signature { background: #e3f2fd; color: #1976d2; }
        .efficacy-statistical { background: #f3e5f5; color: #7b1fa2; }
        .efficacy-hybrid { background: #fff3e0; color: #f57c00; }
        .threat-sources { padding: 30px; background: #f8f9fa; }
        .threat-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .threat-table th { background: #1e3c72; color: white; padding: 15px; text-align: left; font-weight: 600; }
        .threat-table td { padding: 12px 15px; border-bottom: 1px solid #e9ecef; }
        .threat-table tr:hover { background: #f8f9fa; }
        .rank-badge { display: inline-block; width: 30px; height: 30px; line-height: 30px; text-align: center; border-radius: 50%; font-weight: bold; color: white; background: #667eea; }
        .rank-badge.rank-1 { background: #dc3545; }
        .rank-badge.rank-2 { background: #fd7e14; }
        .rank-badge.rank-3 { background: #ffc107; color: #333; }
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 30px; padding: 30px; background: white; }
        .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .chart-title { font-size: 1.2em; color: #1e3c72; margin-bottom: 15px; font-weight: 600; }
        .alerts-section { padding: 30px; background: #f8f9fa; }
        .filter-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 10px 20px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all 0.2s; background: white; color: #333; }
        .filter-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .filter-btn.active { color: white; }
        .filter-btn.all { background: #667eea; color: white; }
        .filter-btn.critical { background: #dc3545; color: white; }
        .filter-btn.high { background: #fd7e14; color: white; }
        .filter-btn.medium { background: #ffc107; }
        .alerts-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .alerts-table th { background: #1e3c72; color: white; padding: 12px; text-align: left; font-weight: 600; font-size: 0.9em; }
        .alerts-table td { padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-size: 0.85em; }
        .alerts-table tr:hover { background: #f8f9fa; }
        .severity-badge { padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 0.75em; text-transform: uppercase; display: inline-block; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #333; }
        .score-badge { font-weight: bold; color: #667eea; }
        .efficiency-low { color: #dc3545; font-weight: bold; }
        .efficiency-medium { color: #ffc107; font-weight: bold; }
        .efficiency-high { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ BloodHound Detection Report</h1>
            <div class="subtitle">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Monitoring Period: $monitoringPeriod</div>
        </div>
        
        <div class="executive-summary">
            <div class="metric-card">
                <div class="metric-label">Total Alerts</div>
                <div class="metric-value">$totalAlerts</div>
                <div class="metric-subtext">All severity levels</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical</div>
                <div class="metric-value">$criticalAlerts</div>
                <div class="metric-subtext">$([math]::Round(($criticalAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card high">
                <div class="metric-label">High</div>
                <div class="metric-value">$highAlerts</div>
                <div class="metric-subtext">$([math]::Round(($highAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card medium">
                <div class="metric-label">Medium</div>
                <div class="metric-value">$mediumAlerts</div>
                <div class="metric-subtext">$([math]::Round(($mediumAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Attack Velocity</div>
                <div class="metric-value">$attackVelocity</div>
                <div class="metric-subtext">alerts per minute</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Attack Bursts</div>
                <div class="metric-value">$burstCount</div>
                <div class="metric-subtext">5+ alerts in 2 min</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Avg Efficiency</div>
                <div class="metric-value">$avgEfficiency%</div>
                <div class="metric-subtext">Query efficiency</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Unique Clients</div>
                <div class="metric-value">$($topThreats.Count)</div>
                <div class="metric-subtext">Top threat sources</div>
            </div>
        </div>
        
        <div class="detection-efficacy">
            <div class="section-title">🎯 Detection Efficacy Analysis</div>
            <div class="efficacy-grid">
                <div class="efficacy-item efficacy-signature">
                    <div style="font-size: 2em;">$signatureDetections</div>
                    <div>Signature-Based ($signaturePercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Known patterns</div>
                </div>
                <div class="efficacy-item efficacy-statistical">
                    <div style="font-size: 2em;">$statisticalDetections</div>
                    <div>Statistical ($statisticalPercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Behavioral anomalies</div>
                </div>
                <div class="efficacy-item efficacy-hybrid">
                    <div style="font-size: 2em;">$hybridDetections</div>
                    <div>Hybrid ($hybridPercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Combined detection</div>
                </div>
            </div>
        </div>
        
        <div class="threat-sources">
            <div class="section-title">🎯 Top 5 Threat Sources</div>
            <table class="threat-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Client IP</th>
                        <th>Total Alerts</th>
                        <th>Avg Score</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
"@

    # Build threat table rows
    $threatRows = ""
    $rank = 1
    foreach ($threat in $topThreats) {
        $riskLevel = if ($threat.AvgScore -ge 0.85) { "CRITICAL" } elseif ($threat.AvgScore -ge 0.60) { "HIGH" } else { "MEDIUM" }
        $riskClass = $riskLevel.ToLower()
        
        $threatRows += @"
                    <tr>
                        <td><span class="rank-badge rank-$rank">$rank</span></td>
                        <td><strong>$($threat.Client)</strong></td>
                        <td>$($threat.Alerts) alerts</td>
                        <td class="score-badge">$($threat.AvgScore)</td>
                        <td><span class="severity-badge severity-$riskClass">$riskLevel</span></td>
                    </tr>
"@
        $rank++
    }

    $htmlPart2 = @"
                </tbody>
            </table>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <div class="chart-title">📈 Alert Timeline</div>
                <canvas id="timelineChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">📊 Severity Distribution</div>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🎯 Top Clients by Alert Count</div>
                <canvas id="clientsChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🔍 Detection Method Breakdown</div>
                <canvas id="detectionChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">⚡ Query Efficiency Distribution</div>
                <canvas id="efficiencyChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🔎 Top Detection Patterns</div>
                <canvas id="patternsChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="section-title">📋 Detailed Alert Log</div>
            <div class="filter-buttons">
                <button class="filter-btn all active" onclick="filterAlerts('all')">All Alerts ($totalAlerts)</button>
                <button class="filter-btn critical" onclick="filterAlerts('critical')">Critical ($criticalAlerts)</button>
                <button class="filter-btn high" onclick="filterAlerts('high')">High ($highAlerts)</button>
                <button class="filter-btn medium" onclick="filterAlerts('medium')">Medium ($mediumAlerts)</button>
            </div>
            <table class="alerts-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Client</th>
                        <th>Efficiency</th>
                        <th>Detection Reasons</th>
                        <th>LDAP Filter</th>
                    </tr>
                </thead>
                <tbody id="alertsTableBody">
"@

    Write-Host "    [*] Building alert table rows..." -ForegroundColor White
    
    # Build alert rows
    $alertRows = ""
    foreach ($alert in $Alerts) {
        try {
            $time = Parse-Timestamp $alert.Timestamp
            $timeStr = $time.ToString('HH:mm:ss')
            $severityClass = $alert.Severity.ToLower()
            $efficiencyClass = if ($alert.Efficiency -lt 30) { 'efficiency-low' } elseif ($alert.Efficiency -lt 70) { 'efficiency-medium' } else { 'efficiency-high' }
            
            $alertRows += @"
                    <tr data-severity="$severityClass">
                        <td>$timeStr</td>
                        <td><span class="severity-badge severity-$severityClass">$($alert.Severity)</span></td>
                        <td class="score-badge">$($alert.Score)</td>
                        <td>$($alert.Client)</td>
                        <td class="$efficiencyClass">$($alert.Efficiency)%</td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="$($alert.Reasons)">$($alert.Reasons)</td>
                        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.8em;" title="$($alert.Filter)">$($alert.Filter)</td>
                    </tr>
"@
        } catch {
            Write-Host "    [!] Warning: Skipped alert with invalid timestamp" -ForegroundColor Yellow
        }
    }

    Write-Host "    [*] Building charts and scripts..." -ForegroundColor White

    $htmlPart3 = @"
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: [$timelineLabelsStr],
                datasets: [{
                    label: 'Alert Score',
                    data: [$timelineScoresStr],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Threat Score' } },
                    x: { title: { display: true, text: 'Time' }, ticks: { maxRotation: 45, minRotation: 45 } }
                }
            }
        });
        
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium'],
                datasets: [{
                    data: [$criticalAlerts, $highAlerts, $mediumAlerts],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'bottom' } }
            }
        });
        
        new Chart(document.getElementById('clientsChart'), {
            type: 'bar',
            data: {
                labels: [$clientLabels],
                datasets: [{
                    label: 'Alert Count',
                    data: [$clientCounts],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, title: { display: true, text: 'Number of Alerts' } } }
            }
        });
        
        new Chart(document.getElementById('detectionChart'), {
            type: 'pie',
            data: {
                labels: ['Signature', 'Statistical', 'Hybrid'],
                datasets: [{
                    data: [$signatureDetections, $statisticalDetections, $hybridDetections],
                    backgroundColor: ['#1976d2', '#7b1fa2', '#f57c00'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'bottom' } }
            }
        });
        
        new Chart(document.getElementById('efficiencyChart'), {
            type: 'bar',
            data: {
                labels: ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%'],
                datasets: [{
                    label: 'Query Count',
                    data: [$efficiencyValues],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Number of Queries' } },
                    x: { title: { display: true, text: 'Efficiency Range' } }
                }
            }
        });
        
        new Chart(document.getElementById('patternsChart'), {
            type: 'bar',
            data: {
                labels: [$patternLabels],
                datasets: [{
                    label: 'Detection Count',
                    data: [$patternCounts],
                    backgroundColor: '#667eea',
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, title: { display: true, text: 'Frequency' } } }
            }
        });
        
        function filterAlerts(severity) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('#alertsTableBody tr').forEach(row => {
                if (severity === 'all') {
                    row.style.display = '';
                } else {
                    row.style.display = row.getAttribute('data-severity') === severity ? '' : 'none';
                }
            });
        }
    </script>
</body>
</html>
"@

    # Combine all HTML parts
    $finalHtml = $htmlPart1 + $threatRows + $htmlPart2 + $alertRows + $htmlPart3
    
    Write-Host "    [*] Writing HTML to file..." -ForegroundColor White
    
    # Write to file
    $finalHtml | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "    [✓] Enhanced report generated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "           ENHANCED HTML REPORT GENERATED SUCCESSFULLY              " -ForegroundColor Green  
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "      Report Location:" -ForegroundColor Cyan
    Write-Host "         $OutputPath" -ForegroundColor White
    Write-Host ""
    Write-Host "      Report Features:" -ForegroundColor Cyan
    Write-Host "         • Executive Summary with 8 Key Metrics" -ForegroundColor Gray
    Write-Host "         • Detection Efficacy Analysis" -ForegroundColor Gray
    Write-Host "         • Top 5 Threat Clients Ranking" -ForegroundColor Gray
    Write-Host "         • 6 Interactive Charts (Chart.js)" -ForegroundColor Gray
    Write-Host "         • Interactive Alert Filtering" -ForegroundColor Gray
    Write-Host "         • Detailed Alert Table" -ForegroundColor Gray
    Write-Host ""
    Write-Host "      Report Statistics:" -ForegroundColor Yellow
    Write-Host "         • $burstCount attack bursts detected" -ForegroundColor Gray
    Write-Host "         • $($topThreats.Count) high-risk clients identified" -ForegroundColor Gray
    Write-Host "         • $totalAlerts total alerts analyzed" -ForegroundColor Gray
    Write-Host "         • $attackVelocity alerts/min attack velocity" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════
# ENHANCED EXPORT-HTMLREPORT FUNCTION - FINAL FIXED VERSION
# ═══════════════════════════════════════════════════════════════
# This version properly handles both DateTime objects and JSON timestamps
# ═══════════════════════════════════════════════════════════════

function Export-HTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Alerts,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:USERPROFILE\Desktop\BloodHound-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )
    
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                   GENERATING ENHANCED HTML REPORT                " -ForegroundColor Cyan
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Alerts.Count -eq 0) {
        Write-Host "    [!] No alerts to report" -ForegroundColor Yellow
        return
    }
    
    # ═══════════════════════════════════════════════════════════════
    # HELPER FUNCTION FOR TIMESTAMP PARSING
    # ═══════════════════════════════════════════════════════════════
    
    function Parse-Timestamp {
        param($timestamp)
        
        if ($timestamp -is [DateTime]) {
            return $timestamp
        }
        elseif ($timestamp -match '/Date\((\d+)\)/') {
            $ticks = [long]$matches[1]
            return [DateTime]::FromFileTimeUtc($ticks)
        }
        else {
            return [DateTime]::Parse($timestamp)
        }
    }
    
    # ═══════════════════════════════════════════════════════════════
    # CALCULATE EXECUTIVE METRICS
    # ═══════════════════════════════════════════════════════════════
    
    $totalAlerts = $Alerts.Count
    $criticalAlerts = ($Alerts | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highAlerts = ($Alerts | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $mediumAlerts = ($Alerts | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    
    # Calculate detection types
    $signatureDetections = ($Alerts | Where-Object { $_.Reasons -match 'SDFlags|ADCS|Kerberoastable|adminCount|ASREPRoastable|Confidential|constrained delegation|ms-Mcs-AdmPwd' }).Count
    $statisticalDetections = ($Alerts | Where-Object { $_.Reasons -match 'High pages|Zero efficiency|No index|Excessive attributes|outlier' }).Count
    $hybridDetections = $totalAlerts - $signatureDetections - $statisticalDetections
    
    if ($hybridDetections -lt 0) { $hybridDetections = 0 }
    
    $signaturePercent = if ($totalAlerts -gt 0) { [math]::Round(($signatureDetections / $totalAlerts) * 100, 1) } else { 0 }
    $statisticalPercent = if ($totalAlerts -gt 0) { [math]::Round(($statisticalDetections / $totalAlerts) * 100, 1) } else { 0 }
    $hybridPercent = if ($totalAlerts -gt 0) { [math]::Round(($hybridDetections / $totalAlerts) * 100, 1) } else { 0 }
    
    # Calculate attack velocity using helper function
    $firstTime = Parse-Timestamp $Alerts[0].Timestamp
    $lastTime = Parse-Timestamp $Alerts[-1].Timestamp
    $timeSpan = $lastTime.Subtract($firstTime)
    $attackVelocity = if ($timeSpan.TotalMinutes -gt 0) { 
        [math]::Round($totalAlerts / $timeSpan.TotalMinutes, 2) 
    } else { 
        0 
    }
    
    # Detect attack bursts (5+ alerts within 2 minutes)
    $burstCount = 0
    if ($Alerts.Count -ge 5) {
        for ($i = 0; $i -lt $Alerts.Count - 4; $i++) {
            try {
                $windowStart = Parse-Timestamp $Alerts[$i].Timestamp
                $windowEnd = Parse-Timestamp $Alerts[$i+4].Timestamp
                
                if (($windowEnd - $windowStart).TotalMinutes -le 2) {
                    $burstCount++
                }
            } catch {
                # Skip if timestamp parsing fails
                continue
            }
        }
    }
    
    # Top threat clients
    $topThreats = $Alerts | Group-Object Client | 
        Sort-Object Count -Descending | 
        Select-Object -First 5 @{Name='Client';Expression={$_.Name}}, 
                                  @{Name='Alerts';Expression={$_.Count}}, 
                                  @{Name='AvgScore';Expression={[math]::Round(($_.Group | Measure-Object Score -Average).Average, 2)}}
    
    # Average efficiency
    $avgEfficiency = [math]::Round(($Alerts | Measure-Object Efficiency -Average).Average, 2)
    
    Write-Host "    [*] Processing $totalAlerts alerts..." -ForegroundColor White
    Write-Host "    [*] Time range: $($firstTime.ToString('HH:mm:ss')) - $($lastTime.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "    [*] Detection mix: $signaturePercent% signature, $statisticalPercent% statistical, $hybridPercent% hybrid" -ForegroundColor White
    Write-Host "    [*] Attack velocity: $attackVelocity alerts/minute" -ForegroundColor White
    Write-Host "    [*] Attack bursts detected: $burstCount" -ForegroundColor White
    
    # ═══════════════════════════════════════════════════════════════
    # PREPARE CHART DATA
    # ═══════════════════════════════════════════════════════════════
    
    # Timeline data
    $timelineLabels = @()
    $timelineScores = @()
    foreach ($alert in $Alerts) {
        try {
            $time = Parse-Timestamp $alert.Timestamp
            $timelineLabels += "'$($time.ToString('HH:mm:ss'))'"
            $timelineScores += $alert.Score
        } catch {
            Write-Host "    [!] Warning: Could not parse timestamp for alert" -ForegroundColor Yellow
        }
    }
    $timelineLabelsStr = $timelineLabels -join ','
    $timelineScoresStr = $timelineScores -join ','
    
    # Top clients data
    $clientLabels = ($topThreats | ForEach-Object { "'$($_.Client)'" }) -join ','
    $clientCounts = ($topThreats | ForEach-Object { $_.Alerts }) -join ','
    
    # Efficiency distribution
    $eff0_20 = ($Alerts | Where-Object { $_.Efficiency -ge 0 -and $_.Efficiency -lt 20 }).Count
    $eff20_40 = ($Alerts | Where-Object { $_.Efficiency -ge 20 -and $_.Efficiency -lt 40 }).Count
    $eff40_60 = ($Alerts | Where-Object { $_.Efficiency -ge 40 -and $_.Efficiency -lt 60 }).Count
    $eff60_80 = ($Alerts | Where-Object { $_.Efficiency -ge 60 -and $_.Efficiency -lt 80 }).Count
    $eff80_100 = ($Alerts | Where-Object { $_.Efficiency -ge 80 }).Count
    $efficiencyValues = "$eff0_20,$eff20_40,$eff40_60,$eff60_80,$eff80_100"
    
    # Pattern analysis
    $patternData = $Alerts | ForEach-Object { $_.Reasons -split '; ' } | 
        Group-Object | 
        Sort-Object Count -Descending | 
        Select-Object -First 8
    $patternLabels = ($patternData | ForEach-Object { 
        $label = $_.Name -replace "'", ""
        "'$label'"
    }) -join ','
    $patternCounts = ($patternData | ForEach-Object { $_.Count }) -join ','
    
    Write-Host "    [*] Building HTML structure..." -ForegroundColor White
    
    # ═══════════════════════════════════════════════════════════════
    # BUILD HTML (PART 1 - HEADER AND STYLES)
    # ═══════════════════════════════════════════════════════════════
    
    $monitoringPeriod = "$($firstTime.ToString('HH:mm')) - $($lastTime.ToString('HH:mm')) ($([math]::Round($timeSpan.TotalMinutes, 1)) min)"
    
    $htmlPart1 = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BloodHound Detection Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .subtitle { font-size: 1.1em; opacity: 0.9; }
        .executive-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; border-bottom: 3px solid #e9ecef; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #667eea; transition: transform 0.2s; }
        .metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .metric-card.critical { border-left-color: #dc3545; }
        .metric-card.high { border-left-color: #fd7e14; }
        .metric-card.medium { border-left-color: #ffc107; }
        .metric-value { font-size: 2.5em; font-weight: bold; color: #667eea; margin: 10px 0; }
        .metric-card.critical .metric-value { color: #dc3545; }
        .metric-card.high .metric-value { color: #fd7e14; }
        .metric-card.medium .metric-value { color: #ffc107; }
        .metric-label { font-size: 0.9em; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; }
        .metric-subtext { font-size: 0.85em; color: #6c757d; margin-top: 5px; }
        .detection-efficacy { padding: 30px; background: white; }
        .section-title { font-size: 1.8em; color: #1e3c72; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e9ecef; }
        .efficacy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .efficacy-item { padding: 15px; border-radius: 8px; text-align: center; font-weight: bold; }
        .efficacy-signature { background: #e3f2fd; color: #1976d2; }
        .efficacy-statistical { background: #f3e5f5; color: #7b1fa2; }
        .efficacy-hybrid { background: #fff3e0; color: #f57c00; }
        .threat-sources { padding: 30px; background: #f8f9fa; }
        .threat-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .threat-table th { background: #1e3c72; color: white; padding: 15px; text-align: left; font-weight: 600; }
        .threat-table td { padding: 12px 15px; border-bottom: 1px solid #e9ecef; }
        .threat-table tr:hover { background: #f8f9fa; }
        .rank-badge { display: inline-block; width: 30px; height: 30px; line-height: 30px; text-align: center; border-radius: 50%; font-weight: bold; color: white; background: #667eea; }
        .rank-badge.rank-1 { background: #dc3545; }
        .rank-badge.rank-2 { background: #fd7e14; }
        .rank-badge.rank-3 { background: #ffc107; color: #333; }
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 30px; padding: 30px; background: white; }
        .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .chart-title { font-size: 1.2em; color: #1e3c72; margin-bottom: 15px; font-weight: 600; }
        .alerts-section { padding: 30px; background: #f8f9fa; }
        .filter-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 10px 20px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all 0.2s; background: white; color: #333; }
        .filter-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .filter-btn.active { color: white; }
        .filter-btn.all { background: #667eea; color: white; }
        .filter-btn.critical { background: #dc3545; color: white; }
        .filter-btn.high { background: #fd7e14; color: white; }
        .filter-btn.medium { background: #ffc107; }
        .alerts-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .alerts-table th { background: #1e3c72; color: white; padding: 12px; text-align: left; font-weight: 600; font-size: 0.9em; }
        .alerts-table td { padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-size: 0.85em; }
        .alerts-table tr:hover { background: #f8f9fa; }
        .severity-badge { padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 0.75em; text-transform: uppercase; display: inline-block; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #333; }
        .score-badge { font-weight: bold; color: #667eea; }
        .efficiency-low { color: #dc3545; font-weight: bold; }
        .efficiency-medium { color: #ffc107; font-weight: bold; }
        .efficiency-high { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ BloodHound Detection Report</h1>
            <div class="subtitle">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Monitoring Period: $monitoringPeriod</div>
        </div>
        
        <div class="executive-summary">
            <div class="metric-card">
                <div class="metric-label">Total Alerts</div>
                <div class="metric-value">$totalAlerts</div>
                <div class="metric-subtext">All severity levels</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical</div>
                <div class="metric-value">$criticalAlerts</div>
                <div class="metric-subtext">$([math]::Round(($criticalAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card high">
                <div class="metric-label">High</div>
                <div class="metric-value">$highAlerts</div>
                <div class="metric-subtext">$([math]::Round(($highAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card medium">
                <div class="metric-label">Medium</div>
                <div class="metric-value">$mediumAlerts</div>
                <div class="metric-subtext">$([math]::Round(($mediumAlerts/$totalAlerts)*100, 1))% of total</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Attack Velocity</div>
                <div class="metric-value">$attackVelocity</div>
                <div class="metric-subtext">alerts per minute</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Attack Bursts</div>
                <div class="metric-value">$burstCount</div>
                <div class="metric-subtext">5+ alerts in 2 min</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Avg Efficiency</div>
                <div class="metric-value">$avgEfficiency%</div>
                <div class="metric-subtext">Query efficiency</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Unique Clients</div>
                <div class="metric-value">$($topThreats.Count)</div>
                <div class="metric-subtext">Top threat sources</div>
            </div>
        </div>
        
        <div class="detection-efficacy">
            <div class="section-title">🎯 Detection Efficacy Analysis</div>
            <div class="efficacy-grid">
                <div class="efficacy-item efficacy-signature">
                    <div style="font-size: 2em;">$signatureDetections</div>
                    <div>Signature-Based ($signaturePercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Known patterns</div>
                </div>
                <div class="efficacy-item efficacy-statistical">
                    <div style="font-size: 2em;">$statisticalDetections</div>
                    <div>Statistical ($statisticalPercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Behavioral anomalies</div>
                </div>
                <div class="efficacy-item efficacy-hybrid">
                    <div style="font-size: 2em;">$hybridDetections</div>
                    <div>Hybrid ($hybridPercent%)</div>
                    <div style="font-size: 0.8em; margin-top: 5px; opacity: 0.8;">Combined detection</div>
                </div>
            </div>
        </div>
        
        <div class="threat-sources">
            <div class="section-title">🎯 Top 5 Threat Sources</div>
            <table class="threat-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Client IP</th>
                        <th>Total Alerts</th>
                        <th>Avg Score</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
"@

    # Build threat table rows
    $threatRows = ""
    $rank = 1
    foreach ($threat in $topThreats) {
        $riskLevel = if ($threat.AvgScore -ge 0.85) { "CRITICAL" } elseif ($threat.AvgScore -ge 0.60) { "HIGH" } else { "MEDIUM" }
        $riskClass = $riskLevel.ToLower()
        
        $threatRows += @"
                    <tr>
                        <td><span class="rank-badge rank-$rank">$rank</span></td>
                        <td><strong>$($threat.Client)</strong></td>
                        <td>$($threat.Alerts) alerts</td>
                        <td class="score-badge">$($threat.AvgScore)</td>
                        <td><span class="severity-badge severity-$riskClass">$riskLevel</span></td>
                    </tr>
"@
        $rank++
    }

    $htmlPart2 = @"
                </tbody>
            </table>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <div class="chart-title">📈 Alert Timeline</div>
                <canvas id="timelineChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">📊 Severity Distribution</div>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🎯 Top Clients by Alert Count</div>
                <canvas id="clientsChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🔍 Detection Method Breakdown</div>
                <canvas id="detectionChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">⚡ Query Efficiency Distribution</div>
                <canvas id="efficiencyChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">🔎 Top Detection Patterns</div>
                <canvas id="patternsChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="section-title">📋 Detailed Alert Log</div>
            <div class="filter-buttons">
                <button class="filter-btn all active" onclick="filterAlerts('all')">All Alerts ($totalAlerts)</button>
                <button class="filter-btn critical" onclick="filterAlerts('critical')">Critical ($criticalAlerts)</button>
                <button class="filter-btn high" onclick="filterAlerts('high')">High ($highAlerts)</button>
                <button class="filter-btn medium" onclick="filterAlerts('medium')">Medium ($mediumAlerts)</button>
            </div>
            <table class="alerts-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Client</th>
                        <th>Efficiency</th>
                        <th>Detection Reasons</th>
                        <th>LDAP Filter</th>
                    </tr>
                </thead>
                <tbody id="alertsTableBody">
"@

    Write-Host "    [*] Building alert table rows..." -ForegroundColor White
    
    # Build alert rows
    $alertRows = ""
    foreach ($alert in $Alerts) {
        try {
            $time = Parse-Timestamp $alert.Timestamp
            $timeStr = $time.ToString('HH:mm:ss')
            $severityClass = $alert.Severity.ToLower()
            $efficiencyClass = if ($alert.Efficiency -lt 30) { 'efficiency-low' } elseif ($alert.Efficiency -lt 70) { 'efficiency-medium' } else { 'efficiency-high' }
            
            $alertRows += @"
                    <tr data-severity="$severityClass">
                        <td>$timeStr</td>
                        <td><span class="severity-badge severity-$severityClass">$($alert.Severity)</span></td>
                        <td class="score-badge">$($alert.Score)</td>
                        <td>$($alert.Client)</td>
                        <td class="$efficiencyClass">$($alert.Efficiency)%</td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="$($alert.Reasons)">$($alert.Reasons)</td>
                        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.8em;" title="$($alert.Filter)">$($alert.Filter)</td>
                    </tr>
"@
        } catch {
            Write-Host "    [!] Warning: Skipped alert with invalid timestamp" -ForegroundColor Yellow
        }
    }

    Write-Host "    [*] Building charts and scripts..." -ForegroundColor White

    $htmlPart3 = @"
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: [$timelineLabelsStr],
                datasets: [{
                    label: 'Alert Score',
                    data: [$timelineScoresStr],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Threat Score' } },
                    x: { title: { display: true, text: 'Time' }, ticks: { maxRotation: 45, minRotation: 45 } }
                }
            }
        });
        
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium'],
                datasets: [{
                    data: [$criticalAlerts, $highAlerts, $mediumAlerts],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'bottom' } }
            }
        });
        
        new Chart(document.getElementById('clientsChart'), {
            type: 'bar',
            data: {
                labels: [$clientLabels],
                datasets: [{
                    label: 'Alert Count',
                    data: [$clientCounts],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, title: { display: true, text: 'Number of Alerts' } } }
            }
        });
        
        new Chart(document.getElementById('detectionChart'), {
            type: 'pie',
            data: {
                labels: ['Signature', 'Statistical', 'Hybrid'],
                datasets: [{
                    data: [$signatureDetections, $statisticalDetections, $hybridDetections],
                    backgroundColor: ['#1976d2', '#7b1fa2', '#f57c00'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'bottom' } }
            }
        });
        
        new Chart(document.getElementById('efficiencyChart'), {
            type: 'bar',
            data: {
                labels: ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%'],
                datasets: [{
                    label: 'Query Count',
                    data: [$efficiencyValues],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Number of Queries' } },
                    x: { title: { display: true, text: 'Efficiency Range' } }
                }
            }
        });
        
        new Chart(document.getElementById('patternsChart'), {
            type: 'bar',
            data: {
                labels: [$patternLabels],
                datasets: [{
                    label: 'Detection Count',
                    data: [$patternCounts],
                    backgroundColor: '#667eea',
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, title: { display: true, text: 'Frequency' } } }
            }
        });
        
        function filterAlerts(severity) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('#alertsTableBody tr').forEach(row => {
                if (severity === 'all') {
                    row.style.display = '';
                } else {
                    row.style.display = row.getAttribute('data-severity') === severity ? '' : 'none';
                }
            });
        }
    </script>
</body>
</html>
"@

    # Combine all HTML parts
    $finalHtml = $htmlPart1 + $threatRows + $htmlPart2 + $alertRows + $htmlPart3
    
    Write-Host "    [*] Writing HTML to file..." -ForegroundColor White
    
    # Write to file
    $finalHtml | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "    [✓] Enhanced report generated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "           ENHANCED HTML REPORT GENERATED SUCCESSFULLY              " -ForegroundColor Green  
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "      Report Location:" -ForegroundColor Cyan
    Write-Host "         $OutputPath" -ForegroundColor White
    Write-Host ""
    Write-Host "      Report Features:" -ForegroundColor Cyan
    Write-Host "         • Executive Summary with 8 Key Metrics" -ForegroundColor Gray
    Write-Host "         • Detection Efficacy Analysis" -ForegroundColor Gray
    Write-Host "         • Top 5 Threat Clients Ranking" -ForegroundColor Gray
    Write-Host "         • 6 Interactive Charts (Chart.js)" -ForegroundColor Gray
    Write-Host "         • Interactive Alert Filtering" -ForegroundColor Gray
    Write-Host "         • Detailed Alert Table" -ForegroundColor Gray
    Write-Host ""
    Write-Host "      Report Statistics:" -ForegroundColor Yellow
    Write-Host "         • $burstCount attack bursts detected" -ForegroundColor Gray
    Write-Host "         • $($topThreats.Count) high-risk clients identified" -ForegroundColor Gray
    Write-Host "         • $totalAlerts total alerts analyzed" -ForegroundColor Gray
    Write-Host "         • $attackVelocity alerts/min attack velocity" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "    Press Enter to continue..." -ForegroundColor Cyan -NoNewline
    $null = Read-Host
}

function Export-CSVReport {
    param([array]$Alerts)
    
    Clear-Host
    Write-Host ""
    Write-Host "    [*] Generating CSV report..." -ForegroundColor Cyan
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = "C:\Windows\debug\BloodHound_Report_$timestamp.csv"
    
    $Alerts | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "    [✓] CSV report saved to: " -NoNewline -ForegroundColor Green
    Write-Host $outputPath -ForegroundColor Cyan
}


function New-EnhancedDFIRReport {
    <#
    .SYNOPSIS
        Enhanced DFIR Report with Level 3 Triage Raw Data
    
    .DESCRIPTION
        Generates comprehensive DFIR report including:
        - Executive summary
        - Alert summaries
        - RAW Event ID 1644 properties for each alert
        - Complete forensic context
        - Timeline analysis
        - Recommendations
    
    .PARAMETER Alerts
        Array of alert objects from bloodhound_alerts.log
    
    .PARAMETER IncludeRawEvents
        Include raw Event ID 1644 properties for Level 3 triage (default: $true)
    
    .PARAMETER OutputFormat
        Report format: Text, HTML, Both (default: Both)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Alerts,
        
        [Parameter(Mandatory=$false)]
        [bool]$IncludeRawEvents = $true,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Text', 'HTML', 'Both')]
        [string]$OutputFormat = 'Both'
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$PSScriptRoot\DFIR_Report_Enhanced_$timestamp.txt"
    $htmlPath = "$PSScriptRoot\DFIR_Report_Enhanced_$timestamp.html"
    
    Write-Host ""
    Write-Host "    Generating Enhanced DFIR Report with Level 3 Triage Data..." -ForegroundColor Cyan
    Write-Host ""
    
    # ═══════════════════════════════════════════════════════════
    # PART 1: COLLECT FORENSIC DATA
    # ═══════════════════════════════════════════════════════════
    
    Write-Host "    [1/4] Analyzing alerts..." -ForegroundColor Cyan
    
    # Alert statistics
    $criticalAlerts = @($Alerts | Where-Object { $_.Severity -eq 'CRITICAL' })
    $highAlerts = @($Alerts | Where-Object { $_.Severity -eq 'HIGH' })
    $mediumAlerts = @($Alerts | Where-Object { $_.Severity -eq 'MEDIUM' })
    $lowAlerts = @($Alerts | Where-Object { $_.Severity -eq 'LOW' })
    
    $uniqueClients = $Alerts | Select-Object -ExpandProperty Client -Unique
    $timespan = if ($Alerts.Count -gt 0) {
        $firstAlert = ($Alerts | Sort-Object Timestamp | Select-Object -First 1).Timestamp
        $lastAlert = ($Alerts | Sort-Object Timestamp | Select-Object -Last 1).Timestamp
        [datetime]$lastAlert - [datetime]$firstAlert
    } else {
        [timespan]::Zero
    }
    
    # ═══════════════════════════════════════════════════════════
    # PART 2: FETCH RAW EVENT ID 1644 DATA
    # ═══════════════════════════════════════════════════════════
    
    $rawEventData = @{}
    
    if ($IncludeRawEvents) {
        Write-Host "    [2/4] Fetching raw Event ID 1644 data for Level 3 triage..." -ForegroundColor Cyan
        
        try {
            # Get all events within the alert timeframe
            $startTime = ($Alerts | Sort-Object Timestamp | Select-Object -First 1).Timestamp
            $endTime = ($Alerts | Sort-Object Timestamp | Select-Object -Last 1).Timestamp
            
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Directory Service'
                ID = 1644
                StartTime = [datetime]$startTime
                EndTime = ([datetime]$endTime).AddMinutes(1)
            } -ErrorAction SilentlyContinue
            
            Write-Host "        Found $($events.Count) raw events in timeframe" -ForegroundColor Green
            
            # Index events by timestamp and client IP for matching
            foreach ($event in $events) {
                $props = $event.Properties
                if ($props.Count -ge 5) {
                    $clientIPRaw = $props[4].Value
                    $eventTime = $event.TimeCreated
                    
                    # Parse IP for matching
                    $clientIP = $null
                    if ($clientIPRaw -match '^\[([0-9a-fA-F:]+(?:%\d+)?)\]:\d+$') {
                        $clientIP = $matches[1]
                    } elseif ($clientIPRaw -match '^([0-9a-fA-F:]+):\d+$' -and $clientIPRaw -match '::') {
                        $clientIP = $matches[1]
                    } elseif ($clientIPRaw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$') {
                        $clientIP = $matches[1]
                    } elseif ($clientIPRaw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        $clientIP = $clientIPRaw
                    }
                    
                    if ($clientIP) {
                        $key = "$clientIP|$($eventTime.ToString('yyyy-MM-ddTHH:mm:ss'))"
                        $rawEventData[$key] = @{
                            Event = $event
                            Properties = $props
                            ClientIP = $clientIP
                        }
                    }
                }
            }
            
        } catch {
            Write-Host "        Warning: Could not fetch raw events: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [2/4] Skipping raw event data (not requested)..." -ForegroundColor Yellow
    }
    
    # ═══════════════════════════════════════════════════════════
    # PART 3: GENERATE TEXT REPORT
    # ═══════════════════════════════════════════════════════════
    
    if ($OutputFormat -eq 'Text' -or $OutputFormat -eq 'Both') {
        Write-Host "    [3/4] Generating text report..." -ForegroundColor Cyan
        
        $report = @"
================================================================================
DIGITAL FORENSICS AND INCIDENT RESPONSE (DFIR) REPORT
BloodHound Detection Analysis - Event ID 1644 LDAP Monitoring
ENHANCED REPORT WITH LEVEL 3 TRIAGE DATA
================================================================================

REPORT GENERATED: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
ANALYST: $env:USERNAME
DOMAIN CONTROLLER: $env:COMPUTERNAME
REPORT TYPE: Enhanced Forensic Analysis

================================================================================
EXECUTIVE SUMMARY
================================================================================

Total Alerts: $($Alerts.Count)
Critical: $($criticalAlerts.Count)
High: $($highAlerts.Count)
Medium: $($mediumAlerts.Count)
Low: $($lowAlerts.Count)

Unique Clients: $($uniqueClients.Count)
Time Span: $([Math]::Round($timespan.TotalHours, 2)) hours
First Alert: $($Alerts | Sort-Object Timestamp | Select-Object -First 1 | ForEach-Object { $_.Timestamp })
Last Alert: $($Alerts | Sort-Object Timestamp | Select-Object -Last 1 | ForEach-Object { $_.Timestamp })

THREAT ASSESSMENT: $(if ($criticalAlerts.Count -gt 10) { "CRITICAL - Active BloodHound enumeration detected" } elseif ($criticalAlerts.Count -gt 0) { "HIGH - Suspicious LDAP activity" } else { "MEDIUM - Monitoring recommended" })

================================================================================
SYSTEM INFORMATION
================================================================================

Computer: $env:COMPUTERNAME
Domain: $env:USERDNSDOMAIN
OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Build: $([System.Environment]::OSVersion.Version.Build)
Memory: $([Math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)) GB

================================================================================
AFFECTED CLIENTS
================================================================================

"@
        
        foreach ($client in $uniqueClients) {
            $clientAlerts = @($Alerts | Where-Object { $_.Client -eq $client })
            $clientCritical = @($clientAlerts | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
            $clientHigh = @($clientAlerts | Where-Object { $_.Severity -eq 'HIGH' }).Count
            
            $report += @"
Client: $client
  Total Alerts: $($clientAlerts.Count)
  Critical: $clientCritical
  High: $clientHigh
  Risk Level: $(if ($clientCritical -gt 5) { "CRITICAL" } elseif ($clientCritical -gt 0) { "HIGH" } else { "MEDIUM" })

"@
        }
        
        $report += @"

================================================================================
DETAILED FORENSIC ANALYSIS (LEVEL 3 TRIAGE)
================================================================================

"@
        
        # Sort alerts by timestamp (most recent first) and limit to top 50 for readability
        $sortedAlerts = $Alerts | Sort-Object Timestamp -Descending | Select-Object -First 50
        
        $alertNum = 1
        foreach ($alert in $sortedAlerts) {
            $report += @"
────────────────────────────────────────────────────────────────────────────────
ALERT #$alertNum - $($alert.Timestamp)
────────────────────────────────────────────────────────────────────────────────

SUMMARY:
  Severity: $($alert.Severity)
  Client: $($alert.Client)
  Score: $($alert.Score)
  Efficiency: $($alert.Efficiency)%
  
DETECTION REASONS:
"@
            foreach ($reason in $alert.Reasons) {
                $report += "  • $reason`n"
            }
            
            $report += @"

LDAP QUERY DETAILS:
  Filter: $($alert.Filter)
  Visited Entries: $($alert.VisitedEntries)
  Returned Entries: $($alert.ReturnedEntries)
  Pages Referenced: $($alert.PagesReferenced)

"@
            
            # ═══════════════════════════════════════════════════════════
            # ADD RAW EVENT ID 1644 PROPERTIES FOR LEVEL 3 TRIAGE
            # ═══════════════════════════════════════════════════════════
            
            if ($IncludeRawEvents) {
                # Try to find matching raw event
                $alertTime = [datetime]$alert.Timestamp
                $key = "$($alert.Client)|$($alertTime.ToString('yyyy-MM-ddTHH:mm:ss'))"
                
                if ($rawEventData.ContainsKey($key)) {
                    $rawEvent = $rawEventData[$key]
                    $props = $rawEvent.Properties
                    
                    $report += @"
RAW EVENT ID 1644 PROPERTIES (Full Forensic Context):
┌─────────────────────────────────────────────────────────────────────────────┐
│ PROPERTY INDEX  │  VALUE                                                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
"@
                    
                    for ($i = 0; $i -lt $props.Count; $i++) {
                        $value = if ($props[$i].Value) {
                            $v = $props[$i].Value.ToString()
                            if ($v.Length -gt 60) { $v.Substring(0, 57) + "..." } else { $v }
                        } else {
                            "(null)"
                        }
                        
                        $report += "│ [$("{0:D2}" -f $i)]            │ $($value.PadRight(62)) │`n"
                    }
                    
                    $report += @"
└─────────────────┴───────────────────────────────────────────────────────────┘

FIELD MAPPING (Event ID 1644):
  [00] = Starting Node (Search Base)
  [01] = Filter
  [02] = Visited Entries
  [03] = Returned Entries  
  [04] = Client IP (with port)
  [05] = Search Scope (base/onelevel/subtree)
  [06] = Attributes Requested
  [07] = Server Controls
  [08] = Used Indexes
  [09] = Pages Referenced
  [10] = Pages Read From Disk
  [11] = Pages Pre-read From Disk
  [12] = Clean Pages Modified
  [13] = Dirty Pages Modified
  [14] = Search Time (ms)
  [15] = Attributes Prevented From Being Returned
  [16] = Calling User

FORENSIC NOTES:
"@
                    
                    # Add forensic interpretation
                    if ($props.Count -ge 9) {
                        $searchBase = $props[0].Value
                        $filter = $props[1].Value
                        $scope = if ($props.Count -gt 5) { $props[5].Value } else { "N/A" }
                        $attributes = if ($props.Count -gt 6) { $props[6].Value } else { "N/A" }
                        $indexes = if ($props.Count -gt 8) { $props[8].Value } else { "N/A" }
                        $pagesRef = if ($props.Count -gt 9) { $props[9].Value } else { "N/A" }
                        
                        $report += "  • Search Base: $searchBase`n"
                        $report += "  • Scope: $scope`n"
                        
                        if ($attributes -eq "*" -or $attributes -match ".*\*.*") {
                            $report += "  • ⚠️  All attributes requested (wildcard) - BloodHound signature`n"
                        } else {
                            $attrCount = ($attributes -split ',').Count
                            $report += "  • Attributes: $attrCount requested`n"
                        }
                        
                        if ($indexes -eq "(null)" -or [string]::IsNullOrWhiteSpace($indexes)) {
                            $report += "  • ⚠️  No indexes used - table scan (inefficient)`n"
                        } else {
                            $report += "  • Indexes: $indexes`n"
                        }
                        
                        if ($filter -match "SDFlags|1.2.840.113556.1.4.801") {
                            $report += "  • 🚨 CRITICAL: SDFlags detected - ACL enumeration (BloodHound)`n"
                        }
                        
                        if ($filter -match "sAMAccountType") {
                            $report += "  • 🚨 sAMAccountType query - targeting users/groups`n"
                        }
                        
                        if ($filter -match "objectClass=\*|^\(\*\)$") {
                            $report += "  • 🚨 CRITICAL: Wildcard objectClass - mass enumeration`n"
                        }
                    }
                    
                    $report += "`n"
                    
                } else {
                    $report += @"
RAW EVENT ID 1644 PROPERTIES:
  (Raw event data not available for this alert)
  This may occur if events were logged outside the analysis timeframe.

"@
                }
            }
            
            $report += "`n"
            $alertNum++
        }
        
        if ($Alerts.Count -gt 50) {
            $report += @"
────────────────────────────────────────────────────────────────────────────────
NOTE: Report truncated to 50 most recent alerts for readability.
Total alerts in dataset: $($Alerts.Count)
────────────────────────────────────────────────────────────────────────────────

"@
        }
        
        $report += @"

================================================================================
THREAT ANALYSIS & INDICATORS
================================================================================

BLOODHOUND SIGNATURES DETECTED:
"@
        
        $sdFlagsCount = @($Alerts | Where-Object { $_.Reasons -match "SDFlags" }).Count
        $zeroEffCount = @($Alerts | Where-Object { $_.Reasons -match "Zero efficiency" }).Count
        $adcsCount = @($Alerts | Where-Object { $_.Reasons -match "ADCS|PKI" }).Count
        $samTypeCount = @($Alerts | Where-Object { $_.Reasons -match "sAMAccountType" }).Count
        $wildcardCount = @($Alerts | Where-Object { $_.Reasons -match "Base scope" }).Count
        
        $report += @"
  • SDFlags ACL Enumeration: $sdFlagsCount alerts
  • Zero Efficiency Queries: $zeroEffCount alerts
  • ADCS/PKI Enumeration: $adcsCount alerts
  • sAMAccountType Queries: $samTypeCount alerts
  • Base Scope Enumerations: $wildcardCount alerts

ATTACK PATTERNS:
"@
        
        if ($sdFlagsCount -gt 0) {
            $report += "  🚨 Active Directory permission mapping (BloodHound SharpHound)`n"
        }
        if ($adcsCount -gt 0) {
            $report += "  🚨 Certificate Services enumeration (ESC1-ESC8 attack prep)`n"
        }
        if ($samTypeCount -gt 0) {
            $report += "  🚨 User and group targeting for privilege escalation`n"
        }
        if ($zeroEffCount -gt 0) {
            $report += "  🚨 Inefficient queries indicate automated tooling`n"
        }
        
        $report += @"

================================================================================
RECOMMENDATIONS
================================================================================

IMMEDIATE ACTIONS:
  1. Investigate source IP(s): $($uniqueClients -join ', ')
  2. Review user accounts associated with suspicious activity
  3. Check for SharpHound.exe, BloodHound, or similar tools on source systems
  4. Verify if this is authorized security assessment activity
  5. Consider blocking source IPs if malicious activity confirmed

FORENSIC INVESTIGATION:
  1. Collect process memory from source systems
  2. Review Windows Security event logs for logon sessions
  3. Check for persistence mechanisms (scheduled tasks, services)
  4. Analyze network traffic for data exfiltration
  5. Review RAW Event ID 1644 properties above for detailed forensic analysis

HARDENING:
  1. Implement LDAP query rate limiting
  2. Enable advanced AD auditing (4662 events)
  3. Deploy EDR solutions on workstations
  4. Restrict LDAP anonymous binds
  5. Monitor for SharpHound indicators continuously

================================================================================
REPORT END
================================================================================
Generated by BloodHound Detector v2.7.5
Report includes Level 3 Triage data with RAW Event ID 1644 properties
"@
        
        # Save text report
        $report | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "        ✓ Text report saved: $reportPath" -ForegroundColor Green
    }
    
    # ═══════════════════════════════════════════════════════════
    # PART 4: GENERATE HTML REPORT (if requested)
    # ═══════════════════════════════════════════════════════════

if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'Both') {
    Write-Host "    [4/4] Generating comprehensive HTML report..." -ForegroundColor Cyan
    
    # Generate full HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DFIR Report - BloodHound Detection Analysis</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        
        .header h1::before {
            content: '🔍';
            margin-right: 15px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .exec-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-box {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-box.critical {
            background: #fee;
            border-left: 4px solid #e74c3c;
        }
        
        .stat-box.high {
            background: #fef3e0;
            border-left: 4px solid #e67e22;
        }
        
        .stat-box.info {
            background: #e8f4f8;
            border-left: 4px solid #3498db;
        }
        
        .stat-box .number {
            font-size: 3em;
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
        }
        
        .stat-box.critical .number { color: #e74c3c; }
        .stat-box.high .number { color: #e67e22; }
        .stat-box.info .number { color: #3498db; }
        
        .stat-box .label {
            font-size: 0.9em;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .threat-level {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 1.2em;
        }
        
        .threat-level.critical {
            background: #e74c3c;
            color: white;
        }
        
        .alert-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 25px;
            overflow: hidden;
            transition: box-shadow 0.3s;
        }
        
        .alert-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .alert-card.critical {
            border-left: 5px solid #e74c3c;
        }
        
        .alert-card.high {
            border-left: 5px solid #e67e22;
        }
        
        .alert-card.medium {
            border-left: 5px solid #f39c12;
        }
        
        .alert-header {
            padding: 15px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .alert-title {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .severity-badge.critical {
            background: #e74c3c;
            color: white;
        }
        
        .severity-badge.high {
            background: #e67e22;
            color: white;
        }
        
        .alert-body {
            padding: 20px;
        }
        
        .alert-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .alert-detail {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .alert-detail .label {
            font-size: 0.85em;
            color: #7f8c8d;
            display: block;
            margin-bottom: 5px;
        }
        
        .alert-detail .value {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .reasons {
            background: #fff3cd;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        
        .reasons ul {
            list-style-position: inside;
            margin-left: 10px;
        }
        
        .reasons li {
            margin-bottom: 5px;
        }
        
        .raw-data {
            background: #2c3e50;
            color: #0f0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 20px 0;
        }
        
        .raw-data table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .raw-data td {
            padding: 5px 10px;
            border-bottom: 1px solid #34495e;
        }
        
        .raw-data td:first-child {
            color: #3498db;
            width: 120px;
        }
        
        .forensic-notes {
            background: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }
        
        .forensic-notes .note {
            margin-bottom: 8px;
        }
        
        .forensic-notes .warning {
            color: #e67e22;
            font-weight: bold;
        }
        
        .forensic-notes .critical {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .threat-matrix {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .threat-indicator {
            padding: 15px;
            border-radius: 8px;
            background: #fff;
            border: 2px solid #ddd;
        }
        
        .threat-indicator .count {
            font-size: 2em;
            font-weight: bold;
            color: #e74c3c;
            display: block;
        }
        
        .threat-indicator .name {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .recommendations {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        
        .recommendations h3 {
            color: #155724;
            margin-bottom: 15px;
        }
        
        .recommendations ol {
            margin-left: 25px;
        }
        
        .recommendations li {
            margin-bottom: 10px;
        }
        
        .clients-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .clients-table th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }
        
        .clients-table td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        
        .clients-table tr:hover {
            background: #f8f9fa;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .risk-badge.critical {
            background: #e74c3c;
            color: white;
        }
        
        .risk-badge.high {
            background: #e67e22;
            color: white;
        }
        
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: #34495e;
            color: white;
            border: none;
            text-align: left;
            width: 100%;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 1em;
        }
        
        .collapsible:hover {
            background: #2c3e50;
        }
        
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        
        .collapsible-content.active {
            max-height: 2000px;
        }
        
        @media print {
            body { background: white; }
            .section { box-shadow: none; page-break-inside: avoid; }
            .alert-card { page-break-inside: avoid; }
            .collapsible { display: none; }
            .collapsible-content { max-height: none !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DFIR Report - BloodHound Detection Analysis</h1>
            <p>Enhanced Report with Level 3 Triage Data</p>
            <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Analyst: $env:USERNAME | DC: $env:COMPUTERNAME</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="exec-summary">
                <div class="stat-box info">
                    <span class="number">$($Alerts.Count)</span>
                    <span class="label">Total Alerts</span>
                </div>
                <div class="stat-box critical">
                    <span class="number">$($criticalAlerts.Count)</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat-box high">
                    <span class="number">$($highAlerts.Count)</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-box info">
                    <span class="number">$($uniqueClients.Count)</span>
                    <span class="label">Unique Clients</span>
                </div>
            </div>
            <p><strong>Time Span:</strong> $([Math]::Round($timespan.TotalHours, 2)) hours</p>
            <p><strong>First Alert:</strong> $($Alerts | Sort-Object Timestamp | Select-Object -First 1 | ForEach-Object { $_.Timestamp })</p>
            <p><strong>Last Alert:</strong> $($Alerts | Sort-Object Timestamp | Select-Object -Last 1 | ForEach-Object { $_.Timestamp })</p>
            <p style="margin-top: 20px;"><strong>Threat Assessment:</strong> 
                <span class="threat-level $(if ($criticalAlerts.Count -gt 10) { 'critical' })">
                    $(if ($criticalAlerts.Count -gt 10) { "CRITICAL - Active BloodHound enumeration detected" } elseif ($criticalAlerts.Count -gt 0) { "HIGH - Suspicious LDAP activity" } else { "MEDIUM - Monitoring recommended" })
                </span>
            </p>
        </div>
        
        <div class="section">
            <h2>Affected Clients</h2>
            <table class="clients-table">
                <thead>
                    <tr>
                        <th>Client IP</th>
                        <th>Total Alerts</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
"@
    
    foreach ($client in $uniqueClients) {
        $clientAlerts = @($Alerts | Where-Object { $_.Client -eq $client })
        $clientCritical = @($clientAlerts | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
        $clientHigh = @($clientAlerts | Where-Object { $_.Severity -eq 'HIGH' }).Count
        $riskLevel = if ($clientCritical -gt 5) { "CRITICAL" } elseif ($clientCritical -gt 0) { "HIGH" } else { "MEDIUM" }
        
        $htmlContent += @"
                    <tr>
                        <td><strong>$client</strong></td>
                        <td>$($clientAlerts.Count)</td>
                        <td>$clientCritical</td>
                        <td>$clientHigh</td>
                        <td><span class="risk-badge $(if ($riskLevel -eq 'CRITICAL') { 'critical' } else { 'high' })">$riskLevel</span></td>
                    </tr>
"@
    }
    
    $htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Detailed Forensic Analysis</h2>
            <p style="margin-bottom: 20px;">Top 50 most recent alerts with complete Event ID 1644 forensic data:</p>
"@
    
    # Generate alert cards
    $sortedAlerts = $Alerts | Sort-Object Timestamp -Descending | Select-Object -First 50
    $alertNum = 1
    
    foreach ($alert in $sortedAlerts) {
        $severityClass = $alert.Severity.ToLower()
        
        $htmlContent += @"
            <div class="alert-card $severityClass">
                <div class="alert-header">
                    <div class="alert-title">Alert #$alertNum - $($alert.Timestamp)</div>
                    <span class="severity-badge $severityClass">$($alert.Severity)</span>
                </div>
                <div class="alert-body">
                    <div class="alert-summary">
                        <div class="alert-detail">
                            <span class="label">Client</span>
                            <span class="value">$($alert.Client)</span>
                        </div>
                        <div class="alert-detail">
                            <span class="label">Score</span>
                            <span class="value">$($alert.Score)</span>
                        </div>
                        <div class="alert-detail">
                            <span class="label">Efficiency</span>
                            <span class="value">$($alert.Efficiency)%</span>
                        </div>
                        <div class="alert-detail">
                            <span class="label">Pages Referenced</span>
                            <span class="value">$($alert.PagesReferenced)</span>
                        </div>
                    </div>
                    
                    <div class="reasons">
                        <strong>Detection Reasons:</strong>
                        <ul>
"@
        
        foreach ($reason in $alert.Reasons) {
            $htmlContent += "                            <li>$reason</li>`n"
        }
        
        $htmlContent += @"
                        </ul>
                    </div>
                    
                    <p><strong>LDAP Filter:</strong> $($alert.Filter)</p>
                    <p><strong>Visited Entries:</strong> $($alert.VisitedEntries) | <strong>Returned:</strong> $($alert.ReturnedEntries)</p>
"@
        
        # Add raw event data if available
        $alertTime = [datetime]$alert.Timestamp
        $key = "$($alert.Client)|$($alertTime.ToString('yyyy-MM-ddTHH:mm:ss'))"
        
        if ($rawEventData.ContainsKey($key)) {
            $rawEvent = $rawEventData[$key]
            $props = $rawEvent.Properties
            
            $htmlContent += @"
                    
                    <button class="collapsible" onclick="toggleCollapsible(this)">▼ RAW Event ID 1644 Properties (Level 3 Triage)</button>
                    <div class="collapsible-content">
                        <div class="raw-data">
                            <table>
"@
            
            for ($i = 0; $i -lt [Math]::Min($props.Count, 17); $i++) {
                $value = if ($props[$i].Value) {
                    $v = $props[$i].Value.ToString()
                    if ($v.Length -gt 80) { $v.Substring(0, 77) + "..." } else { $v }
                } else {
                    "(null)"
                }
                
                $htmlContent += "                                <tr><td>[$("{0:D2}" -f $i)]</td><td>$value</td></tr>`n"
            }
            
            $htmlContent += @"
                            </table>
                        </div>
                        
                        <div class="forensic-notes">
                            <strong>Forensic Notes:</strong>
"@
            
            # Add forensic interpretation
            if ($props.Count -ge 9) {
                $searchBase = $props[0].Value
                $filter = $props[1].Value
                $scope = if ($props.Count -gt 5) { $props[5].Value } else { "N/A" }
                $attributes = if ($props.Count -gt 6) { $props[6].Value } else { "N/A" }
                $indexes = if ($props.Count -gt 8) { $props[8].Value } else { "N/A" }
                
                $htmlContent += "                            <div class='note'>• Search Base: $searchBase</div>`n"
                $htmlContent += "                            <div class='note'>• Scope: $scope</div>`n"
                
                if ($attributes -eq "*" -or $attributes -match ".*\*.*") {
                    $htmlContent += "                            <div class='note warning'>⚠️  All attributes requested (wildcard) - BloodHound signature</div>`n"
                }
                
                if ($indexes -eq "(null)" -or [string]::IsNullOrWhiteSpace($indexes)) {
                    $htmlContent += "                            <div class='note warning'>⚠️  No indexes used - table scan (inefficient)</div>`n"
                } else {
                    $htmlContent += "                            <div class='note'>• Indexes: $indexes</div>`n"
                }
                
                if ($filter -match "SDFlags|1.2.840.113556.1.4.801") {
                    $htmlContent += "                            <div class='note critical'>🚨 CRITICAL: SDFlags detected - ACL enumeration (BloodHound)</div>`n"
                }
                
                if ($filter -match "sAMAccountType") {
                    $htmlContent += "                            <div class='note critical'>🚨 sAMAccountType query - targeting users/groups</div>`n"
                }
                
                if ($filter -match "objectClass=\*|^\(\*\)$") {
                    $htmlContent += "                            <div class='note critical'>🚨 CRITICAL: Wildcard objectClass - mass enumeration</div>`n"
                }
            }
            
            $htmlContent += @"
                        </div>
                    </div>
"@
        }
        
        $htmlContent += @"
                </div>
            </div>
"@
        
        $alertNum++
    }
    
    if ($Alerts.Count -gt 50) {
        $htmlContent += "<p style='text-align: center; padding: 20px; background: #fff3cd; border-radius: 5px;'><strong>Note:</strong> Report truncated to 50 most recent alerts. Total: $($Alerts.Count)</p>`n"
    }
    
    $htmlContent += @"
        </div>
        
        <div class="section">
            <h2>Threat Analysis & Indicators</h2>
            <h3>BloodHound Signatures Detected</h3>
            <div class="threat-matrix">
                <div class="threat-indicator">
                    <span class="count">$sdFlagsCount</span>
                    <span class="name">SDFlags ACL Enumeration</span>
                </div>
                <div class="threat-indicator">
                    <span class="count">$zeroEffCount</span>
                    <span class="name">Zero Efficiency Queries</span>
                </div>
                <div class="threat-indicator">
                    <span class="count">$adcsCount</span>
                    <span class="name">ADCS/PKI Enumeration</span>
                </div>
                <div class="threat-indicator">
                    <span class="count">$samTypeCount</span>
                    <span class="name">sAMAccountType Queries</span>
                </div>
                <div class="threat-indicator">
                    <span class="count">$wildcardCount</span>
                    <span class="name">Base Scope Enumerations</span>
                </div>
            </div>
            
            <h3 style="margin-top: 30px;">Attack Patterns</h3>
            <ul style="margin-left: 20px; margin-top: 15px;">
"@
    
    if ($sdFlagsCount -gt 0) {
        $htmlContent += "                <li style='margin-bottom: 10px;'>🚨 Active Directory permission mapping (BloodHound SharpHound)</li>`n"
    }
    if ($adcsCount -gt 0) {
        $htmlContent += "                <li style='margin-bottom: 10px;'>🚨 Certificate Services enumeration (ESC1-ESC8 attack prep)</li>`n"
    }
    if ($samTypeCount -gt 0) {
        $htmlContent += "                <li style='margin-bottom: 10px;'>🚨 User and group targeting for privilege escalation</li>`n"
    }
    if ($zeroEffCount -gt 0) {
        $htmlContent += "                <li style='margin-bottom: 10px;'>🚨 Inefficient queries indicate automated tooling</li>`n"
    }
    
    $htmlContent += @"
            </ul>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            
            <div class="recommendations">
                <h3>Immediate Actions</h3>
                <ol>
                    <li>Investigate source IP(s): $($uniqueClients -join ', ')</li>
                    <li>Review user accounts associated with suspicious activity</li>
                    <li>Check for SharpHound.exe, BloodHound, or similar tools on source systems</li>
                    <li>Verify if this is authorized security assessment activity</li>
                    <li>Consider blocking source IPs if malicious activity confirmed</li>
                </ol>
            </div>
            
            <div class="recommendations" style="background: #d1ecf1; border-left: 4px solid #17a2b8;">
                <h3 style="color: #0c5460;">Forensic Investigation</h3>
                <ol>
                    <li>Collect process memory from source systems</li>
                    <li>Review Windows Security event logs for logon sessions</li>
                    <li>Check for persistence mechanisms (scheduled tasks, services)</li>
                    <li>Analyze network traffic for data exfiltration</li>
                    <li>Review RAW Event ID 1644 properties above for detailed analysis</li>
                </ol>
            </div>
            
            <div class="recommendations" style="background: #cce5ff; border-left: 4px solid #004085;">
                <h3 style="color: #004085;">Hardening Recommendations</h3>
                <ol>
                    <li>Implement LDAP query rate limiting</li>
                    <li>Enable advanced AD auditing (4662 events)</li>
                    <li>Deploy EDR solutions on workstations</li>
                    <li>Restrict LDAP anonymous binds</li>
                    <li>Monitor for SharpHound indicators continuously</li>
                </ol>
            </div>
        </div>
        
        <div class="section" style="text-align: center; color: #7f8c8d;">
            <p>Report generated by BloodHound Detector v2.7.5</p>
            <p>Includes Level 3 Triage data with RAW Event ID 1644 properties</p>
            <p style="margin-top: 10px;">Text report: $reportPath</p>
        </div>
    </div>
    
    <script>
        function toggleCollapsible(element) {
            element.classList.toggle('active');
            var content = element.nextElementSibling;
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
                element.textContent = '▼ ' + element.textContent.substring(2);
            } else {
                content.style.maxHeight = content.scrollHeight + 'px';
                element.textContent = '▲ ' + element.textContent.substring(2);
            }
        }
    </script>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "        ✓ Comprehensive HTML report saved: $htmlPath" -ForegroundColor Green
}
    
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "    ✅ ENHANCED DFIR REPORT COMPLETE" -ForegroundColor Green
    Write-Host "    ═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    if ($OutputFormat -eq 'Text' -or $OutputFormat -eq 'Both') {
        Write-Host "    📄 Text Report: $reportPath" -ForegroundColor Cyan
    }
    if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'Both') {
        Write-Host "    🌐 HTML Report: $htmlPath" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "    The report includes:" -ForegroundColor White
    Write-Host "      • Executive summary" -ForegroundColor Gray
    Write-Host "      • Alert analysis" -ForegroundColor Gray
    Write-Host "      • RAW Event ID 1644 properties (Level 3 triage)" -ForegroundColor Yellow
    Write-Host "      • Complete forensic context" -ForegroundColor Gray
    Write-Host "      • Threat indicators" -ForegroundColor Gray
    Write-Host "      • Recommendations" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    Press Enter to continue..." -ForegroundColor Gray
    Read-Host
    
    return @{
        TextReport = $reportPath
        HTMLReport = $htmlPath
        AlertCount = $Alerts.Count
        CriticalCount = $criticalAlerts.Count
    }
}

#endregion

#region Status and System Functions

function Show-Status {
    <#
    .SYNOPSIS
        Display current system status
    #>
    
    Clear-Host
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "    ║                      SYSTEM STATUS                           ║" -ForegroundColor Cyan
    Write-Host "    ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    📊 Current Configuration:" -ForegroundColor Cyan
    Write-Host "    ─────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    # Event ID 1644 Status
    $diagLevel = Get-DiagnosticLevel
    Write-Host "    [*] Event ID 1644 Logging: " -NoNewline -ForegroundColor White
    if ($diagLevel -ge 2) {
        Write-Host "✓ Enabled (Level $diagLevel)" -ForegroundColor Green
    } else {
        Write-Host "✗ Disabled (Level $diagLevel)" -ForegroundColor Red
        Write-Host ""
        Write-Host "        To enable, run:" -ForegroundColor Yellow
        Write-Host '        reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" \' -ForegroundColor Gray
        Write-Host '            /v "15 Field Engineering" /t REG_DWORD /d 2 /f' -ForegroundColor Gray
    }
    Write-Host ""
    
    # Baseline Status
    Write-Host "    [*] Baseline Status: " -NoNewline -ForegroundColor White
    if (Test-Path $script:Config.BaselineFile) {
        $baseline = Get-Content $script:Config.BaselineFile | ConvertFrom-Json
        Write-Host "✓ Available" -ForegroundColor Green
        Write-Host "        Created: " -NoNewline -ForegroundColor Gray
        Write-Host $baseline.CreatedAt -ForegroundColor White
        Write-Host "        Duration: " -NoNewline -ForegroundColor Gray
        Write-Host "$($baseline.DurationHours) hours" -ForegroundColor White
    } else {
        Write-Host "✗ No baseline found" -ForegroundColor Yellow
        Write-Host "        Create one with option 1 (Build Baseline)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Alert Log Status
    Write-Host "    [*] Alert Log: " -NoNewline -ForegroundColor White
    if (Test-Path $script:Config.AlertLogFile) {
        $alertCount = (Get-Content $script:Config.AlertLogFile | Measure-Object).Count
        Write-Host "✓ Active ($alertCount alerts logged)" -ForegroundColor Green
    } else {
        Write-Host "No alerts logged yet" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Recent Activity
    Write-Host "    [*] Recent Activity: " -NoNewline -ForegroundColor White
    try {
        $latestEvent = Get-WinEvent -FilterHashtable @{
            LogName = 'Directory Service'
            ID = 1644
        } -MaxEvents 1 -ErrorAction Stop
        
        Write-Host "✓ Latest event: " -NoNewline -ForegroundColor Green
        Write-Host $latestEvent.TimeCreated -ForegroundColor White
    }
    catch {
        Write-Host "No recent events found" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    
    Pause-ForUser
}

function Show-ComprehensiveSystemDiagnostics {
    <#
    .SYNOPSIS
        Ultimate BloodHound Detector Event ID 1644 Diagnostics
    .DESCRIPTION
        Comprehensive diagnostic focused on Event ID 1644 with:
        - Event configuration validation
        - RAW property display with index numbers
        - Detailed parsing attempts (shows exactly what gets extracted)
        - IP extraction testing (all formats: IPv4, IPv6, with/without ports)
        - Skip checks (shows why events might be filtered)
        - Efficiency calculations
        - BloodHound pattern detection
        - Baseline and alert log status
    #>
    
    Clear-Host
    
    # Color scheme
    $colors = @{
        Header = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
        Info = 'White'
        Subtle = 'DarkGray'
        Highlight = 'Magenta'
        Data = 'White'
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $colors.Header
    Write-Host "║                                                              ║" -ForegroundColor $colors.Header
    Write-Host "║        🔍 BLOODHOUND DETECTOR - SYSTEM DIAGNOSTICS 🔍        ║" -ForegroundColor $colors.Header
    Write-Host "║                                                              ║" -ForegroundColor $colors.Header
    Write-Host "║              Event ID 1644 Analysis & Validation             ║" -ForegroundColor $colors.Header
    Write-Host "║                                                              ║" -ForegroundColor $colors.Header
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $colors.Header
    Write-Host ""
    Write-Host "    Running comprehensive diagnostic suite..." -ForegroundColor $colors.Info
    Write-Host "    Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $colors.Subtle
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor $colors.Subtle
    Write-Host ""
    
    # Statistics tracking
    $diagnosticStats = @{
        TotalChecks = 0
        PassedChecks = 0
        Warnings = 0
        Errors = 0
        EventsAnalyzed = 0
        ValidEvents = 0
        SkippedEvents = 0
        SuspiciousEvents = 0
        IPParseFailures = 0
        ParsingErrors = 0
    }
    
    #region Check 1: Event ID 1644 Configuration
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [1/10] Checking Event ID 1644 Configuration..." -ForegroundColor $colors.Info
    Write-Host ""
    
    try {
        $diagLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering")."15 Field Engineering"
        
        if ($diagLevel -ge 2) {
            Write-Host "        ✓ Event logging ENABLED (Level $diagLevel)" -ForegroundColor $colors.Success
            $diagnosticStats.PassedChecks++
        } else {
            Write-Host "        ✗ Event logging DISABLED (Level $diagLevel)" -ForegroundColor $colors.Error
            Write-Host ""
            Write-Host "        To enable, run:" -ForegroundColor $colors.Warning
            Write-Host '        reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" \' -ForegroundColor $colors.Subtle
            Write-Host '            /v "15 Field Engineering" /t REG_DWORD /d 2 /f' -ForegroundColor $colors.Subtle
            $diagnosticStats.Errors++
        }
    } catch {
        Write-Host "        ✗ Cannot access registry key" -ForegroundColor $colors.Error
        Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor $colors.Subtle
        $diagnosticStats.Errors++
    }
    
    Write-Host ""
    
    #endregion
    
    #region Check 2: DETAILED Event Analysis with Debug Output
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [2/10] Analyzing Recent Event ID 1644 Events (DETAILED)..." -ForegroundColor $colors.Info
    Write-Host ""
    
    try {
        # Try last 30 minutes first, then expand
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Directory Service'
            ID = 1644
            StartTime = (Get-Date).AddMinutes(-30)
        } -MaxEvents 5 -ErrorAction Stop
        
        if ($events.Count -eq 0) {
            Write-Host "        No events in last 30 minutes, checking last 24 hours..." -ForegroundColor $colors.Warning
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Directory Service'
                ID = 1644
                StartTime = (Get-Date).AddHours(-24)
            } -MaxEvents 5 -ErrorAction Stop
        }
        
        if ($events.Count -eq 0) {
            Write-Host "        ✗ No Event ID 1644 events found" -ForegroundColor $colors.Error
            Write-Host ""
            Write-Host "        POSSIBLE CAUSES:" -ForegroundColor $colors.Warning
            Write-Host "        • Event ID 1644 logging level too low" -ForegroundColor $colors.Subtle
            Write-Host "        • No recent LDAP activity" -ForegroundColor $colors.Subtle
            Write-Host "        • Events not being captured" -ForegroundColor $colors.Subtle
            Write-Host ""
            Write-Host "        GENERATING TEST LDAP ACTIVITY..." -ForegroundColor $colors.Warning
            try {
                $searcher = [adsisearcher]"(objectclass=user)"
                $searcher.PageSize = 10
                $searcher.SizeLimit = 5
                $result = $searcher.FindAll()
                Write-Host "        Generated LDAP query for $($result.Count) users" -ForegroundColor $colors.Success
                $result.Dispose()
                Write-Host "        Wait 10 seconds and run diagnostics again..." -ForegroundColor $colors.Info
            } catch {
                Write-Host "        Could not generate test activity: $_" -ForegroundColor $colors.Subtle
            }
            $diagnosticStats.Errors++
        } else {
            Write-Host "        ✓ Found $($events.Count) recent events" -ForegroundColor $colors.Success
            Write-Host ""
            Write-Host "        Performing DEEP ANALYSIS on each event..." -ForegroundColor $colors.Info
            Write-Host "        " + ("═" * 60) -ForegroundColor $colors.Subtle
            Write-Host ""
            $diagnosticStats.PassedChecks++
            
            $eventNum = 1
            
            foreach ($event in $events | Select-Object -First 3) {
                $diagnosticStats.EventsAnalyzed++
                
                Write-Host ""
                Write-Host "        ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $colors.Highlight
                Write-Host "        ║  EVENT #$eventNum - $(Get-Date -Date $event.TimeCreated -Format 'yyyy-MM-dd HH:mm:ss')              ║" -ForegroundColor $colors.Highlight
                Write-Host "        ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $colors.Highlight
                Write-Host ""
                
                $props = $event.Properties
                Write-Host "        Time: $($event.TimeCreated)" -ForegroundColor $colors.Subtle
                Write-Host "        Record ID: $($event.RecordId)" -ForegroundColor $colors.Subtle
                Write-Host "        Properties Count: $($props.Count)" -ForegroundColor $colors.Info
                Write-Host ""
                
                # ═══════════════════════════════════════════════════════════
                # RAW PROPERTY DISPLAY (with index numbers)
                # ═══════════════════════════════════════════════════════════
                Write-Host "        ┌─ RAW PROPERTY DATA ───────────────────────────────────" -ForegroundColor $colors.Subtle
                for ($i = 0; $i -lt [Math]::Min($props.Count, 17); $i++) {
                    $value = $props[$i].Value
                    $valueStr = if ($value) { 
                        $v = $value.ToString()
                        if ($v.Length -gt 60) { $v.Substring(0, 57) + "..." } else { $v }
                    } else { 
                        "(null)" 
                    }
                    Write-Host "        │ [$("{0:D2}" -f $i)] = " -NoNewline -ForegroundColor $colors.Subtle
                    Write-Host "'$valueStr'" -ForegroundColor $colors.Data
                }
                Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Subtle
                Write-Host ""
                
                # ═══════════════════════════════════════════════════════════
                # PARSING ATTEMPT (shows exactly what gets extracted)
                # ═══════════════════════════════════════════════════════════
                Write-Host "        ┌─ PARSING ATTEMPT ─────────────────────────────────────" -ForegroundColor $colors.Info
                
                $shouldProcess = $true
                $skipReason = $null
                $clientIP = $null
                $efficiency = $null
                
                try {
                    if ($props.Count -ge 7) {
                        $searchBase = $props[0].Value
                        $filter = $props[1].Value
                        $visitedValue = $props[2].Value
                        $returnedValue = $props[3].Value
                        $clientIPRaw = $props[4].Value
                        $scope = if ($props.Count -gt 5) { $props[5].Value } else { "N/A" }
                        $attributes = if ($props.Count -gt 6) { $props[6].Value } else { "N/A" }
                        
                        Write-Host "        │ Search Base:      " -NoNewline -ForegroundColor $colors.Subtle
                        Write-Host $searchBase -ForegroundColor $colors.Data
                        Write-Host "        │ Filter:           " -NoNewline -ForegroundColor $colors.Subtle
                        Write-Host $filter -ForegroundColor $colors.Data
                        Write-Host "        │ Visited (raw):    " -NoNewline -ForegroundColor $colors.Subtle
                        Write-Host "'$visitedValue'" -ForegroundColor $colors.Data
                        Write-Host "        │ Returned (raw):   " -NoNewline -ForegroundColor $colors.Subtle
                        Write-Host "'$returnedValue'" -ForegroundColor $colors.Data
                        Write-Host "        │ Client IP (raw):  " -NoNewline -ForegroundColor $colors.Subtle
                        Write-Host "'$clientIPRaw'" -ForegroundColor $colors.Data
                        
                        # Parse integers
                        $visitedEntries = if ($visitedValue -match '^\d+$') { [int]$visitedValue } else { $null }
                        $returnedEntries = if ($returnedValue -match '^\d+$') { [int]$returnedValue } else { $null }
                        
                        if ($visitedEntries -eq $null -or $returnedEntries -eq $null) {
                            Write-Host "        │ " -ForegroundColor $colors.Subtle
                            Write-Host "        │ ✗ PARSING ERROR: Cannot parse visited/returned as integers" -ForegroundColor $colors.Error
                            $shouldProcess = $false
                            $skipReason = "Invalid numeric values"
                            $diagnosticStats.ParsingErrors++
                        }
                        
                    } else {
                        Write-Host "        │ ✗ ERROR: Insufficient properties ($($props.Count) < 7)" -ForegroundColor $colors.Error
                        $shouldProcess = $false
                        $skipReason = "Too few properties"
                        $diagnosticStats.ParsingErrors++
                    }
                    
                } catch {
                    Write-Host "        │ ✗ PARSING ERROR: $($_.Exception.Message)" -ForegroundColor $colors.Error
                    $shouldProcess = $false
                    $skipReason = "Exception during parsing"
                    $diagnosticStats.ParsingErrors++
                }
                Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Subtle
                Write-Host ""
                
                # ═══════════════════════════════════════════════════════════
                # IP EXTRACTION TEST (all formats)
                # ═══════════════════════════════════════════════════════════
                if ($shouldProcess -and $clientIPRaw) {
                    Write-Host "        ┌─ IP EXTRACTION TEST ──────────────────────────────────" -ForegroundColor $colors.Info
                    Write-Host "        │ Raw Value: '$clientIPRaw'" -ForegroundColor $colors.Data
                    Write-Host "        │ " -ForegroundColor $colors.Subtle
                    
                    # Try all IP parsing patterns
                    if ($clientIPRaw -match '^\[([0-9a-fA-F:]+(?:%\d+)?)\]:\d+$') {
                        $clientIP = $matches[1]
                        Write-Host "        │ ✓ Parsed IP:       $clientIP" -ForegroundColor $colors.Success
                        Write-Host "        │   Format:          IPv6 with brackets & port" -ForegroundColor $colors.Subtle
                    }
                    elseif ($clientIPRaw -match '^([0-9a-fA-F:]+):\d+$' -and $clientIPRaw -match '::') {
                        $clientIP = $matches[1]
                        Write-Host "        │ ✓ Parsed IP:       $clientIP" -ForegroundColor $colors.Success
                        Write-Host "        │   Format:          IPv6 with port (no brackets)" -ForegroundColor $colors.Subtle
                    }
                    elseif ($clientIPRaw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$') {
                        $clientIP = $matches[1]
                        Write-Host "        │ ✓ Parsed IP:       $clientIP" -ForegroundColor $colors.Success
                        Write-Host "        │   Format:          IPv4 with port" -ForegroundColor $colors.Subtle
                    }
                    elseif ($clientIPRaw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        $clientIP = $clientIPRaw
                        Write-Host "        │ ✓ Parsed IP:       $clientIP" -ForegroundColor $colors.Success
                        Write-Host "        │   Format:          IPv4 plain" -ForegroundColor $colors.Subtle
                    }
                    elseif ($clientIPRaw -match '^[0-9a-fA-F:]+$' -and $clientIPRaw -match '::') {
                        $clientIP = $clientIPRaw
                        Write-Host "        │ ✓ Parsed IP:       $clientIP" -ForegroundColor $colors.Success
                        Write-Host "        │   Format:          IPv6 plain" -ForegroundColor $colors.Subtle
                    }
                    else {
                        Write-Host "        │ ✗ IP PARSING FAILED" -ForegroundColor $colors.Error
                        Write-Host "        │   This event would be filtered out!" -ForegroundColor $colors.Warning
                        $shouldProcess = $false
                        $skipReason = "IP parsing failed"
                        $diagnosticStats.IPParseFailures++
                    }
                    
                    Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Subtle
                    Write-Host ""
                }
                
                # ═══════════════════════════════════════════════════════════
                # SKIP CHECKS (shows why events might be filtered)
                # ═══════════════════════════════════════════════════════════
                Write-Host "        ┌─ SKIP CHECKS ─────────────────────────────────────────" -ForegroundColor $colors.Info
                
                if (-not $clientIP) {
                    # Check if it's a known internal source
                    if ($clientIPRaw -in @("NTDSAPI", "SAM", "LSASS")) {
                        Write-Host "        │ ✗ SKIPPED: Internal event ($clientIPRaw)" -ForegroundColor $colors.Warning
                        $skipReason = "Internal-$clientIPRaw"
                    } else {
                        Write-Host "        │ ✗ SKIPPED: No valid IP extracted" -ForegroundColor $colors.Error
                        $skipReason = "No IP"
                    }
                    $shouldProcess = $false
                }
                elseif ($clientIPRaw -in @("NTDSAPI", "SAM", "LSASS") -or $filter -eq "NTDSAPI") {
                    Write-Host "        │ ✗ SKIPPED: Internal event ($clientIPRaw)" -ForegroundColor $colors.Warning
                    $shouldProcess = $false
                    $skipReason = "Internal-$clientIPRaw"
                }
                else {
                    Write-Host "        │ ✓ PASSED: Event would be processed" -ForegroundColor $colors.Success
                }
                
                Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Subtle
                Write-Host ""
                
                # ═══════════════════════════════════════════════════════════
                # EFFICIENCY CALCULATION & DETECTION
                # ═══════════════════════════════════════════════════════════
                if ($shouldProcess -and $visitedEntries -ne $null -and $returnedEntries -ne $null) {
                    Write-Host "        ┌─ EFFICIENCY ANALYSIS ─────────────────────────────────" -ForegroundColor $colors.Info
                    
                    $efficiency = if ($visitedEntries -gt 0) {
                        ($returnedEntries / $visitedEntries) * 100
                    } else {
                        100.0
                    }
                    
                    Write-Host "        │ Visited Entries:   $visitedEntries" -ForegroundColor $colors.Data
                    Write-Host "        │ Returned Entries:  $returnedEntries" -ForegroundColor $colors.Data
                    Write-Host "        │ Efficiency:        $([Math]::Round($efficiency, 2))%" -ForegroundColor $colors.Data
                    Write-Host "        │ " -ForegroundColor $colors.Subtle
                    
                    # BloodHound indicators
                    $isSuspicious = $false
                    
                    if ($efficiency -eq 0) {
                        Write-Host "        │ 🚨 DETECTION: ZERO EFFICIENCY!" -ForegroundColor $colors.Error
                        Write-Host "        │    This is a BloodHound signature!" -ForegroundColor $colors.Error
                        $isSuspicious = $true
                        $diagnosticStats.SuspiciousEvents++
                    }
                    elseif ($efficiency -lt 5) {
                        Write-Host "        │ ⚠️  DETECTION: Critical efficiency ($([Math]::Round($efficiency, 2))%)" -ForegroundColor $colors.Warning
                        $isSuspicious = $true
                        $diagnosticStats.SuspiciousEvents++
                    }
                    elseif ($efficiency -lt 20) {
                        Write-Host "        │ ⚠️  WARNING: Low efficiency ($([Math]::Round($efficiency, 2))%)" -ForegroundColor $colors.Warning
                    }
                    else {
                        Write-Host "        │ ✓ Normal efficiency" -ForegroundColor $colors.Success
                    }
                    
                    # Additional BloodHound patterns
                    if ($filter -match '\(objectClass=\*\)' -or $filter -match '^\(\*\)$') {
                        Write-Host "        │ 🚨 Wildcard filter detected!" -ForegroundColor $colors.Error
                        $isSuspicious = $true
                    }
                    
                    if ($attributes -match '\*' -or $attributes -eq "N/A") {
                        Write-Host "        │ 🚨 All attributes requested!" -ForegroundColor $colors.Error
                        $isSuspicious = $true
                    }
                    
                    Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Subtle
                    Write-Host ""
                }
                
                # ═══════════════════════════════════════════════════════════
                # EVENT STATUS SUMMARY
                # ═══════════════════════════════════════════════════════════
                Write-Host "        ┌─ EVENT STATUS ────────────────────────────────────────" -ForegroundColor $colors.Highlight
                if ($shouldProcess) {
                    Write-Host "        │ Status:            " -NoNewline -ForegroundColor $colors.Subtle
                    Write-Host "✓ VALID - Would be processed" -ForegroundColor $colors.Success
                    $diagnosticStats.ValidEvents++
                } else {
                    Write-Host "        │ Status:            " -NoNewline -ForegroundColor $colors.Subtle
                    Write-Host "✗ SKIPPED - $skipReason" -ForegroundColor $colors.Error
                    $diagnosticStats.SkippedEvents++
                }
                
                if ($efficiency -ne $null) {
                    Write-Host "        │ Efficiency:        " -NoNewline -ForegroundColor $colors.Subtle
                    Write-Host "$([Math]::Round($efficiency, 2))%" -ForegroundColor $colors.Data
                }
                
                if ($isSuspicious) {
                    Write-Host "        │ Alert:             " -NoNewline -ForegroundColor $colors.Subtle
                    Write-Host "Would generate alert" -ForegroundColor $colors.Error
                }
                
                Write-Host "        └───────────────────────────────────────────────────────────" -ForegroundColor $colors.Highlight
                Write-Host ""
                
                if ($eventNum -lt 3 -and $eventNum -lt $events.Count) {
                    Write-Host "        " + ("─" * 60) -ForegroundColor $colors.Subtle
                }
                
                $eventNum++
            }
            
            # Parsing summary
            Write-Host ""
            Write-Host "        ═══════════════════════════════════════════════════════════" -ForegroundColor $colors.Highlight
            Write-Host "        PARSING ANALYSIS SUMMARY:" -ForegroundColor $colors.Highlight
            Write-Host "        • Total Events Analyzed:  $($diagnosticStats.EventsAnalyzed)" -ForegroundColor $colors.Data
            Write-Host "        • Valid Events:           $($diagnosticStats.ValidEvents)" -ForegroundColor $colors.Success
            Write-Host "        • Skipped Events:         $($diagnosticStats.SkippedEvents)" -ForegroundColor $colors.Warning
            Write-Host "        • Suspicious Events:      $($diagnosticStats.SuspiciousEvents)" -ForegroundColor $(if ($diagnosticStats.SuspiciousEvents -gt 0) { $colors.Error } else { $colors.Success })
            Write-Host "        • IP Parse Failures:      $($diagnosticStats.IPParseFailures)" -ForegroundColor $(if ($diagnosticStats.IPParseFailures -gt 0) { $colors.Error } else { $colors.Success })
            Write-Host "        • Parsing Errors:         $($diagnosticStats.ParsingErrors)" -ForegroundColor $(if ($diagnosticStats.ParsingErrors -gt 0) { $colors.Error } else { $colors.Success })
            Write-Host "        ═══════════════════════════════════════════════════════════" -ForegroundColor $colors.Highlight
        }
        
    } catch {
        Write-Host "        ✗ Error accessing events: $_" -ForegroundColor $colors.Error
        $diagnosticStats.Errors++
    }
    
    Write-Host ""
    
    #endregion
    
    #region Check 3: Baseline Status
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [3/10] Checking Baseline Status..." -ForegroundColor $colors.Info
    
    $baselinePath = "$PSScriptRoot\baseline_statistics.json"
    if (Test-Path $baselinePath) {
        try {
            $baseline = Get-Content $baselinePath | ConvertFrom-Json
            Write-Host "        ✓ Baseline exists" -ForegroundColor $colors.Success
            Write-Host "        Created:              " -NoNewline -ForegroundColor $colors.Subtle
            Write-Host $baseline.Timestamp -ForegroundColor $colors.Data
            Write-Host "        Samples:              " -NoNewline -ForegroundColor $colors.Subtle
            Write-Host $baseline.SampleCount -ForegroundColor $colors.Data
            $diagnosticStats.PassedChecks++
        } catch {
            Write-Host "        ⚠️  Baseline file corrupt" -ForegroundColor $colors.Warning
            $diagnosticStats.Warnings++
        }
    } else {
        Write-Host "        ✗ No baseline found" -ForegroundColor $colors.Error
        Write-Host "        Recommendation: Build baseline with Option 1" -ForegroundColor $colors.Warning
        $diagnosticStats.Errors++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 4: Alert Log Status
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [4/10] Checking Alert Log..." -ForegroundColor $colors.Info
    
    $alertLogPath = "$PSScriptRoot\bloodhound_alerts.log"
    if (Test-Path $alertLogPath) {
        $alertLog = Get-Item $alertLogPath
        $alertCount = (Get-Content $alertLogPath | Measure-Object).Count
        Write-Host "        ✓ Alert log exists" -ForegroundColor $colors.Success
        Write-Host "        Size:                 " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$([Math]::Round($alertLog.Length / 1KB, 2)) KB" -ForegroundColor $colors.Data
        Write-Host "        Alerts:               " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host $alertCount -ForegroundColor $colors.Data
        $diagnosticStats.PassedChecks++
    } else {
        Write-Host "        ⚠️  No alert log found" -ForegroundColor $colors.Warning
        Write-Host "        This is normal if no alerts triggered yet" -ForegroundColor $colors.Subtle
        $diagnosticStats.Warnings++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 5: Permissions
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [5/10] Checking Permissions..." -ForegroundColor $colors.Info
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Host "        ✓ Running with Administrator privileges" -ForegroundColor $colors.Success
        $diagnosticStats.PassedChecks++
    } else {
        Write-Host "        ✗ NOT running as Administrator" -ForegroundColor $colors.Error
        Write-Host "        Some checks may fail" -ForegroundColor $colors.Warning
        $diagnosticStats.Errors++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 6: Domain Controller Role
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [6/10] Checking Domain Controller Role..." -ForegroundColor $colors.Info
    
    try {
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        if ($isDC) {
            Write-Host "        ✓ This is a Domain Controller" -ForegroundColor $colors.Success
            $diagnosticStats.PassedChecks++
        } else {
            Write-Host "        ⚠️  Not a Domain Controller" -ForegroundColor $colors.Warning
            Write-Host "        Event ID 1644 only generates on DCs" -ForegroundColor $colors.Subtle
            $diagnosticStats.Warnings++
        }
    } catch {
        Write-Host "        ⚠️  Cannot determine DC role" -ForegroundColor $colors.Warning
        $diagnosticStats.Warnings++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 7: Directory Service Log Size
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [7/10] Checking Directory Service Log..." -ForegroundColor $colors.Info
    
    try {
        $dsLog = Get-WinEvent -ListLog "Directory Service" -ErrorAction Stop
        $logSizeMB = [Math]::Round($dsLog.FileSize / 1MB, 2)
        $maxSizeMB = [Math]::Round($dsLog.MaximumSizeInBytes / 1MB, 2)
        $percentFull = ($dsLog.FileSize / $dsLog.MaximumSizeInBytes) * 100
        
        Write-Host "        ✓ Log accessible" -ForegroundColor $colors.Success
        Write-Host "        Current Size:         " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$logSizeMB MB" -ForegroundColor $colors.Data
        Write-Host "        Max Size:             " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$maxSizeMB MB" -ForegroundColor $colors.Data
        Write-Host "        Usage:                " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$([Math]::Round($percentFull, 1))%" -ForegroundColor $colors.Data
        
        if ($percentFull -gt 90) {
            Write-Host "        ⚠️  Log nearly full! Events may be overwritten" -ForegroundColor $colors.Warning
            $diagnosticStats.Warnings++
        } else {
            $diagnosticStats.PassedChecks++
        }
    } catch {
        Write-Host "        ⚠️  Cannot access Directory Service log" -ForegroundColor $colors.Warning
        $diagnosticStats.Warnings++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 8: Disk Space
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [8/10] Checking Disk Space..." -ForegroundColor $colors.Info
    
    try {
        $drive = Get-PSDrive -Name C
        $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
        $totalSpaceGB = [Math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
        $percentUsed = (($totalSpaceGB - $freeSpaceGB) / $totalSpaceGB) * 100
        
        Write-Host "        ✓ Disk information available" -ForegroundColor $colors.Success
        Write-Host "        Free Space:           " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$freeSpaceGB GB" -ForegroundColor $colors.Data
        Write-Host "        Total Space:          " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$totalSpaceGB GB" -ForegroundColor $colors.Data
        Write-Host "        Used:                 " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host "$([Math]::Round($percentUsed, 1))%" -ForegroundColor $colors.Data
        
        if ($freeSpaceGB -lt 5) {
            Write-Host "        ⚠️  Low disk space! Only $freeSpaceGB GB free" -ForegroundColor $colors.Warning
            $diagnosticStats.Warnings++
        } else {
            $diagnosticStats.PassedChecks++
        }
    } catch {
        Write-Host "        ⚠️  Cannot determine disk space" -ForegroundColor $colors.Warning
        $diagnosticStats.Warnings++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 9: Time Synchronization
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [9/10] Checking Time Synchronization..." -ForegroundColor $colors.Info
    
    try {
        $w32tm = w32tm /query /status 2>&1
        if ($w32tm -match "Source:\s*(.+)") {
            $timeSource = $matches[1].Trim()
            Write-Host "        ✓ Time service running" -ForegroundColor $colors.Success
            Write-Host "        Time Source:          " -NoNewline -ForegroundColor $colors.Subtle
            Write-Host $timeSource -ForegroundColor $colors.Data
            $diagnosticStats.PassedChecks++
        } else {
            Write-Host "        ⚠️  Time service status unknown" -ForegroundColor $colors.Warning
            $diagnosticStats.Warnings++
        }
    } catch {
        Write-Host "        ⚠️  Cannot check time synchronization" -ForegroundColor $colors.Warning
        $diagnosticStats.Warnings++
    }
    Write-Host ""
    
    #endregion
    
    #region Check 10: Script Features
    
    $diagnosticStats.TotalChecks++
    Write-Host "    [10/10] Script Features & Capabilities..." -ForegroundColor $colors.Info
    
    Write-Host "        ✓ Diagnostic script operational" -ForegroundColor $colors.Success
    Write-Host "        Features Available:" -ForegroundColor $colors.Subtle
    Write-Host "        • Event ID 1644 deep analysis" -ForegroundColor $colors.Subtle
    Write-Host "        • RAW property display with indexes" -ForegroundColor $colors.Subtle
    Write-Host "        • Complete field parsing validation" -ForegroundColor $colors.Subtle
    Write-Host "        • IP extraction testing (all formats)" -ForegroundColor $colors.Subtle
    Write-Host "        • Skip checks (shows filtering logic)" -ForegroundColor $colors.Subtle
    Write-Host "        • Efficiency calculations" -ForegroundColor $colors.Subtle
    Write-Host "        • BloodHound pattern detection" -ForegroundColor $colors.Subtle
    Write-Host "        • Baseline validation" -ForegroundColor $colors.Subtle
    $diagnosticStats.PassedChecks++
    Write-Host ""
    
    #endregion
    
    #region Final Summary
    
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor $colors.Subtle
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $colors.Highlight
    Write-Host "    ║                    DIAGNOSTIC SUMMARY                        ║" -ForegroundColor $colors.Highlight
    Write-Host "    ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $colors.Highlight
    Write-Host ""
    
    $successRate = if ($diagnosticStats.TotalChecks -gt 0) {
        [Math]::Round(($diagnosticStats.PassedChecks / $diagnosticStats.TotalChecks) * 100, 1)
    } else { 0 }
    
    Write-Host "    Total Checks:             " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.TotalChecks -ForegroundColor $colors.Data
    Write-Host "    Passed:                   " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host "$($diagnosticStats.PassedChecks) ($successRate%)" -ForegroundColor $colors.Success
    Write-Host "    Warnings:                 " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.Warnings -ForegroundColor $colors.Warning
    Write-Host "    Errors:                   " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.Errors -ForegroundColor $colors.Error
    Write-Host ""
    Write-Host "    Events Analyzed:          " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.EventsAnalyzed -ForegroundColor $colors.Data
    Write-Host "    Valid Events:             " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.ValidEvents -ForegroundColor $colors.Success
    Write-Host "    Skipped Events:           " -NoNewline -ForegroundColor $colors.Subtle
    Write-Host $diagnosticStats.SkippedEvents -ForegroundColor $colors.Warning
    Write-Host "    Suspicious Events:        " -NoNewline -ForegroundColor $colors.Subtle
    if ($diagnosticStats.SuspiciousEvents -gt 0) {
        Write-Host $diagnosticStats.SuspiciousEvents -ForegroundColor $colors.Error
    } else {
        Write-Host $diagnosticStats.SuspiciousEvents -ForegroundColor $colors.Success
    }
    
    if ($diagnosticStats.IPParseFailures -gt 0) {
        Write-Host "    IP Parse Failures:        " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host $diagnosticStats.IPParseFailures -ForegroundColor $colors.Error
    }
    
    if ($diagnosticStats.ParsingErrors -gt 0) {
        Write-Host "    Parsing Errors:           " -NoNewline -ForegroundColor $colors.Subtle
        Write-Host $diagnosticStats.ParsingErrors -ForegroundColor $colors.Error
    }
    
    Write-Host ""
    
    # Overall health assessment
    Write-Host "    ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor $colors.Subtle
    Write-Host "    │ " -NoNewline -ForegroundColor $colors.Subtle
    
    $healthStatus = if ($diagnosticStats.Errors -eq 0 -and $diagnosticStats.Warnings -eq 0) {
        Write-Host "SYSTEM HEALTH: ✓ EXCELLENT                                  " -NoNewline -ForegroundColor $colors.Success
        "EXCELLENT"
    } elseif ($diagnosticStats.Errors -eq 0) {
        Write-Host "SYSTEM HEALTH: ⚠️  GOOD (Minor warnings)                     " -NoNewline -ForegroundColor $colors.Warning
        "GOOD"
    } elseif ($diagnosticStats.Errors -le 2) {
        Write-Host "SYSTEM HEALTH: ⚠️  FAIR (Some issues detected)               " -NoNewline -ForegroundColor $colors.Warning
        "FAIR"
    } else {
        Write-Host "SYSTEM HEALTH: ✗ POOR (Multiple issues)                    " -NoNewline -ForegroundColor $colors.Error
        "POOR"
    }
    
    Write-Host "│" -ForegroundColor $colors.Subtle
    Write-Host "    │                                                             │" -ForegroundColor $colors.Subtle
    
    if ($healthStatus -eq "EXCELLENT") {
        Write-Host "    │ All systems operational and ready for monitoring            │" -ForegroundColor $colors.Subtle
    } elseif ($healthStatus -eq "GOOD") {
        Write-Host "    │ System operational with minor recommendations               │" -ForegroundColor $colors.Subtle
    } elseif ($healthStatus -eq "FAIR") {
        Write-Host "    │ Review warnings above and address issues                    │" -ForegroundColor $colors.Subtle
    } else {
        Write-Host "    │ Critical issues detected - review errors above              │" -ForegroundColor $colors.Subtle
    }
    
    if ($diagnosticStats.SuspiciousEvents -gt 0) {
        Write-Host "    │                                                             │" -ForegroundColor $colors.Subtle
        Write-Host "    │ 🚨 Suspicious activity detected - investigate immediately   │" -ForegroundColor $colors.Error
    }
    
    if ($diagnosticStats.IPParseFailures -gt 0) {
        Write-Host "    │                                                             │" -ForegroundColor $colors.Subtle
        Write-Host "    │ ⚠️  IP parsing failures - some events may be missed         │" -ForegroundColor $colors.Warning
    }
    
    Write-Host "    └─────────────────────────────────────────────────────────────┘" -ForegroundColor $colors.Subtle
    Write-Host ""
    
    Write-Host "    Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $colors.Subtle
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor $colors.Subtle
    Write-Host ""
    
    #endregion
    
    # Pause for user
    Write-Host "    Press Enter to continue..." -ForegroundColor $colors.Subtle
    Read-Host
}


function Clear-EventLogs {
    <#
    .SYNOPSIS
        Clear Event ID 1644 logs
    #>
    
    Clear-Host
    Write-ColoredHeader "Clear Event Logs" "Yellow"
    
    Write-Host "    This will clear all Event ID 1644 entries from the Directory Service log." -ForegroundColor White
    Write-Host "    This is useful for establishing a clean baseline." -ForegroundColor Gray
    Write-Host ""
    Write-Host "    ⚠️  WARNING: This action cannot be undone!" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "    Type YES to confirm"
    
    if ($confirm -eq "YES") {
        try {
            Write-Host ""
            Write-Host "    [*] Clearing Event ID 1644 logs..." -ForegroundColor Cyan
            
            wevtutil cl "Directory Service"
            
            Write-Host "    [✓] Event logs cleared successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "    [✗] Error clearing logs: $_" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "    [!] Operation cancelled" -ForegroundColor Yellow
    }
    
    Pause-ForUser
}

function Clear-AlertHistory {
    <#
    .SYNOPSIS
        Clear alert log file
    #>
    
    Clear-Host
    Write-ColoredHeader "Clear Alert History" "Yellow"
    
    if (-not (Test-Path $script:Config.AlertLogFile)) {
        Write-Host "    [i] No alert log file exists" -ForegroundColor Gray
        Pause-ForUser
        return
    }
    
    $alertCount = (Get-Content $script:Config.AlertLogFile | Measure-Object).Count
    
    Write-Host "    Current alert log contains $alertCount alerts." -ForegroundColor White
    Write-Host ""
    Write-Host "    ⚠️  WARNING: This will permanently delete all logged alerts!" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "    Type YES to confirm"
    
    if ($confirm -eq "YES") {
        try {
            Remove-Item $script:Config.AlertLogFile -Force
            Write-Host ""
            Write-Host "    [✓] Alert history cleared successfully" -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "    [✗] Error clearing alert history: $_" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "    [!] Operation cancelled" -ForegroundColor Yellow
    }
    
    Pause-ForUser
}

function Open-LogsFolder {
    <#
    .SYNOPSIS
        Open Windows debug folder in Explorer
    #>
    
    $debugFolder = "C:\Windows\debug"
    
    if (Test-Path $debugFolder) {
        Start-Process explorer.exe $debugFolder
        
        Clear-Host
        Write-Host ""
        Write-Host "    [✓] Opened logs folder in Windows Explorer" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Location: $debugFolder" -ForegroundColor Cyan
    } else {
        Clear-Host
        Write-Host ""
        Write-Host "    [✗] Debug folder not found: $debugFolder" -ForegroundColor Red
    }
    
    Pause-ForUser
}

#endregion

#region Documentation

function Show-Documentation {
    <#
    .SYNOPSIS
        Display comprehensive documentation with color-coded sections and corrected examples
    #>
    
    Clear-Host
    
    # Header
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║           BLOODHOUND DETECTOR - DOCUMENTATION                ║" -ForegroundColor Cyan
    Write-Host "║              Complete Implementation Guide                   ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Table of Contents
    Write-Host "TABLE OF CONTENTS" -ForegroundColor Yellow
    Write-Host "─────────────────" -ForegroundColor DarkGray
    Write-Host "1. Overview & Philosophy" -ForegroundColor Gray
    Write-Host "2. How Event ID 1644 Works (Deep Dive)" -ForegroundColor Gray
    Write-Host "3. Detection Methodology" -ForegroundColor Gray
    Write-Host "4. Key Metrics Explained" -ForegroundColor Gray
    Write-Host "5. Common Issues & Bugs We Fixed" -ForegroundColor Gray
    Write-Host "6. Real-World Examples" -ForegroundColor Gray
    Write-Host "7. Advanced Configuration" -ForegroundColor Gray
    Write-Host "8. Troubleshooting Guide" -ForegroundColor Gray
    Write-Host "9. SIEM Integration" -ForegroundColor Gray
    Write-Host "10. Performance Tuning" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    # Section 1: Overview & Philosophy
    Write-Host "1. OVERVIEW & PHILOSOPHY" -ForegroundColor Cyan
    Write-Host "─────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "BloodHound Detector takes a unique approach to detecting LDAP" -ForegroundColor White
    Write-Host "reconnaissance: instead of looking for specific tool signatures," -ForegroundColor White
    Write-Host "it detects the " -ForegroundColor White -NoNewline
    Write-Host "FUNDAMENTAL BEHAVIOR" -ForegroundColor Yellow -NoNewline
    Write-Host " of reconnaissance." -ForegroundColor White
    Write-Host ""
    
    Write-Host "THE CORE INSIGHT:" -ForegroundColor Green
    Write-Host "Reconnaissance tools (BloodHound, SharpHound, custom scripts) all" -ForegroundColor White
    Write-Host "share common characteristics that make them mathematically detectable:" -ForegroundColor White
    Write-Host ""
    Write-Host "  • They MUST query many objects (high volume)" -ForegroundColor Gray
    Write-Host "  • They MUST request specific data (patterns emerge)" -ForegroundColor Gray
    Write-Host "  • They CANNOT be perfectly efficient (tradeoffs exist)" -ForegroundColor Gray
    Write-Host "  • They LEAVE forensic artifacts (Event ID 1644)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Even if an attacker:" -ForegroundColor White
    Write-Host "  ✓ Modifies BloodHound's source code" -ForegroundColor Green
    Write-Host "  ✓ Changes LDAP filter syntax" -ForegroundColor Green
    Write-Host "  ✓ Slows down query rate" -ForegroundColor Green
    Write-Host "  ✓ Uses a completely custom tool" -ForegroundColor Green
    Write-Host ""
    Write-Host "They " -ForegroundColor White -NoNewline
    Write-Host "STILL" -ForegroundColor Red -NoNewline
    Write-Host " exhibit detectable patterns because reconnaissance" -ForegroundColor White
    Write-Host "itself has inherent mathematical properties." -ForegroundColor White
    Write-Host ""
    
    Write-Host "DETECTION APPROACH:" -ForegroundColor Magenta
    Write-Host "  1. Statistical Analysis - Baseline normal behavior, detect anomalies" -ForegroundColor White
    Write-Host "  2. Pattern Matching - Identify known reconnaissance techniques" -ForegroundColor White
    Write-Host "  3. Composite Scoring - Combine multiple weak signals into strong signal" -ForegroundColor White
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 2: How Event ID 1644 Works
    Write-Host "2. HOW EVENT ID 1644 WORKS (DEEP DIVE)" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "EVENT ID 1644: " -ForegroundColor Yellow -NoNewline
    Write-Host "LDAP Search Statistics" -ForegroundColor White
    Write-Host "Generated when: " -ForegroundColor Gray -NoNewline
    Write-Host "LDAP queries meet 'expensive' or 'inefficient' criteria" -ForegroundColor White
    Write-Host "Location: " -ForegroundColor Gray -NoNewline
    Write-Host "Directory Service Event Log" -ForegroundColor White
    Write-Host "Configured by: " -ForegroundColor Gray -NoNewline
    Write-Host "NTDS Diagnostics '15 Field Engineering' registry key" -ForegroundColor White
    Write-Host ""
    
    Write-Host "WHEN DOES IT FIRE?" -ForegroundColor Green
    Write-Host "Microsoft logs Event 1644 for queries that are 'expensive' from" -ForegroundColor White
    Write-Host "a performance perspective. The default thresholds are:" -ForegroundColor White
    Write-Host "  • Expensive searches: 10,000+ entries returned" -ForegroundColor Gray
    Write-Host "  • Inefficient searches: 1,000+ entries visited" -ForegroundColor Gray
    Write-Host "  • Search time: 100ms+ execution time" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "FOR SECURITY DETECTION:" -ForegroundColor Magenta
    Write-Host "We configure Level 2 (or higher) to capture MORE events:" -ForegroundColor White
    Write-Host "  • Level 2: Basic expensive query logging " -ForegroundColor Gray -NoNewline
    Write-Host "(RECOMMENDED)" -ForegroundColor Cyan
    Write-Host "  • Level 5: Maximum verbosity " -ForegroundColor Gray -NoNewline
    Write-Host "(LAB ONLY - generates excessive events)" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "CRITICAL EVENT FIELDS:" -ForegroundColor Red
    Write-Host "Event ID 1644 contains these key properties:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [0] Client IP         " -ForegroundColor Cyan -NoNewline
    Write-Host "- Who made the query" -ForegroundColor Gray
    Write-Host "  [1] Starting Node     " -ForegroundColor Cyan -NoNewline
    Write-Host "- Where in AD tree the search began" -ForegroundColor Gray
    Write-Host "  [2] Filter            " -ForegroundColor Cyan -NoNewline
    Write-Host "- LDAP filter used (e.g., '(objectclass=*)')" -ForegroundColor Gray
    Write-Host "  [3] Visited Entries   " -ForegroundColor Cyan -NoNewline
    Write-Host "- How many objects AD examined" -ForegroundColor Gray
    Write-Host "  [4] Returned Entries  " -ForegroundColor Cyan -NoNewline
    Write-Host "- How many objects matched and were returned" -ForegroundColor Gray
    Write-Host "  [5] Used Indexes      " -ForegroundColor Cyan -NoNewline
    Write-Host "- Which AD indexes were accessed" -ForegroundColor Gray
    Write-Host "  [6] Pages Referenced  " -ForegroundColor Cyan -NoNewline
    Write-Host "- How many DB pages read from disk" -ForegroundColor Gray
    Write-Host "  [7] Attributes        " -ForegroundColor Cyan -NoNewline
    Write-Host "- Which attributes were requested" -ForegroundColor Gray
    Write-Host "  [8] Server Controls   " -ForegroundColor Cyan -NoNewline
    Write-Host "- LDAP controls (e.g., SDFlags)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 3: Detection Methodology
    Write-Host "3. DETECTION METHODOLOGY" -ForegroundColor Cyan
    Write-Host "────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "OUR THREE-LAYER APPROACH:" -ForegroundColor Yellow
    Write-Host ""
    
    # Layer 1
    Write-Host "LAYER 1: STATISTICAL ANALYSIS" -ForegroundColor Magenta -NoNewline
    Write-Host " (Baseline Required)" -ForegroundColor Gray
    Write-Host "──────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Establishes what's 'normal' for YOUR environment." -ForegroundColor White
    Write-Host ""
    Write-Host "Process:" -ForegroundColor Green
    Write-Host "  1. Collect 24-48 hours of Event 1644 logs during business hours" -ForegroundColor White
    Write-Host "  2. Calculate mean and standard deviation for entries returned" -ForegroundColor White
    Write-Host "  3. During monitoring, flag queries >3σ above baseline" -ForegroundColor White
    Write-Host ""
    Write-Host "Why This Works:" -ForegroundColor Green
    Write-Host "  • Normal admin queries: " -ForegroundColor Gray -NoNewline
    Write-Host "Consistent, predictable patterns" -ForegroundColor White
    Write-Host "  • Reconnaissance: " -ForegroundColor Gray -NoNewline
    Write-Host "Sudden spike in volume (10x-100x normal)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Example:" -ForegroundColor Cyan
    Write-Host "  Baseline: " -ForegroundColor White -NoNewline
    Write-Host "Mean = 57 entries, StdDev = 12" -ForegroundColor Gray
    Write-Host "  BloodHound query: " -ForegroundColor White -NoNewline
    Write-Host "3,815 entries returned" -ForegroundColor Yellow
    Write-Host "  Z-Score: " -ForegroundColor White -NoNewline
    Write-Host "(3815 - 57) / 12 = " -ForegroundColor Gray -NoNewline
    Write-Host "313σ above normal! 🚨" -ForegroundColor Red
    Write-Host ""
    
    Pause-ForUser
    
    # Layer 2
    Write-Host "LAYER 2: EFFICIENCY ANALYSIS" -ForegroundColor Magenta -NoNewline
    Write-Host " (Always Active)" -ForegroundColor Gray
    Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Calculates how 'efficient' each LDAP query is." -ForegroundColor White
    Write-Host ""
    Write-Host "Formula:" -ForegroundColor Green
    Write-Host "  " -NoNewline
    Write-Host "Efficiency Ratio = (Returned Entries / Visited Entries) × 100" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Interpretation:" -ForegroundColor Green
    Write-Host "  • 100%: " -ForegroundColor White -NoNewline
    Write-Host "Perfect " -ForegroundColor Green -NoNewline
    Write-Host "(returned everything visited)" -ForegroundColor Gray
    Write-Host "  •  50%: " -ForegroundColor White -NoNewline
    Write-Host "Normal " -ForegroundColor White -NoNewline
    Write-Host "(some filtering occurred)" -ForegroundColor Gray
    Write-Host "  •  10%: " -ForegroundColor White -NoNewline
    Write-Host "Suspicious " -ForegroundColor Yellow -NoNewline
    Write-Host "(visited 10x more than returned)" -ForegroundColor Gray
    Write-Host "  •   0%: " -ForegroundColor White -NoNewline
    Write-Host "Critical " -ForegroundColor Red -NoNewline
    Write-Host "(visited objects but returned nothing)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Why This Works:" -ForegroundColor Green
    Write-Host "  • Normal queries: " -ForegroundColor Gray -NoNewline
    Write-Host "High efficiency (know what they want)" -ForegroundColor White
    Write-Host "  • Reconnaissance: " -ForegroundColor Gray -NoNewline
    Write-Host "Low efficiency (casting wide net)" -ForegroundColor Yellow
    Write-Host "  • Modern SharpHound: " -ForegroundColor Gray -NoNewline
    Write-Host "0% efficiency " -ForegroundColor Red -NoNewline
    Write-Host "(GUID lookups for non-existent objects)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "CRITICAL INSIGHT - The 0% Efficiency Pattern:" -ForegroundColor Red
    Write-Host "Modern SharpHound uses highly targeted queries like:" -ForegroundColor White
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectguid=\xx\xx\xx\xx...)" -ForegroundColor Cyan
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "2 entries" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "0 entries" -ForegroundColor Red
    Write-Host ""
    Write-Host "This is HIGHLY suspicious because:" -ForegroundColor Yellow
    Write-Host "  1. Why look for specific GUID if you don't know it exists?" -ForegroundColor White
    Write-Host "  2. Normal admins don't query non-existent GUIDs" -ForegroundColor White
    Write-Host "  3. This is SharpHound doing exhaustive enumeration" -ForegroundColor White
    Write-Host ""
    Write-Host "We apply a " -ForegroundColor White -NoNewline
    Write-Host "ZeroEfficiencyBoost (+0.3)" -ForegroundColor Red -NoNewline
    Write-Host " to catch this pattern." -ForegroundColor White
    Write-Host ""
    
    Pause-ForUser
    
    # Layer 3
    Write-Host "LAYER 3: PATTERN DETECTION" -ForegroundColor Magenta -NoNewline
    Write-Host " (Signature-Based)" -ForegroundColor Gray
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Identifies specific reconnaissance techniques." -ForegroundColor White
    Write-Host ""
    
    Write-Host "Pattern 1: Base Scope Object Enumeration " -ForegroundColor Red -NoNewline
    Write-Host "(+0.5)" -ForegroundColor Red
    Write-Host "How to identify:" -ForegroundColor Green
    Write-Host "  • Filter: (objectclass=*)" -ForegroundColor Gray
    Write-Host "  • Scope: base (not subtree)" -ForegroundColor Gray
    Write-Host "  • Attributes: Multiple identity attributes" -ForegroundColor Gray
    Write-Host "What this means:" -ForegroundColor Green
    Write-Host "  BloodHound is enumerating all properties of specific objects." -ForegroundColor White
    Write-Host "  This is how it maps object relationships." -ForegroundColor White
    Write-Host ""
    
    Write-Host "Pattern 2: SDFlags Enumeration " -ForegroundColor Red -NoNewline
    Write-Host "(+0.4)" -ForegroundColor Red
    Write-Host "How to identify:" -ForegroundColor Green
    Write-Host "  • Server controls field contains: 'SDFlags:0x5' or 'SDFlags:0x4'" -ForegroundColor Gray
    Write-Host "What this means:" -ForegroundColor Green
    Write-Host "  Requesting security descriptors (ACLs). This is how BloodHound" -ForegroundColor White
    Write-Host "  discovers WHO can access WHAT. Critical for attack path analysis." -ForegroundColor White
    Write-Host "Why it's distinctive:" -ForegroundColor Green
    Write-Host "  Normal admin tools rarely use SDFlags. This is almost exclusively" -ForegroundColor White
    Write-Host "  used by security assessment tools." -ForegroundColor White
    Write-Host ""
    
    Write-Host "Pattern 3: sAMAccountType Enumeration " -ForegroundColor Yellow -NoNewline
    Write-Host "(+0.3-0.4)" -ForegroundColor Yellow
    Write-Host "How to identify:" -ForegroundColor Green
    Write-Host "  • Filter contains: (sAMAccountType=268435456|268435457|536870912|...)" -ForegroundColor Gray
    Write-Host "What this means:" -ForegroundColor Green
    Write-Host "  Targeting specific object types:" -ForegroundColor White
    Write-Host "    • 268435456 = User accounts" -ForegroundColor Gray
    Write-Host "    • 268435457 = Machine accounts" -ForegroundColor Gray
    Write-Host "    • 536870912 = Groups (security)" -ForegroundColor Gray
    Write-Host "    • 536870913 = Groups (distribution)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Pattern 4: ADCS/PKI Infrastructure " -ForegroundColor Yellow -NoNewline
    Write-Host "(+0.3)" -ForegroundColor Yellow
    Write-Host "How to identify:" -ForegroundColor Green
    Write-Host "  • Filter or attributes contain:" -ForegroundColor Gray
    Write-Host "    - pki-enrollment-service" -ForegroundColor Gray
    Write-Host "    - certificationauthority" -ForegroundColor Gray
    Write-Host "    - certificatetemplates" -ForegroundColor Gray
    Write-Host "What this means:" -ForegroundColor Green
    Write-Host "  Mapping certificate infrastructure. This enables attacks like:" -ForegroundColor White
    Write-Host "    • ESC1-ESC8 (certificate template abuse)" -ForegroundColor Gray
    Write-Host "    • NTLM relay to ADCS" -ForegroundColor Gray
    Write-Host "    • Privilege escalation via certificates" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Pattern 5: Excessive Attributes " -ForegroundColor Yellow -NoNewline
    Write-Host "(+0.2)" -ForegroundColor Yellow
    Write-Host "How to identify:" -ForegroundColor Green
    Write-Host "  • Attribute list contains 30+ attributes" -ForegroundColor Gray
    Write-Host "What this means:" -ForegroundColor Green
    Write-Host "  Data exfiltration or comprehensive enumeration." -ForegroundColor White
    Write-Host "Why it's distinctive:" -ForegroundColor Green
    Write-Host "  Normal queries: 5-10 attributes (specific need)" -ForegroundColor Gray
    Write-Host "  Reconnaissance: 30-70 attributes (grab everything)" -ForegroundColor Red
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 4: Key Metrics
    Write-Host "4. KEY METRICS EXPLAINED" -ForegroundColor Cyan
    Write-Host "────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "VISITED ENTRIES vs. RETURNED ENTRIES" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "This is " -ForegroundColor White -NoNewline
    Write-Host "THE MOST IMPORTANT" -ForegroundColor Red -NoNewline
    Write-Host " metric for detection." -ForegroundColor White
    Write-Host ""
    
    Write-Host "Visited Entries:" -ForegroundColor Green
    Write-Host "  • How many objects Active Directory physically examined" -ForegroundColor Gray
    Write-Host "  • AD walks the tree, checking each object against filter" -ForegroundColor Gray
    Write-Host "  • Each evaluation = 1 visit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Returned Entries:" -ForegroundColor Green
    Write-Host "  • How many objects matched the filter" -ForegroundColor Gray
    Write-Host "  • These are sent back to the client" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The Ratio:" -ForegroundColor Magenta
    Write-Host "  " -NoNewline
    Write-Host "Efficiency = (Returned / Visited) × 100" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host ""
    
    # Scenario 1
    Write-Host "Scenario 1: Normal Admin Query" -ForegroundColor White
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(cn=jsmith)" -ForegroundColor Cyan
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "1" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "1" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "100% ✓" -ForegroundColor Green -NoNewline
    Write-Host " (Perfect - knew exactly what to find)" -ForegroundColor Gray
    Write-Host ""
    
    # Scenario 2
    Write-Host "Scenario 2: Legitimate Broad Query" -ForegroundColor White
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(department=Sales)" -ForegroundColor Cyan
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "5,234" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "487" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "9.3% ✓" -ForegroundColor Green -NoNewline
    Write-Host " (Reasonable - filtering by department)" -ForegroundColor Gray
    Write-Host ""
    
    # Scenario 3
    Write-Host "Scenario 3: BloodHound Mass Enumeration" -ForegroundColor White
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectclass=*)" -ForegroundColor Cyan
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "52,847" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "5,234" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "9.9% 🚨" -ForegroundColor Red -NoNewline
    Write-Host " (Suspicious - grabbing everything)" -ForegroundColor Gray
    Write-Host ""
    
    # Scenario 4
    Write-Host "Scenario 4: Modern SharpHound GUID Lookup" -ForegroundColor White
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectguid=\xx\xx\xx\xx...)" -ForegroundColor Cyan
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "2" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "0" -ForegroundColor Red
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "0% 🚨" -ForegroundColor Red -NoNewline
    Write-Host " (CRITICAL - looking for non-existent object)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "USED INDEXES" -ForegroundColor Yellow
    Write-Host "────────────" -ForegroundColor DarkGray
    Write-Host "Format: " -ForegroundColor Gray -NoNewline
    Write-Host "IndexName:AccessCount:Coverage;" -ForegroundColor Cyan
    Write-Host "Example: " -ForegroundColor Gray -NoNewline
    Write-Host "Ancestors_index:1443:N;" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Common Index Types:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  • Ancestors_index" -ForegroundColor Cyan
    Write-Host "    Purpose: " -ForegroundColor Gray -NoNewline
    Write-Host "Object hierarchy and container relationships" -ForegroundColor White
    Write-Host "    High count indicates: " -ForegroundColor Gray -NoNewline
    Write-Host "Broad organizational enumeration" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  • PDN_index " -ForegroundColor Cyan -NoNewline
    Write-Host "(Parent Distinguished Name)" -ForegroundColor Gray
    Write-Host "    Purpose: " -ForegroundColor Gray -NoNewline
    Write-Host "Parent-child relationships" -ForegroundColor White
    Write-Host ""
    Write-Host "  • GUID_index" -ForegroundColor Cyan
    Write-Host "    Purpose: " -ForegroundColor Gray -NoNewline
    Write-Host "Direct object lookups by GUID" -ForegroundColor White
    Write-Host "    Pattern: " -ForegroundColor Gray -NoNewline
    Write-Host "Modern SharpHound uses this heavily" -ForegroundColor Red
    Write-Host ""
    Write-Host "No Index Usage " -ForegroundColor Red -NoNewline
    Write-Host "(0 or <unknown>):" -ForegroundColor Gray
    Write-Host "  This means a TABLE SCAN occurred - AD examined every object" -ForegroundColor White
    Write-Host "  without using any indexes. This is:" -ForegroundColor White
    Write-Host "    • Extremely expensive (performance-wise)" -ForegroundColor Gray
    Write-Host "    • Highly indicative of reconnaissance" -ForegroundColor Red
    Write-Host "    • Adds +0.15 to suspicion score" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 5: Bugs Fixed
    Write-Host "5. COMMON ISSUES & BUGS WE FIXED" -ForegroundColor Cyan
    Write-Host "─────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "BUG #1: THE PARSING NIGHTMARE " -ForegroundColor Red -NoNewline
    Write-Host "(v2.4 Fix)" -ForegroundColor Gray
    Write-Host "─────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "PROBLEM:" -ForegroundColor Yellow
    Write-Host "  Event 1644 logs for ADCS/PKI certificate queries were MALFORMED" -ForegroundColor White
    Write-Host ""
    Write-Host "  Example event:" -ForegroundColor Gray
    Write-Host "  Filter: cn=configuration,cn=services,cn=public key services..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Our parser saw '=' signs and thought:" -ForegroundColor White
    Write-Host "  'This is a filter with equals operators!'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Result: " -ForegroundColor White -NoNewline
    Write-Host "FALSE POSITIVE EXPLOSION" -ForegroundColor Red
    Write-Host "    • Every PKI query flagged as suspicious" -ForegroundColor Gray
    Write-Host "    • 80% of alerts were certificate infrastructure queries" -ForegroundColor Gray
    Write-Host "    • Analysts overwhelmed with noise" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "ROOT CAUSE:" -ForegroundColor Yellow
    Write-Host "  Microsoft logs the DISTINGUISHED NAME in the Filter field" -ForegroundColor White
    Write-Host "  for certain PKI queries, NOT an actual LDAP filter." -ForegroundColor White
    Write-Host ""
    
    Write-Host "THE FIX:" -ForegroundColor Green
    Write-Host "  Enhanced filter validation:" -ForegroundColor White
    Write-Host "    1. Check if 'Filter' field is actually a DN" -ForegroundColor Gray
    Write-Host "    2. Skip detection for malformed/DN-based filter fields" -ForegroundColor Gray
    Write-Host "    3. Add special handling for PKI infrastructure queries" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Code Fix:" -ForegroundColor Cyan
    Write-Host '  if ($filter -match ' -ForegroundColor Gray -NoNewline
    Write-Host "'^cn=.*,cn=.*,dc=.*,dc='" -ForegroundColor Yellow -NoNewline
    Write-Host ' -and $filter -notmatch ' -ForegroundColor Gray -NoNewline
    Write-Host "'\(.*\)'" -ForegroundColor Yellow -NoNewline
    Write-Host ') {' -ForegroundColor Gray
    Write-Host '      # This is a DN, not a filter - skip or handle specially' -ForegroundColor DarkGray
    Write-Host '      continue' -ForegroundColor Gray
    Write-Host '  }' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Impact: " -ForegroundColor White -NoNewline
    Write-Host "Reduced false positives by ~80%" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "LESSON LEARNED:" -ForegroundColor Magenta
    Write-Host "  Always validate your assumptions about log format." -ForegroundColor White
    Write-Host "  Microsoft's Event ID 1644 is not perfectly consistent." -ForegroundColor White
    Write-Host ""
    
    Pause-ForUser
    
    Write-Host "BUG #2: THE 0% EFFICIENCY BLINDSPOT " -ForegroundColor Red -NoNewline
    Write-Host "(v2.5 Fix)" -ForegroundColor Gray
    Write-Host "───────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "PROBLEM:" -ForegroundColor Yellow
    Write-Host "  Modern SharpHound was NOT being detected!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Example missed query:" -ForegroundColor Gray
    Write-Host "    Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectguid=\5c\3e\a7\2f...)" -ForegroundColor Cyan
    Write-Host "    Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "2" -ForegroundColor White
    Write-Host "    Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "0" -ForegroundColor Red
    Write-Host "    Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "0%" -ForegroundColor Red
    Write-Host "    Score: " -ForegroundColor Gray -NoNewline
    Write-Host "0.15 (LOW - no alert generated!)" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "WHY WE MISSED IT:" -ForegroundColor Yellow
    Write-Host "  Our efficiency detection logic:" -ForegroundColor White
    Write-Host "    • < 5% efficiency: +0.3 points" -ForegroundColor Gray
    Write-Host "    • Has indexes: +0.0 points" -ForegroundColor Gray
    Write-Host "    • Total: 0.3 (below alert threshold)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  But 0% efficiency is SPECIAL:" -ForegroundColor Red
    Write-Host "    • Visited entries but returned NOTHING" -ForegroundColor White
    Write-Host "    • This is GUID enumeration (brute force object discovery)" -ForegroundColor White
    Write-Host "    • Only reconnaissance tools do this" -ForegroundColor White
    Write-Host "    • Normal admins don't query non-existent GUIDs" -ForegroundColor White
    Write-Host ""
    
    Write-Host "THE FIX:" -ForegroundColor Green
    Write-Host "  Added ZeroEfficiencyBoost:" -ForegroundColor White
    Write-Host ""
    Write-Host '  if ($efficiency -eq 0 -and $visitedEntries -gt 0) {' -ForegroundColor Gray
    Write-Host '      $score += 0.3  ' -ForegroundColor Green -NoNewline
    Write-Host '# Standard efficiency penalty' -ForegroundColor DarkGray
    Write-Host '      $score += 0.3  ' -ForegroundColor Green -NoNewline
    Write-Host '# ADDITIONAL zero-efficiency boost' -ForegroundColor DarkGray
    Write-Host '      $reasons += "Zero efficiency (visited $visitedEntries, returned 0)"' -ForegroundColor Gray
    Write-Host '  }' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Result: " -ForegroundColor White -NoNewline
    Write-Host "Modern SharpHound now generates CRITICAL alerts!" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "IMPACT:" -ForegroundColor Magenta
    Write-Host "  • Before: " -ForegroundColor Gray -NoNewline
    Write-Host "9 detections" -ForegroundColor Yellow -NoNewline
    Write-Host " (only high-volume queries)" -ForegroundColor Gray
    Write-Host "  • After:  " -ForegroundColor Gray -NoNewline
    Write-Host "47 detections" -ForegroundColor Green -NoNewline
    Write-Host " (includes targeted GUID lookups)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "LESSON LEARNED:" -ForegroundColor Magenta
    Write-Host "  Zero values are not 'no signal' - they're STRONG signal." -ForegroundColor White
    Write-Host "  Mathematical edge cases often reveal important patterns." -ForegroundColor White
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 6: Real-World Examples
    Write-Host "6. REAL-WORLD EXAMPLES" -ForegroundColor Cyan
    Write-Host "───────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "EXAMPLE 1: Classic BloodHound Collection" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Attack: " -ForegroundColor Red -NoNewline
    Write-Host "Default SharpHound.exe --CollectAllProperties" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Event Pattern:" -ForegroundColor Green
    Write-Host "  Time: " -ForegroundColor Gray -NoNewline
    Write-Host "02:41:45-02:42:30 (45 seconds)" -ForegroundColor White
    Write-Host "  Client: " -ForegroundColor Gray -NoNewline
    Write-Host "10.1.1.14" -ForegroundColor Cyan
    Write-Host "  Events: " -ForegroundColor Gray -NoNewline
    Write-Host "64 queries" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Sample Query:" -ForegroundColor Cyan
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectclass=*)" -ForegroundColor Yellow
    Write-Host "  Scope: " -ForegroundColor Gray -NoNewline
    Write-Host "base" -ForegroundColor White
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "52,847" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "5,234" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "9.9%" -ForegroundColor Red
    Write-Host "  Server Controls: " -ForegroundColor Gray -NoNewline
    Write-Host "SDFlags:0x5" -ForegroundColor Red
    Write-Host ""
    
    Write-Host "Detection Score: " -ForegroundColor White -NoNewline
    Write-Host "0.95 " -ForegroundColor Red -NoNewline
    Write-Host "(CRITICAL)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Reasons:" -ForegroundColor Green
    Write-Host "  • Critical efficiency: 9.9%" -ForegroundColor Gray
    Write-Host "  • Volume anomaly: 312σ above baseline" -ForegroundColor Gray
    Write-Host "  • High pages/object: 17.2" -ForegroundColor Gray
    Write-Host "  • Base scope object enumeration" -ForegroundColor Gray
    Write-Host "  • SDFlags ACL enumeration" -ForegroundColor Gray
    Write-Host "  • Excessive attributes (67 requested)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Alert: " -ForegroundColor White -NoNewline
    Write-Host "✓ Detected in real-time" -ForegroundColor Green
    Write-Host "Response: " -ForegroundColor Yellow -NoNewline
    Write-Host "Investigate 10.1.1.14 immediately" -ForegroundColor Red
    Write-Host ""
    
    Pause-ForUser
    
    Write-Host "EXAMPLE 2: Stealthy Modified SharpHound" -ForegroundColor Yellow
    Write-Host "────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Attack: " -ForegroundColor Red -NoNewline
    Write-Host "Custom SharpHound with evasion techniques" -ForegroundColor White
    Write-Host "  • Modified filters to avoid signatures" -ForegroundColor Gray
    Write-Host "  • Rate-limited (1 query per 5 seconds)" -ForegroundColor Gray
    Write-Host "  • Reduced attribute requests (10 vs 67)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Event Pattern:" -ForegroundColor Green
    Write-Host "  Time: " -ForegroundColor Gray -NoNewline
    Write-Host "14:22:15-14:45:33 (23 minutes)" -ForegroundColor White
    Write-Host "  Client: " -ForegroundColor Gray -NoNewline
    Write-Host "10.1.1.28" -ForegroundColor Cyan
    Write-Host "  Events: " -ForegroundColor Gray -NoNewline
    Write-Host "276 queries (spread out)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Sample Query:" -ForegroundColor Cyan
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(objectclass=user) " -ForegroundColor Yellow -NoNewline
    Write-Host " ← Modified from default" -ForegroundColor DarkGray
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "12,456" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "5,234" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "42% " -ForegroundColor Yellow -NoNewline
    Write-Host " ← Better than typical BloodHound" -ForegroundColor DarkGray
    Write-Host "  Attributes: " -ForegroundColor Gray -NoNewline
    Write-Host "10 total (reduced)" -ForegroundColor White
    Write-Host "  Server Controls: " -ForegroundColor Gray -NoNewline
    Write-Host "SDFlags:0x4" -ForegroundColor Red
    Write-Host ""
    
    Write-Host "Detection Score: " -ForegroundColor White -NoNewline
    Write-Host "0.63 " -ForegroundColor Yellow -NoNewline
    Write-Host "(HIGH)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Reasons:" -ForegroundColor Green
    Write-Host "  • Volume anomaly: 178σ above baseline" -ForegroundColor Gray
    Write-Host "  • High pages/object: 8.7" -ForegroundColor Gray
    Write-Host "  • SDFlags enumeration" -ForegroundColor Gray
    Write-Host "  • Sustained pattern over time" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Alert: " -ForegroundColor White -NoNewline
    Write-Host "✓ Detected" -ForegroundColor Green -NoNewline
    Write-Host " (took longer but still caught)" -ForegroundColor Gray
    Write-Host "Why: " -ForegroundColor Yellow -NoNewline
    Write-Host "Statistical analysis caught volume anomaly despite evasion" -ForegroundColor White
    Write-Host ""
    
    Pause-ForUser
    
    Write-Host "EXAMPLE 3: False Positive - Legitimate Admin" -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Activity: " -ForegroundColor Green -NoNewline
    Write-Host "Exchange Online migration script" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Event Pattern:" -ForegroundColor Green
    Write-Host "  Time: " -ForegroundColor Gray -NoNewline
    Write-Host "11:30:00-11:45:00 (15 minutes)" -ForegroundColor White
    Write-Host "  Client: " -ForegroundColor Gray -NoNewline
    Write-Host "10.1.1.100 (known admin workstation)" -ForegroundColor Cyan
    Write-Host "  Events: " -ForegroundColor Gray -NoNewline
    Write-Host "45 queries" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Sample Query:" -ForegroundColor Cyan
    Write-Host "  Filter: " -ForegroundColor Gray -NoNewline
    Write-Host "(mail=*)" -ForegroundColor Yellow
    Write-Host "  Visited: " -ForegroundColor Gray -NoNewline
    Write-Host "8,234" -ForegroundColor White
    Write-Host "  Returned: " -ForegroundColor Gray -NoNewline
    Write-Host "5,187" -ForegroundColor White
    Write-Host "  Efficiency: " -ForegroundColor Gray -NoNewline
    Write-Host "63% " -ForegroundColor Green -NoNewline
    Write-Host " ← Good efficiency" -ForegroundColor DarkGray
    Write-Host "  Attributes: " -ForegroundColor Gray -NoNewline
    Write-Host "mail,proxyaddresses,mailnickname" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Detection Score: " -ForegroundColor White -NoNewline
    Write-Host "0.42 " -ForegroundColor Gray -NoNewline
    Write-Host "(MEDIUM - below alert threshold)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Reasons:" -ForegroundColor Green
    Write-Host "  • Volume anomaly: 102σ above baseline" -ForegroundColor Gray
    Write-Host "  • Good efficiency (not reconnaissance pattern)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Alert: " -ForegroundColor White -NoNewline
    Write-Host "✗ No alert" -ForegroundColor Green -NoNewline
    Write-Host " (score below 0.5 threshold)" -ForegroundColor Gray
    Write-Host "Why: " -ForegroundColor Yellow -NoNewline
    Write-Host "High efficiency and legitimate use pattern" -ForegroundColor White
    Write-Host "Action: " -ForegroundColor Yellow -NoNewline
    Write-Host "Logged but not displayed (working as intended)" -ForegroundColor Green
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 7: Advanced Configuration
    Write-Host "7. ADVANCED CONFIGURATION" -ForegroundColor Cyan
    Write-Host "─────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "TUNING DETECTION THRESHOLDS" -ForegroundColor Yellow
    Write-Host "────────────────────────────" -ForegroundColor DarkGray
    Write-Host "Location: " -ForegroundColor Gray -NoNewline
    Write-Host '$script:Config.Thresholds' -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "# For more aggressive detection (lab/high-security):" -ForegroundColor DarkGray
    Write-Host 'Thresholds = @{' -ForegroundColor Gray
    Write-Host '    EfficiencyCritical = ' -ForegroundColor Gray -NoNewline
    Write-Host '3.0       ' -ForegroundColor Cyan -NoNewline
    Write-Host '# ← Lower = more sensitive' -ForegroundColor DarkGray
    Write-Host '    EfficiencyWarning = ' -ForegroundColor Gray -NoNewline
    Write-Host '10.0' -ForegroundColor Cyan
    Write-Host '    StandardDeviations = ' -ForegroundColor Gray -NoNewline
    Write-Host '2.0       ' -ForegroundColor Cyan -NoNewline
    Write-Host '# ← Detect smaller anomalies' -ForegroundColor DarkGray
    Write-Host '}' -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "# For reducing false positives (production):" -ForegroundColor DarkGray
    Write-Host 'Thresholds = @{' -ForegroundColor Gray
    Write-Host '    EfficiencyCritical = ' -ForegroundColor Gray -NoNewline
    Write-Host '10.0      ' -ForegroundColor Cyan -NoNewline
    Write-Host '# ← Higher = less sensitive' -ForegroundColor DarkGray
    Write-Host '    EfficiencyWarning = ' -ForegroundColor Gray -NoNewline
    Write-Host '25.0' -ForegroundColor Cyan
    Write-Host '    StandardDeviations = ' -ForegroundColor Gray -NoNewline
    Write-Host '4.0       ' -ForegroundColor Cyan -NoNewline
    Write-Host '# ← Only flag major anomalies' -ForegroundColor DarkGray
    Write-Host '}' -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "BASELINE REFRESH STRATEGIES" -ForegroundColor Yellow
    Write-Host "────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Option 1: Rolling Baseline " -ForegroundColor Green -NoNewline
    Write-Host "(RECOMMENDED)" -ForegroundColor Cyan
    Write-Host "  • Rebuild baseline monthly" -ForegroundColor Gray
    Write-Host "  • Always use last 24-48 hours" -ForegroundColor Gray
    Write-Host "  • Adapts to gradual environment changes" -ForegroundColor Gray
    Write-Host "  • Schedule: 1st of each month, 2 AM" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Option 2: Seasonal Baseline" -ForegroundColor Green
    Write-Host "  • Build separate baselines for:" -ForegroundColor Gray
    Write-Host "    - Business hours (8 AM - 6 PM)" -ForegroundColor Gray
    Write-Host "    - After hours (6 PM - 8 AM)" -ForegroundColor Gray
    Write-Host "    - Weekend" -ForegroundColor Gray
    Write-Host "  • Apply appropriate baseline based on time" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Option 3: Static Baseline" -ForegroundColor Green
    Write-Host "  • Build once during 'known good' period" -ForegroundColor Gray
    Write-Host "  • Never refresh (use for stable environments)" -ForegroundColor Gray
    Write-Host "  • Risk: " -ForegroundColor Gray -NoNewline
    Write-Host "Drifts over time, false positives increase" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
    Clear-Host
    
    # Section 10: Performance Tuning
    Write-Host "10. PERFORMANCE TUNING" -ForegroundColor Cyan
    Write-Host "──────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "OPTIMIZATION STRATEGIES" -ForegroundColor Yellow
    Write-Host "───────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "Strategy 1: Reduce Monitoring Frequency" -ForegroundColor Green
    Write-Host "  Default: " -ForegroundColor Gray -NoNewline
    Write-Host "2 second polling interval" -ForegroundColor White
    Write-Host "  For lower impact: " -ForegroundColor Gray -NoNewline
    Write-Host "5-10 seconds" -ForegroundColor Cyan
    Write-Host "  For scheduled scans: " -ForegroundColor Gray -NoNewline
    Write-Host "Run hourly via Task Scheduler" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Strategy 2: Baseline Sampling" -ForegroundColor Green
    Write-Host "  Instead of analyzing all events:" -ForegroundColor Gray
    Write-Host "  • Sample 10% of events for baseline" -ForegroundColor White
    Write-Host "  • Reduces processing time by 90%" -ForegroundColor White
    Write-Host "  • Still statistically valid" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  Code:" -ForegroundColor Cyan
    Write-Host '  $events = Get-WinEvent -FilterHashtable @{' -ForegroundColor Gray
    Write-Host '      LogName="Directory Service"' -ForegroundColor Gray
    Write-Host '      ID=1644' -ForegroundColor Gray
    Write-Host '  }' -ForegroundColor Gray
    Write-Host '  $sampledEvents = $events | Get-Random -Count ([int]($events.Count * 0.1))' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  • NOT recommended for production" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "EXPECTED PERFORMANCE IMPACT" -ForegroundColor Yellow
    Write-Host "────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  CPU: " -ForegroundColor Gray -NoNewline
    Write-Host "< 1% average " -ForegroundColor Green -NoNewline
    Write-Host "(spikes to 3-5% during analysis)" -ForegroundColor Gray
    Write-Host "  Memory: " -ForegroundColor Gray -NoNewline
    Write-Host "50-100 MB" -ForegroundColor Green
    Write-Host "  Disk I/O: " -ForegroundColor Gray -NoNewline
    Write-Host "Minimal (mostly reads)" -ForegroundColor Green
    Write-Host "  Network: " -ForegroundColor Gray -NoNewline
    Write-Host "0 (local processing only)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Event Log Growth:" -ForegroundColor Magenta
    Write-Host "  Level 2 " -ForegroundColor Cyan -NoNewline
    Write-Host "(recommended):" -ForegroundColor Gray
    Write-Host "    • Normal environment: 100-500 events/hour" -ForegroundColor Gray
    Write-Host "    • Under attack: 1,000-5,000 events/hour" -ForegroundColor Gray
    Write-Host "    • Daily growth: ~100-500 MB" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Level 5 " -ForegroundColor Red -NoNewline
    Write-Host "(lab only):" -ForegroundColor Gray
    Write-Host "    • Normal environment: 1,000-10,000 events/hour" -ForegroundColor Gray
    Write-Host "    • Daily growth: 1-5 GB" -ForegroundColor Gray
    Write-Host "    • " -ForegroundColor Gray -NoNewline
    Write-Host "NOT recommended for production" -ForegroundColor Red
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    # Footer
    Write-Host "VERSION: " -ForegroundColor Gray -NoNewline
    Write-Host $script:Config.Version -ForegroundColor Cyan
    Write-Host "LAST UPDATED: " -ForegroundColor Gray -NoNewline
    Write-Host "October 2, 2025" -ForegroundColor White
    Write-Host "LICENSE: " -ForegroundColor Gray -NoNewline
    Write-Host "MIT" -ForegroundColor White
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    Pause-ForUser
}

function Show-Changelog {
    <#
    .SYNOPSIS
        Displays complete version history and changelog
    #>
    
    $changelog = @"
═══════════════════════════════════════════════════════════════
              BLOODHOUND DETECTOR - COMPLETE CHANGELOG
              Version History: v1.0 → v$($script:Config.Version)
              From Proof of Concept to Production System
═══════════════════════════════════════════════════════════════

OVERVIEW
────────
This changelog tracks the complete evolution from a blog post 
simulation demo through production-ready pattern-based detection.

═══════════════════════════════════════════════════════════════

VERSION 2.8.0 - Open Source Release (CURRENT)
Date: June 2026

OPEN SOURCE RELEASE:
✓ License changed from GNU GPL v3 to MIT License
✓ Author attribution: Andrew Schwartz
✓ Prepared for public GitHub repository

INTERNAL EVENT FILTERING:
✓ Added SAM (Security Account Manager) filtering
  - SAM internal queries now properly identified
  - Diagnostic output shows "SKIPPED: Internal event (SAM)"
  - Prevents false attribution of Windows internal queries
✓ Added LSASS filtering for completeness
✓ Improved diagnostic messages for internal events

DETECTION MATRIX:
┌─────────────────────────────────────────────────────────────┐
│ Tool              │ Detected │ Primary Indicators          │
├───────────────────┼──────────┼─────────────────────────────┤
│ SharpHound        │ ✓        │ SDFlags, Efficiency, Volume │
│ BloodHound.py     │ ✓        │ Patterns, Ancestors_index   │
│ SOAPHound         │ ✓        │ !(FALSE), Zero efficiency   │
│ ADExplorer        │ ✓        │ objectClass=*, Volume       │
│ ldapsearch        │ ✓        │ Patterns, Base enumeration  │
│ Custom Scripts    │ ✓        │ Behavioral anomalies        │
└─────────────────────────────────────────────────────────────┘

INTERNAL EVENTS (FILTERED):
• NTDSAPI - Directory service internal operations
• SAM - Security Account Manager queries  
• LSASS - Local Security Authority operations

WHY THIS MATTERS:
• Clean separation of external vs internal queries
• Reduced noise in monitoring output
• More accurate client attribution
• Ready for community contributions

═══════════════════════════════════════════════════════════════

VERSION 2.7.5-ULTIMATE - Production Hardening
Date: October 2025

STABILITY IMPROVEMENTS:
✓ Fixed HTML report DateTime/JSON timestamp handling
✓ Enhanced DFIR forensic report generation
✓ Improved IPv6 parsing (bracketed format with zone IDs)
✓ Comprehensive system diagnostics with 10-point checklist
✓ Better error handling throughout

═══════════════════════════════════════════════════════════════

VERSION 2.7.3 - Universal Pause & User Experience
Date: October 2, 2025

USER EXPERIENCE IMPROVEMENTS:
✓ Added pause after EVERY menu operation
  - Build Baseline: Pause before returning to menu
  - System Diagnostics: Pause with feedback
  - Real-Time Monitoring: Proper exit handling
  - Historical Analysis: Pause with results summary
  - System Status: Pause after display
  - Alert Analysis: Pause after each sub-operation
  - Clear Logs/Alerts: Confirmation + pause
  - Open Logs Folder: Feedback + pause
  - Documentation: Pause after viewing
  - Changelog: Pause after viewing
  - License: Pause after viewing

✓ Consistent color scheme throughout
  - Cyan headers and borders
  - White option titles
  - Gray descriptions (subtle, readable)
  - Color-coded severity indicators

✓ Improved HTML report generation
  - Success message with report details
  - Next steps guidance
  - Pause before returning to menu

WHY THIS MATTERS:
• Prevents instant menu return (no more missing information)
• Users can read operation results
• Consistent, predictable behavior
• Professional user experience
• Better feedback on all operations

TECHNICAL:
• New Pause-ForUser helper function
• Applied universally across all menu operations
• Integrated with existing color system
• No performance impact

═══════════════════════════════════════════════════════════════

VERSION 2.7.2 - Chart Rendering & Menu Fixes
Date: October 1, 2025

FIXES:
✓ Fixed JavaScript "Unexpected string" error in HTML reports
✓ Added separate "Clear Alert History" menu option
✓ Menu renumbered (Changelog #10, License #11, Exit #13)
✓ All 5 charts now render correctly in all browsers

═══════════════════════════════════════════════════════════════

VERSION 2.7.1 - Integration & Polish
Date: October 1, 2025

IMPROVEMENTS:
• Integrated all v2.7 pattern signatures
• Refined dual-threshold interaction
• Improved alert correlation
• Better baseline integration with patterns

═══════════════════════════════════════════════════════════════

VERSION 2.7 - Pattern-Based Detection Signatures
Date: October 2, 2025

MAJOR FEATURE: Seven reconnaissance pattern signatures

DETECTION PATTERNS:
1. Base Scope Object Enumeration (+0.5)
   Filter: (objectclass=*) with base scope
   → Catches: Systematic object property enumeration

2. SDFlags Enumeration (+0.4)
   Server controls: SDFlags:0x5 or SDFlags:0x4
   → Catches: ACL/security descriptor collection

3. sAMAccountType Enumeration (+0.3-0.4)
   Filter: (sAMAccountType=268435456|...)
   → Catches: Group enumeration queries

4. ADCS/PKI Certificate Enumeration (+0.3)
   Keywords: pki-enrollment-service, etc.
   → Catches: Certificate authority discovery

5. Excessive Attributes (+0.2)
   30+ attributes in single query
   → Catches: Mass data exfiltration

6. Configuration Container Queries (+0.2)
   Path: cn=configuration with services
   → Catches: Infrastructure discovery

7. Foreign Security Principals (+0.2)
   cn=foreignsecurityprincipals or S-1-5-*
   → Catches: Trust relationship discovery

WHY THIS MATTERS:
• Works without baseline (instant deployment!)
• Catches efficient SharpHound queries  
• Real-world pattern validation
• Complements statistical detection

THRESHOLDS:
• Critical efficiency: 5% (was 10%)
• High efficiency: 25% (was 50%)

═══════════════════════════════════════════════════════════════

VERSION 2.6 - Dual-Threshold Alerting System
Date: October 1, 2025

MAJOR FEATURE: Two-tier alerting

ALERT LEVELS:
• Log Threshold: ≥0.5 (logs HIGH + CRITICAL)
• Display Threshold: ≥0.7 (shows only CRITICAL)

BEHAVIORS:
• Silent logging for HIGH alerts (0.5-0.69)
• Big red alerts for CRITICAL (0.7+)
• Complete forensic record preserved
• Clean analyst monitoring experience

EXAMPLE:
Silent: [02:42:15] [HIGH] Logged - IP, Eff: 35%, Score: 0.55
Loud:   ╔══════════════════════════════════════╗
        ║  [CRITICAL] BloodHound Detected      ║
        ╚══════════════════════════════════════╝

═══════════════════════════════════════════════════════════════

VERSION 2.5 - Modern SharpHound Detection
Date: October 1, 2025

MAJOR IMPROVEMENT: Zero-efficiency detection

NEW DETECTION LOGIC:
IF efficiency = 0% (visited entries, returned 0):
   ZeroEfficiencyBoost = 1.5
   Base score *= ZeroEfficiencyBoost

THRESHOLDS TIGHTENED:
• Critical efficiency: 10% (was 20%)
• High efficiency: 50% (was 80%)

WHY THIS MATTERS:
Modern SharpHound uses highly targeted queries that
visit entries but return nothing, creating distinctive
0% efficiency patterns previously missed.

EXAMPLE CAUGHT:
Filter: (objectguid=\xx\xx\xx...)
Visited: 2, Returned: 0
Old: LOW (high efficiency)
New: CRITICAL (0% boost applied!)

═══════════════════════════════════════════════════════════════

VERSION 2.4 - Parsing & Accuracy Fixes
Date: September 30, 2025

CRITICAL FIX: ADCS PKI false positive explosion

PROBLEM:
Event 1644 logs for PKI queries were malformed:
"Filter: cn=configuration,cn=services,cn=public key services"
Parser incorrectly flagged "=" as query operator

PARSER IMPROVEMENTS:
• Fixed malformed filter detection
• Improved attribute list parsing
• Better non-standard log format handling
• Reduced false positives ~80%

═══════════════════════════════════════════════════════════════

VERSION 2.3 - Menu Consistency
Date: September 30, 2025

UPDATES:
• Version number consistency across displays
• Menu header shows correct version
• Report footers updated

═══════════════════════════════════════════════════════════════

VERSION 2.0 - The Great Consolidation
Date: September 30, 2025

MAJOR MILESTONE: All scripts merged into one

CONSOLIDATED FROM:
• Complete-LDAP-Monitor.ps1
• Enhanced-Monitor-LDAP.ps1
• Various launcher batch files
• Multiple timing mode scripts

UNIFIED FEATURES:
• Interactive menu system
• Build Baseline
• Real-Time Monitoring
• Historical Analysis
• System Status
• Alert Analysis
• Clear Event Logs
• Clear Alert History
• Open Logs Folder
• Documentation & Methodology
• Changelog & Version History
• License Information
• Exit

TIMING MODES:
• Instant: 0 seconds
• Real-Time: 15 seconds
• Quick: 1 minute
• Full: 5 minutes

NO MORE SIMULATION:
All detection uses real Event ID 1644 parsing.
Production-ready from day one.

═══════════════════════════════════════════════════════════════

VERSION 1.x Series - Evolution to Reality
Date: September 29-30, 2025

Multiple iterations with different script names transitioning
from simulation to real detection.

SCRIPT VARIANTS:
• Complete-LDAP-Monitor.ps1
• Enhanced-Monitor-LDAP.ps1
• RunNow.bat, LaunchDetection.bat

KEY DEVELOPMENTS:
• Real-time Event ID 1644 parsing
• Financial-style charts (clean visualization)
• Multiple timing options
• Baseline storage/retrieval
• Statistical analysis engine
• Alert logging mechanism

OUTPUT ENHANCEMENTS:
• Progress bars and animations
• Financial-style charts
• Clean grid layouts
• Time-series visualization
• Color-coded alerts

═══════════════════════════════════════════════════════════════

VERSION 1.0 - Proof of Concept (THE ORIGINAL)
Date: September 28, 2025

SCRIPT: BloodHound-Statistical-Detection-Complete.ps1
PURPOSE: Blog demonstration for "From Code to Sigma Part 5"

CORE FEATURES:
• Simulation mode (fake baseline, demo data)
• Five-phase detection architecture
• Statistical formula demonstration
• Mathematical probability scoring

FIVE PHASES:
1. Enumeration - Count AD objects
2. Baseline Creation - Calculate mean/stddev
3. Monitoring - Watch Event ID 1644
4. Mathematical Analysis - Apply formulas
5. Alerting - Generate probability-based alerts

KEY INNOVATION:
First script to propose environmental baseline
intelligence with mathematical probability scoring
vs. simple signature-based detection.

DEMONSTRATION EXAMPLE:
Composite BloodHound Probability: 0.923
• Volume: 134.21σ above baseline
• Efficiency: 0.09 (reconnaissance pattern)
• Pages Referenced: Excessive
• Index Usage: Table scan detected

FUNCTION: Start-BloodHoundDetection

IMPORTANT:
This was a SIMULATION for blog screenshots.
Generated fake baseline data to demonstrate concepts.
NO real Event ID 1644 parsing yet.

═══════════════════════════════════════════════════════════════

VERSION COMPARISON MATRIX

Feature                  v1.0  v1.x  v2.0  v2.5  v2.6  v2.7  v2.7.3
──────────────────────────────────────────────────────────────────
Simulation Mode           ✓     -     -     -     -     -     -
Real Event Parsing        -     ✓     ✓     ✓     ✓     ✓     ✓
Interactive Menu          -     -     ✓     ✓     ✓     ✓     ✓
Baseline Learning         ✓     ✓     ✓     ✓     ✓     ✓     ✓
Statistical Analysis      ✓     ✓     ✓     ✓     ✓     ✓     ✓
Zero Efficiency Boost     -     -     -     ✓     ✓     ✓     ✓
Dual Thresholds           -     -     -     -     ✓     ✓     ✓
Pattern Signatures        -     -     -     -     -     ✓     ✓
Universal Pause           -     -     -     -     -     -     ✓
HTML Reports              -     ✓     ✓     ✓     ✓     ✓     ✓
Alert Logging (JSON)      -     ✓     ✓     ✓     ✓     ✓     ✓
Historical Analysis       -     -     ✓     ✓     ✓     ✓     ✓
Consistent UX             -     -     -     -     -     -     ✓

═══════════════════════════════════════════════════════════════

SCRIPT NAME EVOLUTION

v1.0 Era:
• BloodHound-Statistical-Detection-Complete.ps1
• Start-BloodHoundDetection (function)

v1.x Era:
• Complete-LDAP-Monitor.ps1
• Enhanced-Monitor-LDAP.ps1
• RunNow.bat, LaunchDetection.bat

v2.0+ Era:
• BloodHound-Detector.ps1 (UNIFIED)
• Single script, menu-driven

═══════════════════════════════════════════════════════════════

KEY MILESTONES

Sept 28, 2025: v1.0 - Concept demonstration (simulation)
Sept 29, 2025: v1.1-1.x - Real detection transition
Sept 30, 2025: v2.0 - Unified interactive system
Sept 30, 2025: v2.3 - Version consistency
Sept 30, 2025: v2.4 - Parsing fixes
Oct 1, 2025:   v2.5 - Modern SharpHound (0% efficiency)
Oct 1, 2025:   v2.6 - Dual-threshold alerting
Oct 2, 2025:   v2.7 - Pattern-based signatures
Oct 2, 2025:   v2.7.1 - Complete integration
Oct 2, 2025:   v2.7.2 - Chart rendering fixes
Oct 2, 2025:   v2.7.3 - Universal pause & UX improvements

═══════════════════════════════════════════════════════════════

DEPLOYMENT RECOMMENDATIONS

For Learning:
• Use v1.0 (simulation mode)
• Understand concepts via blog post
• Study "The Math Never Lies"

For Lab Testing:
• Use v1.x (real parsing, charts)
• Learn Event ID 1644 patterns
• Run SharpHound and observe

For Production:
• Use v2.7.3+ (complete, hardened, polished UX)
• Build baseline during normal hours
• Enable pattern + statistical detection
• Review alerts daily

═══════════════════════════════════════════════════════════════

RELATED BLOG POST

"From Code to Sigma - Part 5: The Math Never Lies"

KEY CONCEPT:
Environment Intelligence + Statistical Analysis = Universal Detection

This approach works against:
• Known Tools (BloodHound, SharpHound)
• Modified Tools (Custom builds)
• New Tools (Future reconnaissance utilities)

Reconnaissance behavior is mathematically detectable through
LDAP query pattern analysis, regardless of tool implementation.

═══════════════════════════════════════════════════════════════

FUTURE CONSIDERATIONS

Potential Enhancements:
• Machine learning baseline refinement
• Additional patterns (ADFind, BloodHound.py, Certify)
• Windows Defender ATP integration
• Automated remediation
• Additional SIEM export formats
• Email/Slack alerting

Known Limitations:
• Requires Event ID 1644 enabled (Level 2+)
• Pattern signatures need periodic updates
• Baseline needs monthly refresh
• High-volume environments need log management

═══════════════════════════════════════════════════════════════

Current Stable Version: v$($script:Config.Version)
Original Concept: v1.0 (BloodHound-Statistical-Detection-Complete.ps1)
Last Updated: October 2, 2025

═══════════════════════════════════════════════════════════════
"@

    Clear-Host
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "    ║       BLOODHOUND DETECTOR - CHANGELOG & VERSION HISTORY      ║" -ForegroundColor Cyan
    Write-Host "    ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host $changelog -ForegroundColor White
    Write-Host ""
    
    Pause-ForUser
}

function Show-License {
    <#
    .SYNOPSIS
        Display license information
    #>
    
    Clear-Host
    
    $license = @"

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                   LICENSE INFORMATION                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

BloodHound Detector v$($script:Config.Version)
Copyright (C) 2025 Andrew Schwartz

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject
to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

═══════════════════════════════════════════════════════════════

ADDITIONAL TERMS

Attribution:
If you use, modify, or distribute this software, please maintain
attribution to the original author and provide a link to the
original repository.

Contributions:
Contributions are welcome! Please submit pull requests to the
official repository.

Support:
This software is provided as-is. While the author makes efforts
to maintain and improve it, no formal support is guaranteed.

═══════════════════════════════════════════════════════════════

THIRD-PARTY COMPONENTS

This software uses Chart.js for HTML report visualizations:
• Chart.js v4.4.0
• License: MIT
• Copyright (c) 2014-2024 Chart.js Contributors
• https://www.chartjs.org/

═══════════════════════════════════════════════════════════════

For more information about the MIT license, visit:
https://opensource.org/licenses/MIT.en.html

═══════════════════════════════════════════════════════════════
"@

    Write-Host $license -ForegroundColor White
    Write-Host ""
    
    Pause-ForUser
}

#endregion

#region Main Menu

function Show-Menu {
    <#
    .SYNOPSIS
        Display main menu
    #>
    
    Clear-Host
    
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "    ║                                                              ║" -ForegroundColor Cyan
    Write-Host ("    ║" + (" " * 15) + " 🐕 BloodHound Detector v$($script:Config.Version) 🐕" + (" " * 16) + "║") -ForegroundColor Magenta
    Write-Host "    ║                                                              ║" -ForegroundColor Cyan
    Write-Host "    ║        🎯 All-In-One LDAP Reconnaissance Detection 🎯              ║" -ForegroundColor Cyan
    Write-Host "    ║                                                              ║" -ForegroundColor Cyan
    Write-Host "    ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Menu options with proper colors
    Write-Host "    [1]  📊 " -NoNewline -ForegroundColor Cyan
    Write-Host "Build Baseline" -ForegroundColor White
    Write-Host "         Analyze normal LDAP traffic to establish baseline" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [2]  🔧 " -NoNewline -ForegroundColor Cyan
    Write-Host "System Diagnostics" -ForegroundColor White
    Write-Host "         Check Event ID 1644 status and system configuration" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [3]  👁  " -NoNewline -ForegroundColor Cyan
    Write-Host "Start Monitoring" -ForegroundColor White
    Write-Host "         Real-time detection of suspicious LDAP activity" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [4]  📜 " -NoNewline -ForegroundColor Cyan
    Write-Host "Analyze Historical Events" -ForegroundColor White
    Write-Host "         Scan past events for suspicious activity" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [5]  ☑  " -NoNewline -ForegroundColor Cyan
    Write-Host "Show Status" -ForegroundColor White
    Write-Host "         View current system status and recent activity" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [6]  🔍 " -NoNewline -ForegroundColor Yellow
    Write-Host "Alert Analysis" -ForegroundColor White
    Write-Host "         Review and analyze logged alerts" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [7]  🗑  " -NoNewline -ForegroundColor Yellow
    Write-Host "Clear Event Logs" -ForegroundColor White
    Write-Host "         Clear Event ID 1644 events (for clean baseline)" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [8]  🗑  " -NoNewline -ForegroundColor Yellow
    Write-Host "Clear Alert History" -ForegroundColor White
    Write-Host "         Delete the alert log file (bloodhound_alerts.jsonl)" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [9]  📂 " -NoNewline -ForegroundColor Green
    Write-Host "Open Logs Folder" -ForegroundColor White
    Write-Host "         Open Windows debug folder in Explorer" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [10] 📖 " -NoNewline -ForegroundColor Green
    Write-Host "Documentation & Methodology" -ForegroundColor White
    Write-Host "         Learn how detection works and best practices" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [11] 📋 " -NoNewline -ForegroundColor Green
    Write-Host "Changelog & Version History" -ForegroundColor White
    Write-Host "         View complete version history and updates" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [12] ⚖  " -NoNewline -ForegroundColor Green
    Write-Host "License Information" -ForegroundColor White
    Write-Host "         View MIT license and terms" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [13] 📋 " -NoNewline -ForegroundColor Green
    Write-Host "Generate DFIR Report" -ForegroundColor White
    Write-Host "         Create comprehensive forensic analysis report" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "    [14] 🚪 " -NoNewline -ForegroundColor Red
    Write-Host "Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "    ══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    $choice = Read-Host "    Select option (1-14)"
    return $choice
}

#endregion

#region Main Execution

# Main menu loop
do {
    $choice = Show-Menu
    
    switch ($choice) {
        '1' {
            $hours = Read-Host "`n    How many hours of data to analyze? (default: 24)"
            if ([string]::IsNullOrWhiteSpace($hours)) { $hours = 24 }
            Build-Baseline -Hours ([int]$hours)
        }
        '2' {
            Show-ComprehensiveSystemDiagnostics
        }
        '3' {
            Start-Monitoring
        }
        '4' {
            $hours = Read-Host "`n    How many hours to analyze? (default: 2)"
            if ([string]::IsNullOrWhiteSpace($hours)) { $hours = 2 }
            Analyze-History -Hours ([int]$hours)
        }
        '5' {
            Show-Status
        }
        '6' {
            Show-AlertAnalysis
        }
        '7' {
            Clear-EventLogs
        }
        '8' {
            Clear-AlertHistory
        }
        '9' {
            Open-LogsFolder
        }
        '10' {
            Show-Documentation
        }
        '11' {
            Show-Changelog
        }
        '12' {
            Show-License
        }
        '13' {
            if (Test-Path $script:Config.AlertLogFile) {
                $alerts = Get-Content $script:Config.AlertLogFile | ForEach-Object { $_ | ConvertFrom-Json }
                New-EnhancedDFIRReport -Alerts $alerts
            } else {
                New-EnhancedDFIRReport -Alerts @()
            }
        }
        '14' {
            Clear-Host
            Write-Host ""
            Write-Host "    👋 Thanks for using BloodHound Detector v$($script:Config.Version)!" -ForegroundColor Cyan
            Write-Host ""
            exit
        }
        default {
            Write-Host ""
            Write-Host "    [!] Invalid choice. Please select 1-14." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne '14')

#endregion
