<#
.SYNOPSIS
    Debug Event ID 1644 parsing for your DC
.DESCRIPTION
    Shows exactly what Event ID 1644 events look like on your DC
    so we can fix the parsing logic in detection agents.
    Useful for troubleshooting LDAP monitoring and BloodHound detection.
.NOTES
    Requires administrative privileges on the Domain Controller
    Version: 1.0
    License: MIT License

    Copyright (c) 2025 Andrew Schwartz

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

#Requires -RunAsAdministrator

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              EVENT ID 1644 DEBUG ANALYZER                   ║" -ForegroundColor Cyan  
Write-Host "║          Diagnose Event Parsing Issues                      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Event ID 1644 logging level
Write-Host "STEP 1: Checking Event ID 1644 Configuration" -ForegroundColor Yellow
try {
    $diagLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering" -ErrorAction Stop
    Write-Host "  Event ID 1644 Level: $($diagLevel.'15 Field Engineering')" -ForegroundColor Green
    
    if ($diagLevel."15 Field Engineering" -lt 2) {
        Write-Host "  WARNING: Level should be 2+ for detection" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ERROR: Cannot read NTDS diagnostics" -ForegroundColor Red
}

Write-Host ""

# Get recent Event ID 1644 events
Write-Host "STEP 2: Retrieving Recent Event ID 1644 Events" -ForegroundColor Yellow
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Directory Service"
        ID = 1644
        StartTime = (Get-Date).AddMinutes(-30)
    } -MaxEvents 5 -ErrorAction Stop
    
    Write-Host "  Found $($events.Count) events in last 30 minutes" -ForegroundColor Green
    
    if ($events.Count -eq 0) {
        Write-Host "  No recent events - trying last 24 hours..." -ForegroundColor Yellow
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Directory Service"
            ID = 1644
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 5 -ErrorAction Stop
        
        Write-Host "  Found $($events.Count) events in last 24 hours" -ForegroundColor Green
    }
    
} catch {
    Write-Host "  ERROR: Cannot access Directory Service log: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($events.Count -eq 0) {
    Write-Host ""
    Write-Host "NO EVENT ID 1644 EVENTS FOUND!" -ForegroundColor Red
    Write-Host "This explains why the detection agent shows 0 detections." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "POSSIBLE CAUSES:" -ForegroundColor Yellow
    Write-Host "1. Event ID 1644 logging level too low" -ForegroundColor Gray
    Write-Host "2. No recent LDAP activity triggering events" -ForegroundColor Gray
    Write-Host "3. Events being generated but not captured" -ForegroundColor Gray
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "1. Generate some LDAP activity (AD Users and Computers queries)" -ForegroundColor White
    Write-Host "2. Run a simple LDAP query to trigger events" -ForegroundColor White
    Write-Host "3. Check if events appear in Event Viewer manually" -ForegroundColor White
    
    Write-Host ""
    Write-Host "GENERATING TEST LDAP ACTIVITY..." -ForegroundColor Yellow
    try {
        # Try to generate some LDAP activity
        $searcher = [adsisearcher]"(objectclass=user)"
        $searcher.PageSize = 10
        $searcher.SizeLimit = 5
        $result = $searcher.FindAll()
        Write-Host "  Generated LDAP query for $($result.Count) users" -ForegroundColor Green
        $result.Dispose()
    } catch {
        Write-Host "  Could not generate test LDAP activity: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Gray
    Read-Host
    exit 0
}

Write-Host ""

# Analyze event structure
Write-Host "STEP 3: Analyzing Event ID 1644 Structure" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor DarkGray

for ($i = 0; $i -lt $events.Count; $i++) {
    $event = $events[$i]
    
    Write-Host ""
    Write-Host "EVENT #$($i + 1):" -ForegroundColor Cyan
    Write-Host "  Time: $($event.TimeCreated)" -ForegroundColor Gray
    Write-Host "  Record ID: $($event.RecordId)" -ForegroundColor Gray
    Write-Host "  Message Preview:" -ForegroundColor Gray
    $messagePreview = $event.Message.Substring(0, [Math]::Min(150, $event.Message.Length))
    Write-Host "    $messagePreview..." -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "  PROPERTIES ANALYSIS:" -ForegroundColor Yellow
    
    $props = $event.Properties
    Write-Host "    Total Properties: $($props.Count)" -ForegroundColor Green
    
    for ($j = 0; $j -lt $props.Count; $j++) {
        $prop = $props[$j]
        $value = if ($prop.Value -eq $null) { "NULL" } else { $prop.Value.ToString() }
        Write-Host "    [$j] = '$value'" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "  PARSING ATTEMPT:" -ForegroundColor Yellow
    
    # Try to parse using your original logic
    try {
        if ($props.Count -ge 7) {
            $searchBase = $props[0].Value
            $filter = $props[1].Value
            $visitedEntries = if ($props[2].Value -match '^\d+$') { [int]$props[2].Value } else { "INVALID: '$($props[2].Value)'" }
            $returnedEntries = if ($props[3].Value -match '^\d+$') { [int]$props[3].Value } else { "INVALID: '$($props[3].Value)'" }
            $clientIPRaw = $props[4].Value
            $scope = if ($props.Count -gt 5) { $props[5].Value } else { "N/A" }
            $attributes = if ($props.Count -gt 6) { $props[6].Value } else { "N/A" }
            
            Write-Host "    Search Base: $searchBase" -ForegroundColor Green
            Write-Host "    Filter: $filter" -ForegroundColor Green
            Write-Host "    Visited Entries: $visitedEntries" -ForegroundColor Green
            Write-Host "    Returned Entries: $returnedEntries" -ForegroundColor Green
            Write-Host "    Client IP Raw: $clientIPRaw" -ForegroundColor Green
            Write-Host "    Scope: $scope" -ForegroundColor Green
            Write-Host "    Attributes: $attributes" -ForegroundColor Green
            
            # Test IP parsing
            Write-Host ""
            Write-Host "  IP PARSING TEST:" -ForegroundColor Yellow
            
            $clientIP = $null
            if ($clientIPRaw -match '^\[([0-9a-fA-F:]+(?:%\d+)?)\]:\d+$') {
                $clientIP = $matches[1]
                Write-Host "    Parsed IP (IPv6 brackets): $clientIP" -ForegroundColor Green
            }
            elseif ($clientIPRaw -match '^([0-9a-fA-F:]+):\d+$' -and $clientIPRaw -match '::') {
                $clientIP = $matches[1]
                Write-Host "    Parsed IP (IPv6 port): $clientIP" -ForegroundColor Green
            }
            elseif ($clientIPRaw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$') {
                $clientIP = $matches[1]
                Write-Host "    Parsed IP (IPv4 port): $clientIP" -ForegroundColor Green
            }
            elseif ($clientIPRaw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $clientIP = $clientIPRaw
                Write-Host "    Parsed IP (IPv4 plain): $clientIP" -ForegroundColor Green
            }
            elseif ($clientIPRaw -match '^[0-9a-fA-F:]+$' -and $clientIPRaw -match '::') {
                $clientIP = $clientIPRaw
                Write-Host "    Parsed IP (IPv6 plain): $clientIP" -ForegroundColor Green
            }
            else {
                Write-Host "    IP PARSING FAILED: '$clientIPRaw'" -ForegroundColor Red
                Write-Host "    This is likely why events are being filtered out!" -ForegroundColor Yellow
            }
            
            # Skip checks
            Write-Host ""
            Write-Host "  SKIP CHECKS:" -ForegroundColor Yellow
            
            if (-not $clientIP) {
                Write-Host "    SKIPPED: No valid IP extracted" -ForegroundColor Red
            }
            elseif ($clientIPRaw -eq "NTDSAPI" -or $filter -eq "NTDSAPI") {
                Write-Host "    SKIPPED: NTDSAPI internal event" -ForegroundColor Red
            }
            else {
                Write-Host "    PASSED: Event should be processed" -ForegroundColor Green
                
                # Calculate efficiency
                if ($visitedEntries -is [int] -and $returnedEntries -is [int]) {
                    $efficiency = if ($visitedEntries -gt 0) {
                        ($returnedEntries / $visitedEntries) * 100
                    } else {
                        100.0
                    }
                    Write-Host "    Efficiency: $([Math]::Round($efficiency, 2))%" -ForegroundColor Cyan
                    
                    if ($efficiency -eq 0) {
                        Write-Host "    DETECTION: Zero efficiency (BloodHound signature!)" -ForegroundColor Red
                    }
                    elseif ($efficiency -lt 5) {
                        Write-Host "    DETECTION: Critical efficiency" -ForegroundColor Yellow
                    }
                }
            }
            
        } else {
            Write-Host "    ERROR: Insufficient properties ($($props.Count) < 7)" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "    PARSING ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    if ($i -lt ($events.Count - 1)) {
        Write-Host ""
        Write-Host "  " + ("─" * 60) -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "DEBUG ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor DarkGray
Write-Host ""

# Summary and recommendations
Write-Host "SUMMARY & NEXT STEPS:" -ForegroundColor Cyan
Write-Host ""

if ($events.Count -gt 0) {
    Write-Host "✓ Event ID 1644 events are being generated" -ForegroundColor Green
    Write-Host "✓ Event structure can be analyzed" -ForegroundColor Green
    Write-Host ""
    Write-Host "LIKELY ISSUES:" -ForegroundColor Yellow
    Write-Host "1. IP parsing logic not matching your DC's format" -ForegroundColor White
    Write-Host "2. Events being filtered out as 'internal'" -ForegroundColor White  
    Write-Host "3. Field order different than expected" -ForegroundColor White
    Write-Host ""
    Write-Host "NEXT ACTIONS:" -ForegroundColor Cyan
    Write-Host "1. Fix the C# parsing logic based on the analysis above" -ForegroundColor White
    Write-Host "2. Test with a simple LDAP query to verify detection" -ForegroundColor White
    Write-Host "3. Monitor for zero efficiency patterns" -ForegroundColor White
} else {
    Write-Host "✗ No Event ID 1644 events found" -ForegroundColor Red
    Write-Host "✗ This explains the zero detections" -ForegroundColor Red
    Write-Host ""
    Write-Host "IMMEDIATE ACTIONS:" -ForegroundColor Yellow
    Write-Host "1. Generate LDAP activity (browse AD Users and Computers)" -ForegroundColor White
    Write-Host "2. Verify Event ID 1644 logging level" -ForegroundColor White
    Write-Host "3. Check Event Viewer manually" -ForegroundColor White
}

Write-Host ""
Write-Host "ADDITIONAL DEBUGGING:" -ForegroundColor Cyan
Write-Host "To generate LDAP activity for testing:" -ForegroundColor White
Write-Host "1. Open 'Active Directory Users and Computers'" -ForegroundColor Gray
Write-Host "2. Browse different OUs and expand user groups" -ForegroundColor Gray
Write-Host "3. Search for users or computers" -ForegroundColor Gray
Write-Host "4. Run this script again to see new events" -ForegroundColor Gray

Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Gray
Read-Host
