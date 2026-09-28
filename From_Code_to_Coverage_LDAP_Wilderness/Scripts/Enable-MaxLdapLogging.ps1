<#
.SYNOPSIS
    Enables MAXIMUM LDAP logging verbosity on Domain Controllers (LAB VERSION)

.DESCRIPTION
    This script cranks up ALL LDAP and Directory Service diagnostic logging to maximum levels.
    
    WARNING: This generates MASSIVE amounts of logs - LAB USE ONLY!

    What it does:
    - Sets all 24 NTDS diagnostic categories to level 5 (maximum)
    - Configures ultra-sensitive LDAP query thresholds via registry
    - Modifies AD-stored LDAP policies to log virtually ALL queries
    - Enables Directory Service access/change auditing
    - Auto-generates Disable-MaxLogging.ps1 for easy rollback

.NOTES
    Author: Andrew Schwartz
    Version: 3.1
    Requires: Domain Controller, PowerShell 5.1+, Administrative privileges

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

.EXAMPLE
    .\Enable-MaxLdapLogging.ps1
    Prompts for 'LAB' confirmation then enables maximum logging.
#>

# Epic ASCII Art Header
Write-Host @"

██╗      █████╗ ██████╗     ███╗   ███╗ █████╗ ██╗  ██╗    ██╗      ██████╗  ██████╗ ███████╗
██║     ██╔══██╗██╔══██╗    ████╗ ████║██╔══██╗╚██╗██╔╝    ██║     ██╔═══██╗██╔════╝ ██╔════╝
██║     ███████║██████╔╝    ██╔████╔██║███████║ ╚███╔╝     ██║     ██║   ██║██║  ███╗███████╗
██║     ██╔══██║██╔══██╗    ██║╚██╔╝██║██╔══██║ ██╔██╗     ██║     ██║   ██║██║   ██║╚════██║
███████╗██║  ██║██████╔╝    ██║ ╚═╝ ██║██║  ██║██╔╝ ██╗    ███████╗╚██████╔╝╚██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚═════╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝

            ╔═══════════════════════════════════════════════════════════════╗
            ║  🔥 EXTREME VERBOSITY MODE - LAB ENVIRONMENT ONLY! 🔥        ║
            ║  Warning: This will generate MASSIVE amounts of logging!      ║
            ╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Red

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for admin privileges
if (-not (Test-Administrator)) {
    Write-Host "[!] This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "[!] Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Warning prompt for lab confirmation
Write-Host "`n[⚠] WARNING: This script enables MAXIMUM logging verbosity!" -ForegroundColor Yellow
Write-Host "[⚠] This should ONLY be used in LAB environments!" -ForegroundColor Yellow
Write-Host "[⚠] Production DCs will suffer performance impact!" -ForegroundColor Red
$confirm = Read-Host "`nType 'LAB' to confirm this is a lab environment"

if ($confirm -ne 'LAB') {
    Write-Host "[!] Confirmation failed. Exiting for safety." -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] ENGAGING MAXIMUM VERBOSITY MODE..." -ForegroundColor Magenta
Write-Host ("=" * 80) -ForegroundColor DarkGray

# Simple loading message
Write-Host ""
Write-Host "[*] Preparing to unleash the logging kraken..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 500
Write-Host "[✓] Ready to configure EXTREME logging!" -ForegroundColor Green

try {
    # Main NTDS Diagnostics registry path
    $diagPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
    $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    
    Write-Host "`n[+] Phase 1: NTDS Diagnostic Logging Levels" -ForegroundColor Cyan
    Write-Host "    Registry Path: $diagPath" -ForegroundColor White
    
    # All NTDS diagnostic categories with descriptions
    $diagnosticSettings = @{
        "1 Knowledge Consistency Checker" = @{Value = 5; Desc = "KCC and replication topology"}
        "2 Security Events" = @{Value = 5; Desc = "Security and authentication events"}
        "3 ExDS Interface Events" = @{Value = 5; Desc = "Exchange Directory Service interface"}
        "4 MAPI Interface Events" = @{Value = 5; Desc = "MAPI client interactions"}
        "5 Replication Events" = @{Value = 5; Desc = "AD replication events"}
        "6 Garbage Collection" = @{Value = 5; Desc = "Garbage collection and tombstone"}
        "7 Internal Configuration" = @{Value = 5; Desc = "Internal AD configuration"}
        "8 Directory Access" = @{Value = 5; Desc = "Directory access and queries"}
        "9 Internal Processing" = @{Value = 5; Desc = "Internal LSASS processing"}
        "10 Performance Counters" = @{Value = 5; Desc = "Performance counter updates"}
        "11 Initialization/Termination" = @{Value = 5; Desc = "Service startup/shutdown"}
        "12 Service Control" = @{Value = 5; Desc = "Service control manager events"}
        "13 Name Resolution" = @{Value = 5; Desc = "DNS and name resolution"}
        "14 Backup" = @{Value = 5; Desc = "Backup operations"}
        "15 Field Engineering" = @{Value = 5; Desc = "LDAP query efficiency (1644 events)"}
        "16 LDAP Interface Events" = @{Value = 5; Desc = "ALL LDAP operations"}
        "17 Setup" = @{Value = 5; Desc = "DCPROMO and setup events"}
        "18 Global Catalog" = @{Value = 5; Desc = "Global Catalog operations"}
        "19 Inter-site Messaging" = @{Value = 5; Desc = "Inter-site replication messaging"}
        "20 Group Caching" = @{Value = 5; Desc = "Universal group caching"}
        "21 Linked-Value Replication" = @{Value = 5; Desc = "Linked value replication"}
        "22 DS RPC Client" = @{Value = 5; Desc = "RPC client operations"}
        "23 DS RPC Server" = @{Value = 5; Desc = "RPC server operations"}
        "24 DS Schema" = @{Value = 5; Desc = "Schema operations"}
    }
    
    Write-Host "`n[*] Setting ALL diagnostic categories to MAXIMUM (Level 5):" -ForegroundColor Yellow
    
    foreach ($setting in $diagnosticSettings.GetEnumerator()) {
        $keyName = $setting.Key
        $value = $setting.Value.Value
        $desc = $setting.Value.Desc
        
        # Get current value
        $currentVal = (Get-ItemProperty -Path $diagPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
        if ($null -eq $currentVal) { $currentVal = 0 }
        
        # Set new value
        Set-ItemProperty -Path $diagPath -Name $keyName -Value $value -Type DWORD
        
        # Verify the change was applied
        $newVal = (Get-ItemProperty -Path $diagPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
        
        # Display with fancy formatting
        $arrow = "→"
        if ($newVal -eq $value) {
            Write-Host "    [$currentVal $arrow " -NoNewline -ForegroundColor DarkGray
            Write-Host "$newVal" -NoNewline -ForegroundColor Green
            Write-Host "] $keyName" -NoNewline -ForegroundColor Cyan
            Write-Host " - $desc" -ForegroundColor DarkGray
        } else {
            Write-Host "    [FAILED] $keyName - Could not set value" -ForegroundColor Red
        }
    }
    
    Write-Host "`n[+] Phase 2: LDAP Query Thresholds (SUPER SENSITIVE MODE)" -ForegroundColor Cyan
    
    # Create Parameters key if it doesn't exist
    if (-not (Test-Path $paramPath)) {
        New-Item -Path $paramPath -Force | Out-Null
    }
    
    # Set EXTREMELY sensitive thresholds for maximum visibility
    $thresholds = @{
        "Expensive Search Results Threshold" = @{Value = 100; Desc = "Log queries returning >100 results"}
        "Inefficient Search Results Threshold" = @{Value = 50; Desc = "Log queries visiting >50 entries"}
        "Search Time Threshold (msecs)" = @{Value = 10; Desc = "Log queries taking >10ms"}
    }
    
    Write-Host "`n[*] Setting ULTRA-SENSITIVE search thresholds:" -ForegroundColor Yellow
    foreach ($threshold in $thresholds.GetEnumerator()) {
        # Use New-ItemProperty with Force to create or update
        New-ItemProperty -Path $paramPath -Name $threshold.Key -Value $threshold.Value.Value -PropertyType DWORD -Force | Out-Null
        
        # Verify
        $verifyVal = (Get-ItemProperty -Path $paramPath -Name $threshold.Key -ErrorAction SilentlyContinue).($threshold.Key)
        if ($verifyVal -eq $threshold.Value.Value) {
            Write-Host "    [✓] $($threshold.Key): " -NoNewline -ForegroundColor Green
            Write-Host "$($threshold.Value.Value)" -NoNewline -ForegroundColor Cyan
            Write-Host " - $($threshold.Value.Desc)" -ForegroundColor DarkGray
        } else {
            Write-Host "    [!] $($threshold.Key): Failed to set" -ForegroundColor Red
        }
    }
    
    # Enable LDAP query statistics
    Write-Host "`n[+] Phase 3: Additional LDAP Statistics & Logging" -ForegroundColor Cyan
    
    # Enable LDAP stats collection
    New-ItemProperty -Path $paramPath -Name "LDAP Interface Events" -Value 2 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    [✓] LDAP Interface Events enabled" -ForegroundColor Green
    
    # Configure LDAP policies directly in AD (more reliable than NTDSUTIL piping)
    Write-Host "`n[+] Phase 3b: LDAP Query Policies (AD-stored)" -ForegroundColor Cyan
    Write-Host "[*] Setting MAXIMUM sensitivity LDAP policies directly in AD..." -ForegroundColor Yellow
    
    try {
        # Get the Configuration naming context
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configNC = $rootDSE.configurationNamingContext
        
        # Path to Default Query Policy
        $policyDN = "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
        $policy = [ADSI]"LDAP://$policyDN"
        
        if ($policy) {
            # Get current lDAPAdminLimits values
            $currentLimits = $policy.lDAPAdminLimits
            
            Write-Host "    [i] Current LDAP Admin Limits:" -ForegroundColor DarkGray
            $currentLimits | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
            
            # Build new limits array - modify the three we care about, keep everything else
            $newLimits = @()
            $setMaxQuery = $false
            $setExpensive = $false
            $setInefficient = $false
            
            foreach ($limit in $currentLimits) {
                if ($limit -match "^MaxQueryDuration=") {
                    $newLimits += "MaxQueryDuration=1"
                    $setMaxQuery = $true
                } elseif ($limit -match "^ExpensiveSearchResultsThreshold=") {
                    $newLimits += "ExpensiveSearchResultsThreshold=1"
                    $setExpensive = $true
                } elseif ($limit -match "^InefficiientSearchResultsThreshold=") {
                    # Note: There's a typo in the actual AD attribute (double 'i')
                    $newLimits += "InefficiientSearchResultsThreshold=1"
                    $setInefficient = $true
                } else {
                    $newLimits += $limit
                }
            }
            
            # Add if not present
            if (-not $setMaxQuery) { $newLimits += "MaxQueryDuration=1" }
            if (-not $setExpensive) { $newLimits += "ExpensiveSearchResultsThreshold=1" }
            if (-not $setInefficient) { $newLimits += "InefficiientSearchResultsThreshold=1" }
            
            # Apply changes
            $policy.Put("lDAPAdminLimits", $newLimits)
            $policy.SetInfo()
            
            Write-Host "    [✓] MaxQueryDuration: 1" -ForegroundColor Green
            Write-Host "    [✓] ExpensiveSearchResultsThreshold: 1" -ForegroundColor Green
            Write-Host "    [✓] InefficientSearchResultsThreshold: 1" -ForegroundColor Green
            Write-Host "    [✓] LDAP policies committed to Active Directory!" -ForegroundColor Green
        } else {
            throw "Could not find Default Query Policy in AD"
        }
        
    } catch {
        Write-Host "    [!] Direct AD modification failed: $_" -ForegroundColor Yellow
        Write-Host "    [i] Run NTDSUTIL manually instead:" -ForegroundColor Cyan
        Write-Host @"
        
        ntdsutil
        ldap policies
        connections
        connect to server localhost
        q
        set MaxQueryDuration to 1
        set ExpensiveSearchResultsThreshold to 1
        set InefficientSearchResultsThreshold to 1
        commit changes
        q
        q
"@ -ForegroundColor White
    }
    
    # Enable additional audit policies
    Write-Host "`n[+] Phase 4: Directory Service Audit Policies" -ForegroundColor Cyan
    
    Write-Host "[*] Enabling Directory Service Access auditing..." -ForegroundColor Yellow
    $null = auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable 2>&1
    $null = auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable 2>&1
    $null = auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable 2>&1
    Write-Host "    [✓] Directory Service auditing enabled for Success & Failure" -ForegroundColor Green
    
    # Enable LDAP signing logging
    Write-Host "`n[+] Phase 5: LDAP Signing & Binding Events" -ForegroundColor Cyan
    New-ItemProperty -Path $paramPath -Name "LDAP Admin Limits" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    [✓] LDAP Admin Limits logging enabled" -ForegroundColor Green
    
    # Summary of what will be logged
    Write-Host "`n" -NoNewline
    Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║                        🎯 MAXIMUM LOGGING ACHIEVED! 🎯                       ║
╠════════════════════════════════════════════════════════════════════════════╣
║ LDAP POLICY THRESHOLDS (stored in AD via NTDSUTIL):                         ║
║ • MaxQueryDuration = 1 second (log slow queries)                            ║
║ • ExpensiveSearchResultsThreshold = 1 (log virtually ALL queries!)          ║
║ • InefficientSearchResultsThreshold = 1 (log virtually ALL queries!)        ║
║                                                                              ║
║ You will now see these events in Directory Service log:                      ║
║ • Event 1644 - Expensive/Inefficient LDAP searches (now triggers on ALL!)   ║
║ • Event 1138 - LDAP search details                                          ║
║ • Event 1139 - LDAP bind details                                            ║
║ • Event 2889 - LDAP signing mismatches                                      ║
║ • Event 2887 - LDAP over SSL/TLS events                                     ║
║ • Event 1535 - LDAP connection events                                       ║
║ • Event 1655 - LDAP timeout events                                          ║
║ • Event 1220 - LDAP client sessions                                         ║
║ • Event 1643 - LDAP page searches                                           ║
║ • Event 1137 - Internal LDAP operations                                     ║
║ • Event 2884-2893 - Various LDAP security events                           ║
║ • ALL Replication, KCC, Schema, and internal AD events at MAXIMUM detail    ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green
    
    # Performance warning
    Write-Host "`n⚠️  CRITICAL WARNINGS:" -ForegroundColor Red
    Write-Host "════════════════════" -ForegroundColor DarkRed
    Write-Host "• Your Directory Service log will fill up VERY quickly!" -ForegroundColor Yellow
    Write-Host "• Consider increasing log size: wevtutil sl 'Directory Service' /ms:1073741824" -ForegroundColor Yellow
    Write-Host "• DC performance WILL be impacted - CPU and Disk I/O will increase" -ForegroundColor Yellow
    Write-Host "• Some events require gpupdate /force or DC restart to fully activate" -ForegroundColor Yellow
    
    # Provide helpful commands
    Write-Host "`n📊 USEFUL COMMANDS TO VIEW YOUR LOGS:" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host '• All LDAP queries: Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1644}' -ForegroundColor White
    Write-Host '• LDAP binds: Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1139}' -ForegroundColor White
    Write-Host '• Failed LDAP: Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1138,1535,1655}' -ForegroundColor White
    Write-Host '• Export to CSV: Get-WinEvent -FilterHashtable @{LogName="Directory Service"} | Export-Csv ldap.csv' -ForegroundColor White
    
    Write-Host "`n🔍 VERIFY LDAP POLICY SETTINGS:" -ForegroundColor Cyan
    Write-Host "════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "Run this to confirm LDAP policies are set:" -ForegroundColor White
    Write-Host '  (echo ldap policies & echo connections & echo connect to server localhost & echo q & echo show values & echo q & echo q) | ntdsutil' -ForegroundColor Yellow
    
    # Create a disable script
    Write-Host "`n[*] Creating disable script for easy rollback..." -ForegroundColor Cyan
    
    $disableScript = @'
<#
.SYNOPSIS
    Disables maximum LDAP logging and restores defaults.
.DESCRIPTION
    Rollback script auto-generated by Enable-MaxLdapLogging.ps1
    Resets all NTDS diagnostic levels to 0 and LDAP policies to defaults.
#>

Write-Host "Disabling extreme logging..." -ForegroundColor Yellow

# Reset NTDS diagnostic registry values
$diagPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
Get-Item $diagPath | Select-Object -ExpandProperty Property | ForEach-Object {
    Set-ItemProperty -Path $diagPath -Name $_ -Value 0
}
Write-Host "[✓] All diagnostic logging disabled!" -ForegroundColor Green

# Reset LDAP policies to defaults via direct AD modification
Write-Host "Resetting LDAP policies to defaults..." -ForegroundColor Yellow
try {
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $configNC = $rootDSE.configurationNamingContext
    $policyDN = "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
    $policy = [ADSI]"LDAP://$policyDN"
    
    $currentLimits = $policy.lDAPAdminLimits
    $newLimits = @()
    
    foreach ($limit in $currentLimits) {
        if ($limit -match "^MaxQueryDuration=") {
            $newLimits += "MaxQueryDuration=120"
        } elseif ($limit -match "^ExpensiveSearchResultsThreshold=") {
            $newLimits += "ExpensiveSearchResultsThreshold=10000"
        } elseif ($limit -match "^InefficiientSearchResultsThreshold=") {
            $newLimits += "InefficiientSearchResultsThreshold=1000"
        } else {
            $newLimits += $limit
        }
    }
    
    $policy.Put("lDAPAdminLimits", $newLimits)
    $policy.SetInfo()
    Write-Host "[✓] LDAP policies reset to defaults (10000/1000/120)!" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not reset LDAP policies: $_" -ForegroundColor Yellow
    Write-Host "Run manually: ntdsutil -> ldap policies -> set values -> commit changes" -ForegroundColor Cyan
}

Write-Host "`n[✓] Logging disabled. DC performance should return to normal." -ForegroundColor Green
'@
    
    $disableScript | Out-File -FilePath ".\Disable-MaxLdapLogging.ps1" -Encoding UTF8
    Write-Host "    [✓] Created 'Disable-MaxLdapLogging.ps1' for easy rollback" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] An error occurred: $_" -ForegroundColor Red
    Write-Host @"
    
        ╔════════════════════════════════════════════════════════════════════╗
        ║                            ERROR! ✗                                ║
        ║                    Failed to configure maximum logging             ║
        ╚════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red
    exit 1
}

# Epic success ASCII art
Write-Host "`n" -NoNewline
Write-Host @"
    ██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗██╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝██║
    ██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ ██║
    ██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  ╚═╝
    ██║  ██║███████╗██║  ██║██████╔╝   ██║   ██╗
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝
                                                
    Your DC is now a LOGGING MONSTER! 🔥🔥🔥
    Check Event Viewer → Applications and Services → Directory Service
"@ -ForegroundColor Magenta

Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  Remember: This is LAB ONLY! Your logs are about to EXPLODE with detail! 💥" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
