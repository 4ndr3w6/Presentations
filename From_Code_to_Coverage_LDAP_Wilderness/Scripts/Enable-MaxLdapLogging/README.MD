# Enable-MaxLdapLogging.ps1

> 🔥 **EXTREME VERBOSITY MODE** - Turn your Domain Controller into a logging monster!

A PowerShell script that enables **maximum** LDAP and Directory Service diagnostic logging on Windows Domain Controllers. Perfect for lab environments where you need to capture every single LDAP query, bind, and directory operation.

## ⚠️ WARNING: LAB USE ONLY!

This script is designed for **lab and research environments only**. Running this in production will:
- Generate **massive** amounts of log data
- Impact DC performance (CPU and Disk I/O)
- Fill up your Directory Service event log rapidly

## What It Does

```
╔════════════════════════════════════════════════════════════════════════════╗
║                        🎯 MAXIMUM LOGGING ACHIEVED! 🎯                       ║
╠════════════════════════════════════════════════════════════════════════════╣
║ • Sets ALL 24 NTDS diagnostic categories to Level 5 (maximum)              ║
║ • Configures ultra-sensitive LDAP query thresholds                         ║
║ • Modifies AD-stored LDAP policies to log virtually ALL queries            ║
║ • Enables Directory Service access/change auditing                         ║
║ • Auto-generates Disable-MaxLdapLogging.ps1 for easy rollback              ║
╚════════════════════════════════════════════════════════════════════════════╝
```

### Phase 1: NTDS Diagnostic Logging (24 Categories)

| Category | Description |
|----------|-------------|
| 1 Knowledge Consistency Checker | KCC and replication topology |
| 2 Security Events | Security and authentication events |
| 3 ExDS Interface Events | Exchange Directory Service interface |
| 4 MAPI Interface Events | MAPI client interactions |
| 5 Replication Events | AD replication events |
| 6 Garbage Collection | Garbage collection and tombstone |
| 7 Internal Configuration | Internal AD configuration |
| 8 Directory Access | Directory access and queries |
| 9 Internal Processing | Internal LSASS processing |
| 10 Performance Counters | Performance counter updates |
| 11 Initialization/Termination | Service startup/shutdown |
| 12 Service Control | Service control manager events |
| 13 Name Resolution | DNS and name resolution |
| 14 Backup | Backup operations |
| **15 Field Engineering** | **LDAP query efficiency (Event 1644)** |
| **16 LDAP Interface Events** | **ALL LDAP operations** |
| 17 Setup | DCPROMO and setup events |
| 18 Global Catalog | Global Catalog operations |
| 19 Inter-site Messaging | Inter-site replication messaging |
| 20 Group Caching | Universal group caching |
| 21 Linked-Value Replication | Linked value replication |
| 22 DS RPC Client | RPC client operations |
| 23 DS RPC Server | RPC server operations |
| 24 DS Schema | Schema operations |

### Phase 2: Ultra-Sensitive Thresholds (Registry)

| Setting | Value | Effect |
|---------|-------|--------|
| Expensive Search Results Threshold | 100 | Log queries returning >100 results |
| Inefficient Search Results Threshold | 50 | Log queries visiting >50 entries |
| Search Time Threshold (msecs) | 10 | Log queries taking >10ms |

### Phase 3: AD-Stored LDAP Policies

These are the **real** settings that control Event 1644 generation:

| Policy | Value | Effect |
|--------|-------|--------|
| MaxQueryDuration | 1 | Log any query >1 second |
| ExpensiveSearchResultsThreshold | 1 | Log virtually ALL queries |
| InefficientSearchResultsThreshold | 1 | Log virtually ALL queries |

### Phase 4-5: Audit Policies & LDAP Signing

- Directory Service Access auditing (Success & Failure)
- Directory Service Changes auditing
- Directory Service Replication auditing
- LDAP Admin Limits logging

## Events You'll See

After running this script, your Directory Service log will capture:

| Event ID | Description |
|----------|-------------|
| **1644** | Expensive/Inefficient LDAP searches (now triggers on ALL!) |
| 1137 | Internal LDAP operations |
| 1138 | LDAP search details |
| 1139 | LDAP bind details |
| 1220 | LDAP client sessions |
| 1535 | LDAP connection events |
| 1643 | LDAP page searches |
| 1655 | LDAP timeout events |
| 2887 | LDAP over SSL/TLS events |
| 2889 | LDAP signing mismatches |
| 2884-2893 | Various LDAP security events |

## Usage

```powershell
# Run as Administrator on a Domain Controller
.\Enable-MaxLdapLogging.ps1

# You'll be prompted to type 'LAB' to confirm
Type 'LAB' to confirm this is a lab environment: LAB
```

## Example Output

```
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

[⚠] WARNING: This script enables MAXIMUM logging verbosity!
[⚠] This should ONLY be used in LAB environments!
[⚠] Production DCs will suffer performance impact!

Type 'LAB' to confirm this is a lab environment: LAB

[*] ENGAGING MAXIMUM VERBOSITY MODE...
================================================================================

[*] Preparing to unleash the logging kraken...
[✓] Ready to configure EXTREME logging!

[+] Phase 1: NTDS Diagnostic Logging Levels
    Registry Path: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics

[*] Setting ALL diagnostic categories to MAXIMUM (Level 5):
    [0 → 5] 1 Knowledge Consistency Checker - KCC and replication topology
    [0 → 5] 2 Security Events - Security and authentication events
    ...
    [0 → 5] 15 Field Engineering - LDAP query efficiency (1644 events)
    [0 → 5] 16 LDAP Interface Events - ALL LDAP operations
    ...

[+] Phase 3b: LDAP Query Policies (AD-stored)
[*] Setting MAXIMUM sensitivity LDAP policies directly in AD...
    [✓] MaxQueryDuration: 1
    [✓] ExpensiveSearchResultsThreshold: 1
    [✓] InefficientSearchResultsThreshold: 1
    [✓] LDAP policies committed to Active Directory!

    ██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗██╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝██║
    ██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ ██║
    ██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  ╚═╝
    ██║  ██║███████╗██║  ██║██████╔╝   ██║   ██╗
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝
                                                
    Your DC is now a LOGGING MONSTER! 🔥🔥🔥
```

## Useful Commands

### View LDAP Queries (Event 1644)
```powershell
Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1644}
```

### View LDAP Binds
```powershell
Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1139}
```

### View Failed/Timeout LDAP Operations
```powershell
Get-WinEvent -FilterHashtable @{LogName="Directory Service"; ID=1138,1535,1655}
```

### Export All Directory Service Events
```powershell
Get-WinEvent -FilterHashtable @{LogName="Directory Service"} | Export-Csv ldap.csv
```

### Increase Log Size (Recommended!)
```powershell
wevtutil sl "Directory Service" /ms:1073741824  # 1GB
```

### Verify LDAP Policy Settings
```cmd
(echo ldap policies & echo connections & echo connect to server localhost & echo q & echo show values & echo q & echo q) | ntdsutil
```

## Rollback

The script automatically generates `Disable-MaxLdapLogging.ps1` in the same directory:

```powershell
.\Disable-MaxLdapLogging.ps1
```

This will:
- Reset all 24 NTDS diagnostic categories to 0
- Restore LDAP policies to defaults (10000/1000/120)

## Requirements

- Windows Server Domain Controller
- PowerShell 5.1+
- Administrative privileges
- Domain Admin or equivalent (for AD-stored LDAP policy changes)

## Use Cases

- **Security Research**: Capture reconnaissance tool behavior (BloodHound, SharpHound, ADRecon)
- **Troubleshooting**: Debug LDAP query performance issues
- **Learning**: Understand what LDAP operations applications perform
- **Detection Engineering**: Develop detection signatures for LDAP-based attacks
- **Forensics Training**: Generate realistic LDAP activity for analysis exercises

## Related Tools

- [BloodHound-Detector](../BloodHound-Detector/) - Detect LDAP reconnaissance using Event 1644
- [Debug-Event1644](../Debug-Event1644/) - Parse and analyze Event 1644 data
- [Get-ADWSAttribution](../Get-ADWSAttribution/) - Attribute ADWS queries to source processes

## License

MIT License - Copyright (c) 2025 Andrew Schwartz

## Author

**Andrew Schwartz**

---

*"When in doubt, log everything. Sort it out later."* 🔥
