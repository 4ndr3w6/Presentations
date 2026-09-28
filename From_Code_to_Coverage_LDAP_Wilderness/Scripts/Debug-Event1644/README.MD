# Debug-Event1644

**Diagnose Event ID 1644 parsing issues on Active Directory Domain Controllers**

This PowerShell script helps troubleshoot why LDAP monitoring and detection tools might not be seeing Event ID 1644 events. It analyzes the event structure, tests parsing logic, and identifies common issues.

## Purpose

When building LDAP detection agents (for BloodHound detection, etc.), Event ID 1644 parsing can fail silently due to:

- Different event property formats across Windows Server versions
- IP address format variations (`[::1]:port` vs `::1:port` vs `127.0.0.1:port`)
- Insufficient diagnostic logging levels
- Events being incorrectly filtered as "internal"

This script exposes exactly what your DC's Event ID 1644 events look like so you can fix your parsing logic.

## Requirements

- Administrative privileges on the Domain Controller
- PowerShell 5.1+
- Event ID 1644 logging enabled (Field Engineering level 2+)

## Usage

```powershell
# Run on the Domain Controller
.\Debug-Event1644.ps1
```

## What It Does

1. **Checks Configuration** - Verifies Event ID 1644 logging level in registry
2. **Retrieves Events** - Gets recent 1644 events (last 30 min, falls back to 24 hours)
3. **Analyzes Structure** - Shows raw property values for each event
4. **Tests Parsing** - Attempts to parse events using common logic patterns
5. **Identifies Issues** - Highlights why events might be filtered or skipped

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║              EVENT ID 1644 DEBUG ANALYZER                    ║
║          Diagnose Event Parsing Issues                       ║
╚══════════════════════════════════════════════════════════════╝

STEP 1: Checking Event ID 1644 Configuration
  Event ID 1644 Level: 5

STEP 2: Retrieving Recent Event ID 1644 Events
  Found 5 events in last 30 minutes

STEP 3: Analyzing Event ID 1644 Structure
==========================================

EVENT #1:
  Time: 12/11/2025 5:28:33 PM
  Record ID: 12345

  PROPERTIES ANALYSIS:
    Total Properties: 7
    [0] = 'DC=marvel,DC=local'
    [1] = '(&(objectClass=user)(objectCategory=CN=Person,...))'
    [2] = '53'
    [3] = '53'
    [4] = '[::1]:53149'
    [5] = 'subtree'
    [6] = 'nTSecurityDescriptor'

  PARSING ATTEMPT:
    Search Base: DC=marvel,DC=local
    Filter: (&(objectClass=user)(objectCategory=CN=Person,...))
    Visited Entries: 53
    Returned Entries: 53
    Client IP Raw: [::1]:53149
    
  IP PARSING TEST:
    Parsed IP (IPv6 brackets): ::1

  SKIP CHECKS:
    PASSED: Event should be processed
    Efficiency: 100%
```

## Common Issues Identified

| Issue | Symptom | Solution |
|-------|---------|----------|
| Low logging level | No events found | Set Field Engineering to 2+ |
| IP format mismatch | "IP PARSING FAILED" | Update regex patterns |
| Wrong property order | Incorrect field values | Adjust property indexes |
| Internal filtering | Events skipped | Review skip logic |

## Enabling Event ID 1644 Logging

If the script shows logging level is too low:

```powershell
# Set Field Engineering diagnostic level (generates Event 1644)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f
```

## Related Tools

- [Get-ADWSAttribution](../Get-ADWSAttribution/) - Correlates ADWS connections to LDAP queries with source IP attribution

## License

MIT License - See [LICENSE](../../LICENSE) for details.

## Author

Andrew Schwartz
