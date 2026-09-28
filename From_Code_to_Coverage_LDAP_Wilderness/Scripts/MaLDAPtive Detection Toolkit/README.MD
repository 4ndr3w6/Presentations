# MaLDAPtive Detection Toolkit

A PowerShell toolkit for testing LDAP obfuscation detection rules based on the [MaLDAPtive](https://github.com/MaLDAPtive/MaLDAPtive) research by Sabajete Elezaj and Daniel Bohannon.

## Overview

This toolkit provides two scripts designed to work together for testing and validating LDAP obfuscation detection capabilities:

| Script | Purpose | Run On |
|--------|---------|--------|
| `Get-LDAPClientLogs.ps1` | Collect client-side LDAP logs (LDAPMon) | Same client |
| `Get-DCLDAPLogs.ps1` | Collect DC Event 1644 logs | Domain Controller (or remote) |

## Critical: Detection Architecture

### Two-Tier Detection Strategy

LDAP obfuscation detection requires **both client-side and DC-side logging** for complete visibility:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LDAP Query Flow                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CLIENT (Workstation)                    DOMAIN CONTROLLER                 │
│   ═══════════════════                     ═════════════════                 │
│                                                                             │
│   ┌─────────────────────┐                 ┌─────────────────────┐          │
│   │ Application sends   │                 │ DC receives and     │          │
│   │ LDAP query with     │ ──────────────> │ NORMALIZES query    │          │
│   │ obfuscation         │                 │ before processing   │          │
│   └─────────────────────┘                 └─────────────────────┘          │
│            │                                         │                      │
│            ▼                                         ▼                      │
│   ┌─────────────────────┐                 ┌─────────────────────┐          │
│   │ LDAPMon captures    │                 │ Event 1644 logs     │          │
│   │ RAW query with      │                 │ DECODED query       │          │
│   │ encoding intact     │                 │ (normalized)        │          │
│   └─────────────────────┘                 └─────────────────────┘          │
│            │                                         │                      │
│            ▼                                         ▼                      │
│   ┌─────────────────────┐                 ┌─────────────────────┐          │
│   │ DETECTS:            │                 │ DETECTS:            │          │
│   │ • Hex encoding      │                 │ • Boolean logic     │          │
│   │ • Null bytes        │                 │ • Wildcards         │          │
│   │ • OID attributes    │                 │ • Bitwise ops       │          │
│   │ • Invalid bytes     │                 │ • Range operators   │          │
│   └─────────────────────┘                 └─────────────────────┘          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Each Location Detects

| Obfuscation Type | Raw Query Sent | Client (LDAPMon) | DC (Event 1644) |
|------------------|----------------|------------------|-----------------|
| Hex Encoding | `(name=\44omain \41dmins)` | ✅ **Detected** | ❌ Sees `(name=Domain Admins)` |
| Full Hex | `(name=\6b\72\62\74\67\74)` | ✅ **Detected** | ❌ Sees `(name=krbtgt)` |
| Null Byte | `(name=kr\00btgt)` | ✅ **Detected** | ❌ Sees `(name=krbtgt)` |
| Invalid Bytes | `(name=\80kr\90btgt\ff)` | ✅ **Detected** | ❌ Sees `(name=krbtgt)` |
| OID Attribute | `(1.2.840.113556.1.4.1=test)` | ✅ **Detected** | ❌ Sees `(name=test)` |
| Leading Zeros | `(sAMAccountType=0000805306368)` | ✅ **Detected** | ❌ Sees normalized |
| Double Negation | `(!(!(name=x)))` | ✅ Detected | ✅ **Detected** |
| De Morgan | `(!(\|(name=x)(name=y)))` | ✅ Detected | ✅ **Detected** |
| Wildcards | `(name=*k*r*b*)` | ✅ Detected | ✅ **Detected** |
| Bitwise | `(userAccountControl\|2)` | ✅ Detected | ✅ **Detected** |
| Range Ops | `(sAMAccountType>=805306368)` | ✅ Detected | ✅ **Detected** |

> **⚠️ Bottom Line:** Use **LDAPMon on clients** to detect encoding-based obfuscation, and **Event 1644 on DCs** to detect structural obfuscation. You need both for complete coverage.

---

## Quick Start

### 1. Set Up Client-Side Logging (LDAPMon)

LDAPMon is an ETW-based tool that captures raw LDAP queries before DC normalization.

**Install LDAPMon** (from [https://github.com/jonny-jhnson/LDAPMon](https://github.com/jonny-jhnson/LDAPMon)):
```powershell
# Download and extract LDAPMon
# Run LDAPMonitor.exe as Administrator

# Verify it's working
. .\Get-LDAPClientLogs.ps1
Get-LDAPLogStatus
```

### 2. Enable DC-Side Logging (Event 1644)

**On the Domain Controller** (as Administrator):
```powershell
. .\Get-DCLDAPLogs.ps1
Enable-Event1644Logging -ComputerName "DC01" -ExpensiveThreshold 1 -InefficientThreshold 1 -SearchTimeThresholdMs 1
Get-Event1644Status -ComputerName "DC01"
```

### 3. Hunt for Obfuscation

**On the Client (LDAPMon):**
```powershell
. .\Get-LDAPClientLogs.ps1

# Hunt for ALL encoding-based obfuscation
Search-LDAPLogs -ObfuscationType All

# Exclude normal Windows traffic (lsass DC locator queries use hex encoding)
Search-LDAPLogs -ObfuscationType All -ExcludeProcess lsass

# Hunt for specific patterns
Search-LDAPLogs -ObfuscationType HexEncoding
Search-LDAPLogs -ObfuscationType NullByteInjection
Search-LDAPLogs -ObfuscationType OIDAttribute
```

**On the DC (Event 1644):**
```powershell
. .\Get-DCLDAPLogs.ps1

# Hunt for ALL structural obfuscation
Search-Event1644 -ObfuscationType All

# Hunt for specific patterns
Search-Event1644 -ObfuscationType DoubleNegation
Search-Event1644 -ObfuscationType ExcessiveWildcards
```

---

## Detailed Usage: Get-LDAPClientLogs.ps1

### Check Status

```powershell
. .\Get-LDAPClientLogs.ps1

Get-LDAPLogStatus

# Output:
# ======================================================================
#   LDAP CLIENT LOG STATUS (LDAPMon)
#   Computer: WORKSTATION01
# ======================================================================
# 
#   LDAPMon/Operational
#     Channel: LDAPMon/Operational
#     Channel Exists: YES
#     Logging: ENABLED
#     Events: Available
#     LDAPMonitor.exe: RUNNING (PID 4532)
# 
# ======================================================================
#   STATUS SUMMARY
# ======================================================================
# 
#   LDAPMon: READY
# 
#   Available commands:
#     Get-LDAPLogs             - Retrieve historical logs
#     Watch-LDAPLogs           - Real-time monitoring
#     Search-LDAPLogs          - Hunt for obfuscation patterns
#     Export-LDAPLogs          - Export to file
# ======================================================================
```

### View Recent Logs

```powershell
# View recent LDAPMon events
Get-LDAPLogs -MaxEvents 20

# Output:
# ================================================================================
#   LDAP CLIENT LOGS (LDAPMon)
# ================================================================================
#   Computer: WORKSTATION01
#   Time Range: 2025-12-12 16:00:00 to 2025-12-12 17:00:00
#   Log Source: LDAPMon/Operational
# ================================================================================
# 
# Found 20 events
# ────────────────────────────────────────────────────────────────────────────────
#   Time:        2025-12-12 16:55:23.456
#   User:        MARVEL\loki
#   Process:     PID 8532 (powershell_ise)
#   Base DN:     DC=marvel,DC=local
#   Scope:       subtree
#   Filter:      (name=\44omain \41dmins)     <-- Hex encoding visible!
#   Attributes:  [all]
```

### Real-Time Monitoring

```powershell
# Watch for LDAP queries in real-time
Watch-LDAPLogs -DurationSeconds 120

# Compact one-line output
Watch-LDAPLogs -DurationSeconds 120 -Compact

# Output:
# ================================================================================
#   LDAP CLIENT LOG WATCHER
# ================================================================================
#   Computer: WORKSTATION01
#   Duration: 120 seconds
#   Log source: LDAPMon/Operational
#   Press Ctrl+C to stop
# ================================================================================
# 
# Watching for events...
# 
# [16:55:23.456] [MARVEL\loki] [powershell_ise] (name=\44omain \41dmins)
# [16:55:24.789] [MARVEL\loki] [powershell_ise] (name=\6b\72\62\74\67\74)
```

### Hunt for Obfuscation Patterns

```powershell
# List all available detection patterns
Get-ClientObfuscationPatterns

# Output:
# ================================================================================
#   CLIENT-SIDE OBFUSCATION PATTERNS
#   These detect encoding-based obfuscation BEFORE DC normalizes it
# ================================================================================
# 
#   HexEncoding
#     Description: Hex-encoded characters (\XX format)
#     Pattern:     \\[0-9a-fA-F]{2}
#     Example:     (name=\44omain \41dmins)
#     DC sees:     (name=Domain Admins)
# 
#   NullByteInjection
#     Description: Null byte injection (\00)
#     Pattern:     \\00
#     Example:     (name=kr\00btgt)
#     DC sees:     (name=krbtgt)
#   ...

# Search for ALL encoding-based obfuscation
Search-LDAPLogs -ObfuscationType All

# Output:
# ================================================================================
#   LDAP CLIENT OBFUSCATION HUNT
# ================================================================================
#   Computer: WORKSTATION01
#   Log source: LDAPMon/Operational
#   Time range: 2025-12-11 17:00:00 to 2025-12-12 17:00:00
#   Obfuscation: All
#   Dedupe: ON (LDAPMon logs each query twice)
# ================================================================================
# 
# Events found: 521 (deduped from 1042)
# 
# ────────────────────────────────────────────────────────────────────────────────
#   MATCH: HexEncoding
#   Time:      2025-12-12 16:55:23.456
#   User:      MARVEL\loki
#   Process:   PID 8532 (powershell_ise)
#   Base DN:   DC=marvel,DC=local
#   Scope:     subtree
#   Filter:    (name=\44omain \41dmins)
#   DC sees:   (decoded/normalized - encoding stripped)

# Exclude normal Windows traffic
Search-LDAPLogs -ObfuscationType All -ExcludeProcess lsass

# Exclude multiple processes
Search-LDAPLogs -ObfuscationType All -ExcludeProcess @("lsass", "svchost")

# Only show PowerShell processes
Search-LDAPLogs -ObfuscationType All -ProcessName "*powershell*"

# Custom regex search
Search-LDAPLogs -FilterPattern "\\00|\\[8-9a-fA-F][0-9a-fA-F]"
```

---

## Detailed Usage: Get-DCLDAPLogs.ps1

### Check Event 1644 Status

```powershell
. .\Get-DCLDAPLogs.ps1

Get-Event1644Status -ComputerName "DC01"

# Output:
# ================================================================================
#   EVENT 1644 LOGGING STATUS
#   Target DC: DC01
# ================================================================================
# 
# Status: ENABLED (Level 5)
# 
# Thresholds:
#   Expensive Search:     1 results
#   Inefficient Search:   1 entries visited
#   Search Time:          1 ms
# ================================================================================
```

### Enable Event 1644 Logging

```powershell
# Enable with aggressive thresholds (catch everything)
Enable-Event1644Logging -ComputerName "DC01" `
    -ExpensiveThreshold 1 `
    -InefficientThreshold 1 `
    -SearchTimeThresholdMs 1
```

### View Event 1644 Entries

```powershell
Get-Event1644 -ComputerName "DC01" -MaxEvents 20

# Output:
# ================================================================================
#   EVENT 1644 - EXPENSIVE LDAP SEARCHES
# ================================================================================
#   DC: DC01.marvel.local
#   Logging: ON (Level 5) | Thresholds: Exp=1 Ineff=1 Time=1ms
#   Time Range: 2025-12-12 16:00:00 to 2025-12-12 17:00:00
# ================================================================================
# 
# Found 20 events
# 
# ────────────────────────────────────────────────────────────────────────────────
#   Time:        2025-12-12 16:55:23.456
#   User:        MARVEL\loki
#   Client:      10.1.1.50:54321
#   Base DN:     DC=marvel,DC=local
#   Scope:       subtree
#   Filter:      (name=Domain Admins)        <-- Hex decoded by DC!
#   Returned:    1 entries
#   Visited:     3457 entries
```

### Hunt for Obfuscation Patterns

```powershell
# List available DC-side detection patterns
Get-ObfuscationPatterns

# Search for ALL structural obfuscation
Search-Event1644 -ObfuscationType All

# Search specific patterns
Search-Event1644 -ObfuscationType DoubleNegation
Search-Event1644 -ObfuscationType ExcessiveWildcards
Search-Event1644 -ObfuscationType BitwiseOperator

# Filter by user
Search-Event1644 -User '*loki*' -ObfuscationType All

# Custom regex
Search-Event1644 -FilterPattern "krbtgt|adminCount"
```

---

## Detection Patterns Reference

### Client-Side Patterns (LDAPMon)

These detect **encoding-based obfuscation** that is decoded before Event 1644:

| Pattern | Description | Example |
|---------|-------------|---------|
| `HexEncoding` | Hex-encoded characters | `(name=\44omain \41dmins)` |
| `NullByteInjection` | Null byte injection | `(name=kr\00btgt)` |
| `InvalidByteInjection` | Invalid UTF-8 bytes | `(name=\80kr\90btgt\ff)` |
| `OIDAttribute` | OID instead of name | `(1.2.840.113556.1.4.1=x)` |
| `OIDWithHex` | OID + hex value | `(1.2.840...=\6b\72...)` |
| `LeadingZeros` | Leading zeros | `(attr=0000805306368)` |

### DC-Side Patterns (Event 1644)

These detect **structural obfuscation** that survives DC normalization:

| Pattern | Description | Example |
|---------|-------------|---------|
| `DoubleNegation` | Double NOT operators | `( ! ( ! (name=x) ) )` |
| `DeMorganTransform` | De Morgan transforms | `( ! ( \| (name=x)(y) ) )` |
| `ExcessiveWildcards` | Multiple wildcards | `(name=*x*y*z*)` |
| `ANRAttribute` | Ambiguous Name Resolution | `(anr=Domain Admins)` |
| `ApproximateMatch` | Phonetic match | `(name~=smith)` |
| `RangeOperators` | Range comparisons | `(sAMAccountType>=805306368)` |
| `BitwiseOperator` | Bitwise filters | `(userAccountControl\|2)` |
| `ExtensibleMatchOID` | OID match rules | `(attr:1.2.840...:=value)` |
| `TimestampFilter` | Time-based filters | `(whenCreated>=...)` |
| `AdminCount` | Privileged account enum | `(adminCount=1)` |

---

## Complete Workflow Example

### Testing Your Detection Rules

**Terminal 1 - DC Monitoring:**
```powershell
. .\Get-DCLDAPLogs.ps1
Watch-Event1644 -DurationSeconds 0   # Runs until Ctrl+C
```

**Terminal 2 - Client Monitoring:**
```powershell
. .\Get-LDAPClientLogs.ps1
Watch-LDAPLogs -DurationSeconds 0 -Compact
```

**After Testing - Analyze:**
```powershell
# Client-side (encoding detection) - exclude Windows noise
Search-LDAPLogs -ObfuscationType All -ExcludeProcess lsass

# DC-side (structural detection)
Search-Event1644 -ObfuscationType All

# Export evidence
Export-LDAPLogs -Path ".\evidence\client"
Export-DCLDAPLogs -Path ".\evidence\dc"
```

---

## Requirements

| Script | Requirements |
|--------|-------------|
| `Get-LDAPClientLogs.ps1` | Windows client, [LDAPMon](https://github.com/jonny-jhnson/LDAPMon) |
| `Get-DCLDAPLogs.ps1` | Domain Admin privileges (remote) or run locally on DC |

### Why LDAPMon?

The built-in `Microsoft-Windows-LDAP-Client/Debug` log is **not reliable** for capturing LDAP search filters:
- It's an ETL-based debug log that requires an active ETW trace session
- Even when "enabled" in Event Viewer, it may not capture events
- It doesn't reliably include LDAP search filters

**LDAPMon** was purpose-built for this task and provides:
- Reliable event logging to standard Windows Event Log
- Complete capture of LDAP search filters, Base DN, Scope, Attributes
- User and Process attribution
- Works immediately when running

---

## References

- [MaLDAPtive GitHub](https://github.com/MaLDAPtive/MaLDAPtive)
- [LDAPMon GitHub](https://github.com/jonny-jhnson/LDAPMon)
- [Microsoft Event 1644 Documentation](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/event-1644-monitor-ad-ds)
- [LDAP Filter Syntax](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)

---

## License

MIT License - See individual script files for details.
