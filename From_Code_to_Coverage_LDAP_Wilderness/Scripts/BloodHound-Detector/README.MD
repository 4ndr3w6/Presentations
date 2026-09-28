# BloodHound-Detector

**All-In-One LDAP Reconnaissance Detection for Active Directory Domain Controllers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server-0078D6.svg)](https://www.microsoft.com/en-us/windows-server)

Detect BloodHound, SharpHound, and other LDAP reconnaissance tools through statistical analysis of Event ID 1644 (LDAP Search Statistics). This tool uses environmental baseline intelligence combined with pattern-based signatures to catch reconnaissance regardless of tool modifications or evasion techniques.

## The Philosophy

> "The Math Never Lies"

Instead of looking for specific tool signatures that attackers can modify, BloodHound-Detector detects the **fundamental behavior** of reconnaissance:

- Reconnaissance tools **must** query many objects (high volume)
- They **must** request specific data (patterns emerge)  
- They **cannot** be perfectly efficient (tradeoffs exist)
- They **leave** forensic artifacts (Event ID 1644)

Even if an attacker modifies BloodHound's source code, changes LDAP filter syntax, slows down query rate, or uses a completely custom tool - they **still** exhibit detectable patterns because reconnaissance itself has inherent mathematical properties.

## Features

- **Statistical Analysis** — Baseline normal behavior, detect anomalies using z-scores
- **Pattern Detection** — 7 reconnaissance signatures (SDFlags, sAMAccountType, ADCS, etc.)
- **Zero-Efficiency Detection** — Catches modern SharpHound GUID lookups (0% efficiency)
- **Dual-Threshold Alerting** — Log HIGH (≥0.5), display CRITICAL (≥0.7) to reduce noise
- **Real-Time Monitoring** — Continuous watch for suspicious activity
- **Historical Analysis** — Scan past events for missed reconnaissance
- **HTML Reports** — Executive summaries with Chart.js visualizations
- **DFIR Reports** — Comprehensive forensic analysis with raw Event 1644 data
- **Works Without Baseline** — Pattern detection works immediately on deployment
- **Consolidated Output** — All files saved to a single configurable directory

## Requirements

- Windows Server 2016+ (Domain Controller)
- PowerShell 5.1+
- Administrator privileges
- Event ID 1644 logging enabled

### Enable Event ID 1644 Logging

```powershell
# Production: Level 2 (logs expensive/inefficient searches)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 2 /f

# Lab: Level 5 (logs ALL searches - more disk I/O)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f

# Optional: Lower thresholds to capture more queries
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "Search Time Threshold (msecs)" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "Expensive Search Results Threshold" /t REG_DWORD /d 1 /f
```

## Installation

```powershell
# Clone the repository
git clone https://github.com/4ndr3w6/Presentations.git
cd infosec-scripts/ldap/BloodHound-Detector

# Or download directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/4ndr3w6/Presentations/main/From_Code_to_Coverage_LDAP_Wilderness/Scripts/BloodHound-Detector/BloodHound-Detector.ps1" -OutFile "BloodHound-Detector.ps1"
```

## Usage

```powershell
# Launch interactive menu
.\BloodHound-Detector.ps1
```

### Interactive Menu

```
╔══════════════════════════════════════════════════════════════╗
║                 🐕 BloodHound Detector v2.8.0 🐕              ║
║        🎯 All-In-One LDAP Reconnaissance Detection 🎯        ║
╚══════════════════════════════════════════════════════════════╝

[1]  📊 Build Baseline         - Analyze normal LDAP traffic (24-48 hrs recommended)
[2]  🔧 System Diagnostics     - Check Event 1644 status and configuration
[3]  👁  Start Monitoring       - Real-time detection of suspicious activity
[4]  📜 Analyze Historical     - Scan past events for reconnaissance
[5]  ☑  Show Status            - View system status and recent activity
[6]  🔍 Alert Analysis         - Review logged alerts with filtering
[7]  🗑  Clear Event Logs       - Clear Event 1644 logs (for clean baseline)
[8]  🗑  Clear Alert History    - Delete the alert log file
[9]  📂 Open Output Folder     - Open output directory in Explorer
[10] 📖 Documentation          - Learn how detection works
[11] 📋 Changelog              - View version history
[12] ⚖  License Information    - View MIT license
[13] 📋 Generate DFIR Report   - Create comprehensive forensic report
[14] 🚪 Exit
```

## Detection Methodology

### Three-Layer Approach

**Layer 1: Statistical Analysis** (requires baseline)
- Establishes what's "normal" for YOUR environment
- Calculates mean and standard deviation for entries returned
- Flags queries >3σ above baseline

**Layer 2: Efficiency Analysis** (always active)
- Formula: `Efficiency = (Returned Entries / Visited Entries) × 100`
- 100% = Perfect (returned everything visited)
- <10% = Suspicious (casting wide net)
- 0% = Critical (visited but returned nothing - SharpHound GUID lookups)

**Layer 3: Pattern Detection** (signature-based, always active)

| Pattern | Score | Description |
|---------|-------|-------------|
| Base Scope Object Enumeration | +0.5 | `(objectclass=*)` with base scope |
| SDFlags Enumeration | +0.4 | ACL harvesting via `SDFlags:0x5` or `0x4` |
| sAMAccountType Enumeration | +0.3-0.4 | Targeting users/groups by type |
| ADCS/PKI Infrastructure | +0.3 | Certificate authority discovery |
| Excessive Attributes | +0.2 | 30+ attributes in single query |
| Configuration Container | +0.2 | Infrastructure discovery |
| Foreign Security Principals | +0.2 | Trust relationship enumeration |

### Composite Scoring

Each query is analyzed and assigned a composite score (0.0 - 1.0+):

| Score Range | Severity | Behavior |
|-------------|----------|----------|
| < 0.3 | Normal | Ignored |
| 0.3 - 0.49 | Low | Logged for analysis |
| 0.5 - 0.69 | HIGH | Silently logged |
| ≥ 0.7 | CRITICAL | Alert displayed on screen |

## Example Detections

### Classic BloodHound Collection

```
╔══════════════════════════════════════════════════════════════╗
║  [CRITICAL] BloodHound Activity Detected                     ║
╚══════════════════════════════════════════════════════════════╝

Time:        2025-12-11 02:41:45
Client:      10.1.1.14
Score:       0.95
Efficiency:  9.9%

Detection Reasons:
• Critical efficiency: 9.9%
• Volume anomaly: 312σ above baseline
• High pages/object: 17.2
• Base scope object enumeration
• SDFlags ACL enumeration
• Excessive attributes (67 requested)
```

### Modern SharpHound (Zero-Efficiency Pattern)

```
╔══════════════════════════════════════════════════════════════╗
║  [CRITICAL] BloodHound Activity Detected                     ║
╚══════════════════════════════════════════════════════════════╝

Time:        2025-12-11 03:15:22
Client:      10.1.1.14
Score:       0.85
Efficiency:  0%

Detection Reasons:
• Zero efficiency (visited 2, returned 0)
• GUID lookup pattern detected
• Base scope object enumeration
```

### ADCS Certificate Enumeration

```
╔══════════════════════════════════════════════════════════════╗
║  [CRITICAL] BloodHound Activity Detected                     ║
╚══════════════════════════════════════════════════════════════╝

Time:        2025-12-11 04:22:18
Client:      10.1.1.14
Score:       0.72
Efficiency:  45%

Detection Reasons:
• ADCS/PKI infrastructure enumeration
• Configuration container queries
• Certificate template discovery
```

## Output Files

All files are saved to the output directory (default: `.\BloodHound-Detector-Output`):

```
BloodHound-Detector-Output/
├── ldap_baseline.json              # Statistical baseline data
├── bloodhound_alerts.jsonl         # Alert log (JSON Lines format)
├── dfir_events.jsonl               # Raw forensic event data
├── BloodHound-Report-*.html        # Interactive HTML reports
├── BloodHound_Report_*.csv         # CSV exports for SIEM
├── DFIR_Report_Enhanced_*.txt      # Text forensic reports
└── DFIR_Report_Enhanced_*.html     # HTML forensic reports
```

### Alert Log Format (JSONL)

Each line in `bloodhound_alerts.jsonl` is a JSON object:

```json
{
  "Timestamp": "2025-12-11T02:41:45",
  "Severity": "CRITICAL",
  "Score": 0.95,
  "Client": "10.1.1.14",
  "Efficiency": 9.9,
  "Reasons": "Critical efficiency; Volume anomaly; SDFlags enumeration",
  "Filter": "(objectclass=*)",
  "VisitedEntries": 52847,
  "ReturnedEntries": 5234,
  "PagesReferenced": 89234
}
```

## SIEM Integration

### Splunk

```spl
# inputs.conf
[monitor://C:\SecurityLogs\BloodHound\bloodhound_alerts.jsonl]
sourcetype = bloodhound:alerts
index = security

# Search query
index=security sourcetype="bloodhound:alerts" Severity="CRITICAL"
| stats count by Client, Score
| sort -count
```

### Elastic/Filebeat

```yaml
filebeat.inputs:
  - type: log
    paths:
      - C:/SecurityLogs/BloodHound/bloodhound_alerts.jsonl
    json.keys_under_root: true
    json.add_error_key: true
```

### Generic Export

```powershell
# Export to CSV
$alerts = Get-Content ".\BloodHound-Detector-Output\bloodhound_alerts.jsonl" | 
    ForEach-Object { $_ | ConvertFrom-Json }
$alerts | Export-Csv -Path "bloodhound_export.csv" -NoTypeInformation
```

## Performance Impact

| Metric | Value |
|--------|-------|
| CPU | <1% average (spikes to 3-5% during analysis) |
| Memory | 50-100 MB |
| Disk I/O | Minimal (mostly reads) |
| Network | 0 (local processing only) |

### Event Log Growth

| Level | Normal Traffic | Under Attack | Daily Growth |
|-------|---------------|--------------|--------------|
| Level 2 | 100-500 events/hr | 1,000-5,000 events/hr | 100-500 MB |
| Level 5 | 1,000-10,000 events/hr | 10,000+ events/hr | 1-5 GB |

## Detection Capabilities

| Tool | Detected | Primary Method |
|------|----------|----------------|
| SharpHound (legacy) | ✅ | Efficiency + volume anomaly |
| SharpHound (modern) | ✅ | Zero-efficiency + patterns |
| BloodHound.py | ✅ | Pattern signatures |
| ADExplorer | ✅ | Volume anomaly |
| ADRecon | ✅ | Pattern + efficiency |
| PowerView | ✅ | Pattern signatures |
| ldapsearch enum | ✅ | Efficiency ratio |
| Certify/Certipy | ✅ | ADCS pattern |
| Custom LDAP tools | ⚠️ | Depends on technique |

### Internal Event Filtering

The following internal Windows events are automatically filtered to prevent false positives:

| Source | Description |
|--------|-------------|
| NTDSAPI | Directory service internal operations |
| SAM | Security Account Manager queries (lsass.exe) |
| LSASS | Local Security Authority operations |

These appear in Event 1644 with non-IP client identifiers and represent normal Windows operations, not external reconnaissance.

## Troubleshooting

### No Events Found

1. Verify Event 1644 logging is enabled:
   ```powershell
   Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering"
   # Should return 2 or higher
   ```

2. Generate test LDAP activity:
   ```powershell
   $searcher = [adsisearcher]"(objectclass=user)"
   $searcher.FindAll()
   ```

3. Check Event Viewer → Applications and Services → Directory Service

### High False Positives

1. Build a longer baseline (72+ hours during normal business)
2. Increase `AlertDisplayThreshold` to 0.8 in config
3. Exclude known admin/service workstations by IP
4. Rebuild baseline after major AD changes

### Missed Detections

1. Lower efficiency thresholds in config
2. Ensure baseline is current (rebuild monthly)
3. Enable Level 5 logging temporarily for full visibility
4. Check all pattern signatures are enabled

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.8.0 | Jun 2026 | MIT license, SAM/LSASS internal event filtering, open source release |
| 2.7.5 | Oct 2025 | Production hardening, DFIR reports, IPv6 parsing fixes |
| 2.7.3 | Oct 2025 | Universal pause, UX improvements |
| 2.7.0 | Oct 2025 | Pattern-based signatures (7 patterns) |
| 2.6.0 | Oct 2025 | Dual-threshold alerting |
| 2.5.0 | Oct 2025 | Zero-efficiency detection for modern SharpHound |
| 2.4.0 | Sep 2025 | ADCS false positive fixes |
| 2.0.0 | Sep 2025 | Unified interactive menu system |
| 1.0.0 | Sep 2025 | Initial proof of concept |

## Related Tools

| Tool | Description |
|------|-------------|
| [Enable-MaxLdapLogging](../Enable-MaxLdapLogging/) | Enable maximum LDAP diagnostic logging |
| [Get-ADWSAttribution](../Get-ADWSAttribution/) | Correlate ADWS connections to LDAP queries |
| [Debug-Event1644](../Debug-Event1644/) | Diagnose Event 1644 parsing issues |
| [Test-NonExistentAttributes](../Test-NonExistentAttributes/) | Test LDAP filter transformation |

## References

- [Event ID 1644 Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd941635(v=ws.10))
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [SharpHound](https://github.com/BloodHoundAD/SharpHound)
- [Monitoring AD for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)

## License

MIT License - Copyright (c) 2025-2026 Andrew Schwartz

See [LICENSE](../../LICENSE) for full text.

## Author

**Andrew Schwartz**

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Commit changes (`git commit -am 'Add new detection pattern'`)
4. Push to branch (`git push origin feature/new-pattern`)
5. Open a Pull Request
