# ADWS Source IP Attribution

**Correlate external ADWS connections to LDAP queries on Active Directory Domain Controllers**

This PowerShell script proves that source IP attribution **is possible** for ADWS-proxied LDAP queries, contrary to claims that the originating host cannot be determined when tools like BloodHound/SharpHound use ADWS (TCP/9389) instead of direct LDAP.

## The Problem

Active Directory Web Services (ADWS) proxies LDAP queries through `localhost`, making traditional LDAP logging appear as if all queries originate from `[::1]` or `127.0.0.1`. This has been cited as a limitation for detecting reconnaissance tools that use ADWS.

## The Solution

This script correlates multiple Windows event sources to recover the true source IP:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  5156 External    →    5156 Internal      →    1138    →    1644       │
│  10.1.1.13→:9389       ::1:60983→:389          Start        Details    │
│  SOURCE IP             CORRELATION PORT        User SID     Filter     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Correlation Methods

| Method | Confidence | Description |
|--------|------------|-------------|
| **PORT** | High (deterministic) | Matches internal 5156 source port to 1644 client port |
| **TIMESTAMP** | Medium-High | Falls back to temporal correlation (~100ms window) |

## Requirements

Enable the following audit policies and diagnostic logging on your Domain Controllers:

```powershell
# Enable Windows Filtering Platform connection logging (Event 5156)
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

# Enable LDAP Interface Events (Event 1138)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f

# Enable Field Engineering / Expensive Search Results (Event 1644)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f
```

> **Note**: These settings increase log volume. Test in non-production first and ensure adequate log storage.

## Installation

```powershell
# Clone the repository
git clone https://github.com/4ndr3w6/Presentations.git

# Or download directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/4ndr3w6/Presentations/main/From_Code_to_Coverage_LDAP_Wilderness/Scripts/Get-ADWSAttribution/Get-ADWSAttribution.ps1" -OutFile "Get-ADWSAttribution.ps1"
```

## Usage

### Hunt Mode (Default)

Analyze historical events for the last N minutes:

```powershell
# Analyze last 10 minutes (default)
.\Get-ADWSAttribution.ps1

# Analyze last 60 minutes, show all queries
.\Get-ADWSAttribution.ps1 -Minutes 60 -ShowAll

# Only show suspicious queries
.\Get-ADWSAttribution.ps1 -Minutes 30 -AlertOnly
```

### Monitor Mode

Real-time monitoring for new ADWS queries:

```powershell
# Start monitoring (Ctrl+C to stop)
.\Get-ADWSAttribution.ps1 -Monitor

# Monitor with 2-second polling, alerts only
.\Get-ADWSAttribution.ps1 -Monitor -AlertOnly -PollSeconds 2
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Monitor` | Switch | - | Enable real-time monitoring mode |
| `-Minutes` | Int | 10 | Hunt mode: minutes of history to analyze |
| `-PollSeconds` | Int | 5 | Monitor mode: polling interval |
| `-MaxDeltaMs` | Int | 500 | Maximum milliseconds for event correlation |
| `-ExcludeIPs` | String[] | @() | IP addresses to exclude from results |
| `-AlertOnly` | Switch | - | Only display suspicious queries |
| `-ShowAll` | Switch | - | Hunt mode: show all queries including benign |
| `-Detailed` | Switch | - | Show verbose debug information |

## Suspicious Indicators

The script flags queries matching common reconnaissance patterns:

| Indicator | Description |
|-----------|-------------|
| ACL enumeration | Queries for `nTSecurityDescriptor` attribute |
| Full SD (BloodHound pattern) | `SDflags:0x7` control requesting full security descriptors |
| Kerberoasting recon | Filter contains `serviceprincipalname=*` |
| Delegation enumeration | Queries for `msDS-AllowedToDelegateTo` |
| gMSA enumeration | Queries for `msDS-GroupMSAMembership` |
| Unconstrained delegation | Filter checking `userAccountControl` for TRUSTED flags |
| Bulk enumeration | Queries returning >100 objects |
| Privileged account hunt | Filter contains `adminCount=1` |
| Password attribute query | Queries for `userPassword` or `unicodePwd` |

## Example Output

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║  [!] SUSPICIOUS ADWS QUERY DETECTED                            ║
  ╚══════════════════════════════════════════════════════════════════╝

    Source IP:   10.1.1.50
    User:        CORP\svc_bloodhound
    Correlation: PORT:62445 | High (deterministic) (45.2ms)

    IOC Summary:
      [5156] External ADWS connection (TCP/9389)
      [1138] Localhost client ([::1]:62445)
      [1644] Full SD (BloodHound pattern)
      [1644] Bulk enumeration (1547 objects)

    Event Chain:
    ┌───────────────────────────────────────────────────────────────┐
    │ [5156] 14:32:15.123 - Security Log (WFP Connection)          │
    │        Source:      10.1.1.50:49832                          │
    │        Destination: DC:9389 (ADWS)                           │
    │                     ↓ 12.3ms                                 │
    │ [1138] 14:32:15.135 - Directory Service (LDAP Op Start)      │
    │        Client:      [::1]:62445                              │
    │                     ↓ 32.9ms                                 │
    │ [1644] 14:32:15.168 - Directory Service (Expensive Search)   │
    │        Filter:      (objectClass=*)                          │
    │        Controls:    SDflags:0x7                              │
    │        Returned:    1547 entries                             │
    └───────────────────────────────────────────────────────────────┘
```

## Real-World Examples

### Hunt Mode - Detecting BloodHound Activity

```
PS C:\Scripts> .\Get-ADWSAttribution.ps1

  ╔══════════════════════════════════════════════════════════════════╗
  ║           ADWS Source IP Attribution - Hunt Mode                 ║
  ║                                                                  ║
  ║   Correlation: 5156 (external) → 1644 (LDAP query)               ║
  ║   Methods: PORT (deterministic) + TIMESTAMP (fallback)           ║
  ╚══════════════════════════════════════════════════════════════════╝

  Time Range: 2025-12-11 17:23:57 → 17:33:57

  [1/4] Collecting 5156 (external → port 9389)... 3
  [2/4] Collecting 5156 (internal ADWS → LDAP)... 12
  [3/4] Collecting 1138 (LDAP operations)... 312
  [4/4] Collecting 1644 (query details)... 10

  ╔══════════════════════════════════════════════════════════════════╗
  ║  RESULTS                                                         ║
  ╚══════════════════════════════════════════════════════════════════╝

    Correlated Queries: 7

    Correlation Methods:
      TIMESTAMP [probabilistic]: 1
      PORT [deterministic]: 6

    Source IPs:
      10.1.1.13: 7 queries (2 suspicious)

  ╔══════════════════════════════════════════════════════════════════╗
  ║  SUSPICIOUS QUERIES                                              ║
  ╚══════════════════════════════════════════════════════════════════╝

    Source IP:   10.1.1.13
    User:        MARVEL\loki
    Correlation: PORT:53149 | High (deterministic) (87.5ms)

    IOC Summary:
      [5156] External ADWS connection (TCP/9389)
      [1138] Localhost client ([::1]:53149)
      [1138] ADWS proxy to LDAP
      [1644] ACL enumeration
      [1644] Full SD (BloodHound pattern)

    Event Chain:
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │ [5156] 17:28:33.291 - Security Log (WFP Connection)                                  │
    │        Source:      10.1.1.13:58188
    │        Destination: DC:9389 (ADWS)
    │        Application: microsoft.activedirectory.webservices.exe
    │        » External ADWS connection (TCP/9389)
    │
    │                     ↓ 70.3ms
    │
    │ [1138] 17:28:33.361 - Directory Service (LDAP Op Start)                              │
    │        Client:      [::1]:53149
    │        Operation:
    │        User SID:    S-1-5-21-208534352-3953284921-3886779260-1105
    │        » Localhost client ([::1]:53149)
    │        » ADWS proxy to LDAP
    │
    │                     ↓ 17.2ms
    │
    │ [1644] 17:28:33.378 - Directory Service (Expensive Search)                           │
    │        Client:      [::1]:53149
    │        User:        MARVEL\loki
    │        Base DN:     DC=marvel,DC=local
    │        Filter:      (&(objectClass=user)(objectCategory=CN=Person,CN=Schema,...))
    │        Attributes:  [all_with_list]nTSecurityDescriptor
    │        Controls:    SDflags:0x7;
    │
    │        Search Statistics:
    │          Visited:     53 entries
    │          Returned:    53 entries
    │          Indexes:     idx_objectCategory:53:N;
    │          Pages:       1967
    │          Search Time: 15ms
    │
    │        [!] Suspicious Indicators:
    │          • ACL enumeration
    │          • Full SD (BloodHound pattern)
    └───────────────────────────────────────────────────────────────────────────────────────┘
```

### Monitor Mode - Real-Time Detection

```
PS C:\Scripts> .\Get-ADWSAttribution.ps1 -Monitor

  ╔══════════════════════════════════════════════════════════════════╗
  ║           ADWS Real-Time Source IP Monitor                       ║
  ║                                                                  ║
  ║   Correlation: 5156 (external) → 1644 (LDAP query)               ║
  ║   Method: Timestamp-based (~60-100ms delta)                      ║
  ╚══════════════════════════════════════════════════════════════════╝

  [*] Monitoring for external ADWS queries...
  [*] Poll interval: 5s | Press Ctrl+C to stop

  ╔════════════════════════════════════════════════════════════════╗
  ║  [!] SUSPICIOUS ADWS QUERY DETECTED                            ║
  ╚════════════════════════════════════════════════════════════════╝

    Source IP:   10.1.1.13
    User:        MARVEL\loki
    Correlation: TIMESTAMP | High (61.6ms)

    IOC Summary:
      [5156] External ADWS connection (TCP/9389)
      [1138] Localhost client ([::1]:53149)
      [1138] ADWS proxy to LDAP
      [1644] ACL enumeration
      [1644] Full SD (BloodHound pattern)

    Event Chain:
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │ [5156] 17:30:08.214 - Security Log (WFP Connection)                                  │
    │        Source:      10.1.1.13:48594
    │        Destination: DC:9389 (ADWS)
    │        Application: microsoft.activedirectory.webservices.exe
    │        » External ADWS connection (TCP/9389)
    │
    │                     ↓ 46.4ms
    │
    │ [1138] 17:30:08.260 - Directory Service (LDAP Op Start)                              │
    │        Client:      [::1]:53149
    │        User SID:    S-1-5-21-208534352-3953284921-3886779260-1105
    │        » Localhost client ([::1]:53149)
    │        » ADWS proxy to LDAP
    │
    │                     ↓ 15.2ms
    │
    │ [1644] 17:30:08.275 - Directory Service (Expensive Search)                           │
    │        Client:      [::1]:53149
    │        User:        MARVEL\loki
    │        Base DN:     DC=marvel,DC=local
    │        Filter:      (&(objectClass=user)(objectCategory=CN=Person,...))
    │        Attributes:  [all_with_list]nTSecurityDescriptor
    │        Controls:    SDflags:0x7;
    │
    │        Search Statistics:
    │          Visited:     53 entries
    │          Returned:    53 entries
    │          Indexes:     idx_objectCategory:53:N;
    │          Pages:       1967
    │          Search Time: 16ms
    │
    │        [!] Suspicious Indicators:
    │          • ACL enumeration
    │          • Full SD (BloodHound pattern)
    └───────────────────────────────────────────────────────────────────────────────────────┘
```

## Pipeline Support

Results are returned as objects for further processing:

```powershell
# Export to CSV
.\Get-ADWSAttribution.ps1 -Minutes 60 | Export-Csv -Path "adws_queries.csv" -NoTypeInformation

# Filter in pipeline
.\Get-ADWSAttribution.ps1 -Minutes 60 | Where-Object { $_.Suspicious } | Select-Object Time, SourceIP, User, Filter

# Group by source
.\Get-ADWSAttribution.ps1 -Minutes 60 | Group-Object SourceIP | Sort-Object Count -Descending
```

## How It Works

1. **Event 5156 (External)**: Windows Filtering Platform logs the inbound TCP connection to port 9389 from the external source IP
2. **Event 5156 (Internal)**: WFP logs ADWS (`webservices.exe`) connecting to local LDAP on port 389, capturing the ephemeral source port
3. **Event 1138**: Directory Service logs the LDAP operation start with the client port (matches step 2)
4. **Event 1644**: Directory Service logs expensive/inefficient search details with the same client port

The script correlates these events using port matching (deterministic) or timestamp proximity (fallback) to attribute the original source IP to each LDAP query.

## Limitations

- Requires all audit policies enabled on the DC
- High-volume environments may experience event log rollover
- Timestamp correlation has a small chance of false positives under heavy load
- Does not capture queries that don't trigger 1644 (non-expensive searches)

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## License

MIT License - See [LICENSE](LICENSE) for details.

## References

- [MS-ADCAP: Active Directory Web Services Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/)
- [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
- [Event 1644: LDAP Search Query Performance](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd941635(v=ws.10))

## Author

Andrew Schwartz
