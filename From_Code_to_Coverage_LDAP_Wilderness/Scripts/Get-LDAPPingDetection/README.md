# Get-LDAPPingDetection.ps1

Detects **LDAP Ping (ldapnomnom-style) username enumeration** by correlating Windows
**Event 5156** (the source IP of inbound connections to LDAP ports 389/636) with the
**Netlogon debug log** (the usernames that were queried and whether each was a hit, miss,
or disabled account). Neither source alone is complete — the script joins them by
timestamp to show *who* queried and *what* they queried.

Part of the "From Code to Coverage" series (Part 6). Author: Andrew Schwartz (@4ndr3w6S) / Huntress.

## Requirements

- Run on a Domain Controller
- Filtering Platform Connection auditing (Event 5156):
  `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable`
- Netlogon debug logging: `nltest /dbflag:0x2080ffff`

(Or pass `-EnableLogging` to configure both automatically — requires Administrator on the DC.)

## Usage

```powershell
# Real-time monitor with a honeytoken account
.\Get-LDAPPingDetection.ps1 -Monitor -MonitorIntervalSeconds 5 -HoneytokenAccounts svc_backup

# Historical analysis of the last N hours
.\Get-LDAPPingDetection.ps1 -HoursBack 24 -HoneytokenAccounts "administrator,svc_backup"

# Enable required logging, then analyze
.\Get-LDAPPingDetection.ps1 -EnableLogging -HoursBack 1

# Export full results to CSV
.\Get-LDAPPingDetection.ps1 -HoneytokenAccounts "admin,svc_backup" -ExportPath C:\Logs\ldap_ping.csv
```

## Key parameters

| Parameter | Purpose |
|-----------|---------|
| `-Monitor` | Real-time monitoring; alerts as LDAP Pings arrive |
| `-MonitorIntervalSeconds` | Poll interval in monitor mode (default 10) |
| `-HoneytokenAccounts` | Comma-separated canary accounts; a hit is high-confidence enumeration |
| `-HoursBack` | Hours of history to analyze (default 24) |
| `-CorrelationWindowSeconds` | Window to join Event 5156 with netlogon.log (default 5) |
| `-AlertThreshold` | Alert when a source queries more than N unique usernames (default 10) |
| `-LogPath` | Path to netlogon.log (default `%windir%\debug\netlogon.log`) |
| `-ExportPath` | Optional CSV export path |
| `-EnableLogging` | Enable Filtering Platform Connection auditing + Netlogon debug logging |

## Notes

- UDP cLDAP LDAP Pings appear in netlogon.log but generate **no** Event 5156 (no TCP
  connection, so no source IP); TCP-based pings fire Event 5156 with the source IP.
- The script also emits Sigma rules for the detection logic.

## License

MIT — see [../LICENSE](../LICENSE).
