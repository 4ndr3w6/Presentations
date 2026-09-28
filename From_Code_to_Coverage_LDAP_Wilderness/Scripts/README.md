# Scripts

Detection and logging tooling for the talk *"From Code to Coverage: A Detection Engineer's Journey Through the LDAP Wilderness."*

All scripts are MIT licensed — see [LICENSE](LICENSE).

| Tool | Description |
|------|-------------|
| [BloodHound-Detector](BloodHound-Detector/) | Detect BloodHound, SharpHound, and other LDAP reconnaissance via statistical analysis of Event ID 1644. |
| [Debug-Event1644](Debug-Event1644/) | Troubleshoot why LDAP detection tools might not be seeing Event ID 1644 events. |
| [Enable-MaxLdapLogging](Enable-MaxLdapLogging/) | Enable maximum LDAP / Directory Service diagnostic logging on a Domain Controller. |
| [Get-ADWSAttribution](Get-ADWSAttribution/) | Source-IP attribution for ADWS-proxied (TCP/9389) LDAP queries. |
| [Get-LDAPPingDetection](Get-LDAPPingDetection/) | Detect LDAP Ping (ldapnomnom-style) username enumeration by correlating Event 5156 with the Netlogon debug log. |
| [MaLDAPtive Detection Toolkit](MaLDAPtive%20Detection%20Toolkit/) | Collect and hunt LDAP obfuscation across client-side (LDAPMon) and DC-side (Event 1644) logs. |
