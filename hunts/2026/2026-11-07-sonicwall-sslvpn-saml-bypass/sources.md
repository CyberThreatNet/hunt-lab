# Sources (verified 7 Nov 2026)

| Claim | Source | Status |
|---|---|---|
| SNWLID-2026-0014 published 2026-11-06, 7 CVEs, workaround none | SonicWall PSIRT (rendered page, evidence/) | Verified primary |
| CVE-2026-19868 wording: valid creds for alternate auth method bypass SAML; may bypass SAML-enforced MFA | SonicWall PSIRT; NVD; CISA KEV | Verified primary |
| Only affects SSL-VPN when SAML enabled for SSL-VPN logins | SonicWall PSIRT NOTE | Verified primary |
| PSIRT investigated report of potential exploitation; upgrade urged | SonicWall PSIRT | Verified primary |
| CVSS 7.1 AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N, CWE-308 | SonicWall PSIRT | Verified primary (CISA-ADP scores 7.5 in NVD) |
| Affected Gen7 7.3.3-7015 and older, Gen8 8.2.2-8015 and older; fixed 7.3.4-7013 and 8.2.3-8015; model lists | SonicWall PSIRT | Verified primary |
| KEV added 2026-11-06, due 2026-11-20, ransomware use Unknown | CISA alert + KEV JSON | Verified primary |
| Other six CVEs and their nature | SonicWall PSIRT | Verified primary |
| Reporter Ryan Harris, The Electronic Office | SonicWall PSIRT | Verified, not used in article |
| Secondary summary | BleepingComputer 6 Nov 2026 | Secondary |

## Labelled as ours (not SonicWall)
- Restricting SSL-VPN exposure, reviewing non-SAML methods, password resets, IdP-join hunt logic.

## Dropped / not claimed
- Any attacker, campaign, or IOC: none published.
- Auth-method field (SAML vs local/LDAP): no documented field found; that check is a non-deployable template in the pack.

## Hunt field mapping sources
| Mapping | Source |
|---|---|
| Event 1080 "SSL VPN zone remote user login allowed" | https://docs.rapid7.com/insightidr/sonicwall-firewall/ ; https://arcticwolf.com/resources/blog/smash-and-grab-aggressive-akira-campaign-targets-sonicwall-vpns/ ; https://arcticwolf.com/resources/blog/arctic-wolf-labs-observes-increased-fog-and-akira-ransomware-activity-linked-to-sonicwall-ssl-vpn/ |
| CommonSecurityLog, DeviceVendor SonicWall | https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/sonicwall-firewall |
| DeviceEventClassID = SonicOS event ID; SourceUserName / susr | https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/ASimNetworkSession/Parsers/ASimNetworkSessionSonicWallFirewall.yaml |
| SonicWall Log Events Reference Guide (official) | https://www.sonicwall.com/techdocs/pdf/SonicOSX_7.0.1_LogEvents_ReferenceGuide.pdf : download blocked from box, NOT read |
- EPSS: not checked.
