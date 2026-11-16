# Hunt: BO Team Log4Shell on vCenter and a supply-chain near miss

Full write-up: [BO Team targeted software supply chain via Log4Shell](https://cyber-threat.net/bo-team-log4shell-vcenter-supply-chain/) on Cyber-Threat.net.

> **Status:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-11-16-bo-team-log4shell-vcenter` |
| **Date** | 16 November 2026 |
| **Status** | Experimental |
| **Platforms** | Linux hypervisors and vCenter appliances (auditd, file events, DNS, cron); Microsoft Defender for Endpoint and Microsoft Sentinel |
| **ATT&CK** | T1190 Exploit Public-Facing Application. T1021.004 Remote Services: SSH. T1053.003 Cron. T1105 Ingress Tool Transfer. T1003.001 LSASS Memory. T1003.003 NTDS. T1036 Masquerading. T1195 Supply Chain Compromise (objective, not a confirmed completed implant). |
| **CVEs** | CVE-2021-44228 |
| **Files** | `rule-pgcache-cron-hourly.yml`, `rule-nofrillsdns-gsocket.yml`, `rule-comsvcs-lsass-dump.yml` (Sigma, DRL 1.1, experimental); `query.kql` (MIT); `linux-auditd-shell-hunt.md` (MIT); `rule-nofrillsdns-gsocket-yara.yar` (MIT); `sources.md`; `ci-targets.txt`; `sigma-check.txt` |

## Hypothesis

If an attacker has used Log4Shell on an unpatched vCenter appliance to reach the hypervisor, they may leave an hourly script such as `/etc/cron.hourly/pgcache`, park command and control on a nofrillsdns.com name that resolves to 127.0.0.1 until they need it, fetch GSocket from gsocket[.]io, and later dump LSASS with comsvcs.dll rather than a well-known tool.

## Threat context

- **Source.** Kaspersky ICS CERT, 5 November 2026, after a June 2025 engagement with a Russian software developer. The Hacker News is secondary.
- **Access.** Exposed SSH on a Linux terminal server, then likely CVE-2021-44228 on VMware vCenter 7.0.3. Kaspersky reproduced the exploit on the same build. The official fix is vCenter Server 7.0 Update 3c, build 19234570. CVE-2021-44228 has been in CISA's KEV catalogue since 10 December 2021.
- **Objective.** Kaspersky believes the likely aim was a supply-chain implant via the code-signing server, and that the attackers were apparently unable to finish after they lost access.

## How to use this pack

1. On vCenter appliances and hypervisors, work through `linux-auditd-shell-hunt.md`.
2. Deploy the Sigma rules for Linux file events, proxy or DNS, and Windows process creation.
3. Run `query.kql` in Microsoft Defender XDR or Sentinel where those tables exist.
4. The YARA rule is a string-based aid for disk or memory review, not a complete family detector.

## Caveats

- Untested against a live vCenter or customer tenant.
- `pgcache` as a filename can be coincidental. Confirm the hash and content.
- GSocket is also a legitimate project. Confirm the download URL, parent process and published indicators.
- A 127.0.0.1 answer for a nofrillsdns name is a parked-record lead, not a live beacon by itself.

## Validation notes

- Draft for review: untested. See `sigma-check.txt`.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 16 November 2026. Indicators from Kaspersky ICS CERT, 5 November 2026.
- Sigma rules: Detection Rule License (DRL) 1.1. All other files in this pack: MIT.

## Sources

See `sources.md`.
