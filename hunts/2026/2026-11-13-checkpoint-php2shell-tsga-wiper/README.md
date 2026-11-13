# PHP2Shell on Check Point gateways: portal webshells, TSGA and an ESXi wiper

> **Status:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-11-13-checkpoint-php2shell-tsga-wiper` |
| **Date** | 13 November 2026 |
| **Status** | Experimental |
| **Platforms** | Check Point Security Gateways (Gaia) with Mobile Access or another affected web portal; Management and Log Servers (CVE-2026-123039 only); VMware ESXi hosts reachable from a gateway; firewall, syslog and SIEM telemetry |
| **ATT&CK** | T1190 Exploit Public-Facing Application, T1595.002 Vulnerability Scanning, T1068 Exploitation for Privilege Escalation, T1505.003 Web Shell, T1140 Deobfuscate/Decode Files or Information, T1036.005 Match Legitimate Resource Name or Location, T1055 Process Injection, T1090 Proxy, T1070 Indicator Removal, T1046 Network Service Discovery, T1021.004 SSH, T1078 Valid Accounts, T1485 Data Destruction |
| **CVEs** | CVE-2026-109618, CVE-2026-109619 (PHP2Shell), CVE-2026-123039 (Gaia DynamicCLI) |
| **Files** | `rule-cp-portal-webshell-drop.yml`, `rule-cp-tsga-artefacts.yml`, `rule-cp-tsga-process.yml`, `rule-cp-scan-sources.yml`, `rule-esxi-wiper-note.yml` (Sigma, DRL 1.1); `checkpoint-php2shell-tsga.yar` (DRL 1.1); `query.kql`, `host-checks.sh`, `esxi-checks.sh` (MIT); `sources.md`; `ci-targets.txt` |

## Hypothesis

If an internet-facing Check Point gateway ran an affected web portal without the PHP2Shell hotfix in late October 2026, an attacker may have gained code execution as the portal service account, used CVE-2026-123039 to get root, and left PHP webshells as `zz*.tpl` files in the directory the Mobile Access portal uses to build its login pages. A passive backdoor, TSGA, may be running as `slot_CPconfigdaemon` with its TSProxy library at `/lib/libcpfwcommon.so`. If the gateway could reach VMware ESXi over SSH, the attacker may have logged in as `vpxuser` and run a wiper.

## Threat context

- **Source.** Check Point Research and a Check Point advisory, both published 12 November 2026. Check Point saw exploitation from 30 October and active until 4 November 2026.
- **Two waves.** 30 October: Israeli organisations, with destructive activity against some. 2 November: organisations in many countries and sectors, including some first-wave targets, with no destructive activity seen. Check Point saw no sector preference and calls it opportunistic.
- **Chain.** PHP2Shell (CVE-2026-109618, CVE-2026-109619) through the Mobile Access portal for initial access. Then CVE-2026-123039: the Gaia `dynamic_server` process runs as root and listens on `/tmp/dynamic_socket`, created world-writable (0777) with no caller check, so any local user can run commands as root.
- **After root.** Webshells written with `printf <base64> | base64 -d > <templates>/zz<random>.tpl`; a larger shell needing the key `zz2026` that runs OS commands and PHP and saves uploads to `/tmp/.up.tpl`, later copied into the portal as `challenge_render.tpl`. Then TSGA (`nohup /tmp/CPconfigdaemon >/tmp/.bd.log 2>&1 &`), relaunched as `slot_CPconfigdaemon` in the boot persistence directory, with TSProxy written to `/lib/libcpfwcommon.so` and injected into appliance processes to handle marked attacker connections. TSGA steals configuration, persists through backups and snapshots, and can tamper with binary firewall logs. It listens on TCP 11072 on all IPv4 interfaces and uses `/tmp/.p_sock`.
- **Destruction.** The gogo scanner for internal discovery; SSH to an ESXi host as `vpxuser`; the `destroy_v6` wiper staged at `/tmp/des`, which zero-fills then deletes files and writes `DREAM_ANNEXATION.txt` into each directory. Check Point does not say how the attacker obtained the `vpxuser` credentials.
- **Who.** TSGA and TSProxy are modified PhiliKit variants; ESET associated PhiliKit with China-nexus UNC5221. Check Point notes LightNode VPS hosting and scanning between 00:00 and 09:00 UTC, but says the destruction, the Israel focus and the Hebrew note do not fit, and that it cannot assess the operation with high confidence. This pack makes no attribution.

## Fixed versions and mitigation

- **CVE-2026-123039** (sk1000362, CVSS 7.8): Jumbo Hotfix R82.20 Take 14, R82.10 Take 52, R82 Take 132, R81.20 Take 174. Affects Force Firewalls, Management and Log Servers, Multi-Domain Security Management and Log Server, and Maestro Orchestrator on R81.20 to R82.20, plus end-of-support R81 and R81.10. Interim: stop `dynamic_server` and keep it from restarting as sk1000362 describes; the Dynamic CLI commands in sk144112 then stop working.
- **PHP2Shell** (sk1000302, Check Point CVSS 9.2): the same Jumbo takes, or the standalone hotfix available since 23 October 2026 18:30 GMT (reboot needed). Spark R82.00.11 build 998002843 and R81.10.17 build 996005005. Affects gateways using the Mobile Access Portal, Remote Access VPN with SSL Network Extender, Remote Access VPN with a SAML realm, Identity Awareness Captive Portal, UserCheck Portal or Zero Phishing.
- **Patching does not remove an implant.** Hunt every gateway that ran an affected portal unpatched after 21 October.

## Indicators (defanged; Check Point Research, 12 November 2026)

| Indicator | Role |
|---|---|
| `130.94.19[.]204` | Scanning and exploitation source |
| `130.94.19[.]168` | Scanning source |
| `upload_progress_pwn` | Marker in PHP session files (seen under `/opt/CPcvpn-R81.20/tmp/`) |
| `zz*.tpl`, `challenge_render.tpl`, `/tmp/.up.tpl` | Webshells and uploaded file |
| `/tmp/CPconfigdaemon`, `slot_CPconfigdaemon`, `/tmp/.bd.log` | TSGA |
| `/lib/libcpfwcommon.so` | TSProxy |
| TCP 11072, `/tmp/.p_sock` | TSGA and PhiliKit listener and socket |
| `/tmp/des`, `DREAM_ANNEXATION.txt` | Wiper and note on ESXi |

| SHA256 | File |
|---|---|
| `edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3` | .tpl webshell |
| `4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8` | slot_CPconfigdaemon |
| `d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63` | CPconfigdaemon |
| `3b51080a909023f7d484e2443740b572307ce0054eb9e32d98f0a06bfcd2db90` | gogo |
| `c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237` | destroy_v6 |
| `0522937c0c0337be54fe25493539e5f5f8ceb9742c980aaff1cfc9515f3a96f7` | DREAM_ANNEXATION.txt |
| `ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7` | philistine (PhiliKit) |
| `fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da` | libdssafe.so (PhiliKit) |

Check Point also lists: a process or binary named like `CPconfigdaemon`; scanner or wiper tools under `/tmp` or `/temp`; a ransom-style note referencing "Dream Annexation" with no payment demand; and unexplained gaps in firewall traffic logs, especially after a logging daemon crash. Check Point says absence of a match does not rule out compromise.

## Data sources and tables

| Query | Data source | What it finds |
|---|---|---|
| `host-checks.sh` | Gateway, Expert mode, read-only | Socket mode, `dynamicCli.log` rejections, implant paths, 11072 listener, processes with TSProxy mapped, `zz*.tpl` and PHP in portal `.tpl` files, session marker, segfaults |
| `esxi-checks.sh` | ESXi shell, read-only | `vpxuser` SSH logins, wiper commands in `shell.log`, `/tmp/des`, notes |
| `rule-cp-portal-webshell-drop.yml` | Linux `process_creation` (auditd execve) | `base64 -d` writing a `.tpl`, or the upload copy |
| `rule-cp-tsga-artefacts.yml` | Linux `file_event` | TSGA, TSProxy and upload paths |
| `rule-cp-tsga-process.yml` | Linux `process_creation` | TSGA launch, wiper, gogo |
| `rule-cp-scan-sources.yml`, `query.kql` Q1 | Firewall, CommonSecurityLog, Syslog | The two source addresses |
| `query.kql` Q2 | Portal or WAF URL logs | Requests for `.tpl` files or the marker |
| `query.kql` Q3 | Syslog | Any implant, wiper or note string |
| `query.kql` Q4 | Syslog (`dynamicCli.log`) | Blocked CVE-2026-123039 attempts after patching |
| `rule-esxi-wiper-note.yml`, `query.kql` Q5 | ESXi syslog | `vpxuser` SSH logins, note files |
| `query.kql` Q6 | CommonSecurityLog | Hours a gateway stopped logging |
| `checkpoint-php2shell-tsga.yar` | Files collected from the gateway or ESXi | Webshell, TSGA, TSProxy, wiper, note, gogo hash |

## First-hour checklist

1. **Patch** every gateway, Management and Log Server to the Jumbo takes above. If you cannot yet, apply the sk1000362 interim step and the PHP2Shell hotfix.
2. **Check the socket.** `ls -l /tmp/dynamic_socket` should show `srw-rw---- root config` (0660), not 0777. After patching, read `/var/log/dynamicCli.log` for `Rejected connection from unauthorized uid`; a non-zero or unexpected uid (for example 99, nobody) is a blocked attempt. Correlate bursts with portal and authentication logs.
3. **Run `host-checks.sh`** on every gateway that had an affected portal reachable from the internet after 21 October. Save the output off the box.
4. **Search back to 30 October** for the two addresses (Q1) and for portal requests to `.tpl` files (Q2).
5. **Check ESXi.** Run `esxi-checks.sh` on every ESXi host the gateway could reach, and Q5 in the SIEM. A `vpxuser` SSH login from a gateway is a finding.
6. **Look for log gaps** (Q6). TSGA can tamper with binary firewall logs.
7. **If anything hits:** isolate, preserve memory and disk, contact Check Point, rebuild the gateway from known-good media, and rotate every secret it held (VPN and portal certificates, LDAP and RADIUS bind accounts, SIC, admin credentials, pre-shared keys). Reset `vpxuser` through vCenter, review ESXi local accounts and turn SSH off on ESXi where it is not needed.

## Tuning and false positives

- Most gateways do not forward process or file events. The Sigma rules need auditd or an equivalent agent; the shell scripts are the main tool.
- `challenge_render.tpl` may also be a genuine portal file name: judge it by content, size and time against a clean gateway on the same version.
- `libcpfwcommon.so` is a name chosen to look like a Check Point library. Check Point lists `/lib/libcpfwcommon.so` as the TSProxy drop path. Confirm against a clean gateway before acting on the name alone.
- Portal segfaults can have other causes. Hundreds in a short window, with session files containing `upload_progress_pwn`, is the pattern Check Point describes.
- gogo is a public scanner. The YARA rule matches only the published hash; the Sigma selection on the name should be scoped to gateways and ESXi.

## Validation notes

- Draft for review: untested in a live estate. No sample was run, downloaded or built.
- `sigma check --fail-on-issues`: 0 errors and 0 issues (`sigma-check.txt`). Splunk conversion succeeds for all five rules; the four Linux rules also convert for Microsoft XDR and Sentinel ASIM. The firewall rule has no Kusto table mapping, so CI runs Splunk only (`ci-targets.txt`).
- `checkpoint-php2shell-tsga.yar` compiles with yara-python 4.5.4 and was smoke-tested against synthetic strings only (`yara-check.txt`). String choices follow Check Point's published paths and key; they are not taken from samples.
- `host-checks.sh` and `esxi-checks.sh` pass `bash -n` and `sh -n`. Check commands on a lab gateway before running across an estate.

## Related Hunt Lab packs

- `hunts/2026/2026-10-22-php-web-server-spawning-shell`: PHP and web server parents spawning shells.
- `hunts/2026/2026-10-28-php2shell-fragnesia-chain`: the PHP2Shell and Fragnesia chain on firewall management interfaces.
- `hunts/2026/2026-10-29-esxi-audit-log-gaps`: ESXi audit-log gaps and unpatched inventory.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 13 November 2026. Facts and indicators from Check Point Research, the Check Point advisory and sk1000362 and sk1000302; PhiliKit background from ESET; KEV status from CISA.
- Sigma rules and the YARA file: Detection Rule License (DRL) 1.1. `query.kql`, `host-checks.sh`, `esxi-checks.sh`: MIT.
