# Changelog

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Hunts are listed by publication date.

## [Unreleased]

### Fixed

**SCKit partner-access Sigma identifiers (20 November 2026)**
- `hunts/2026/2026-11-14-sckit-screenconnect-partner-access/`
- New titles and rule IDs so the four Sigma rules can coexist with the 12 November SCKit rogue-client pack in `sigma check`. Detection logic is unchanged. The network rule still adds the 13 November indicators. Each rule records the original identifier in `related`.


### Added

**Optimizely Web script injection (16 November 2026)**
- `hunts/2026/2026-11-17-optimizely-web-script-injection/`
- Sigma for proxy and DNS hits on the published injection infrastructure; KQL for Microsoft Defender and Sentinel; YARA for saved snippets and page archives; a read-only snippet check script. Covers 13 to 17 November 2026, including the earlier webshell.lol wave. Companion to the Cyber-Threat.net Alert: https://cyber-threat.net/optimizely-supply-chain-attack-check-scripts/
- Status: experimental; YARA tested on synthetic samples only. Indicators from Report URI and BleepingComputer. No CVE.

**NoisyTCP CVE-2026-99288: Linux TCP remote crash**
- `hunts/2026/2026-11-17-noisytcp-cve-2026-99288/`
- Read-only exposure check script, Sigma for kernel panics with tcp_v4_rcv in the trace, and KQL for Defender Vulnerability Management and Sentinel. Companion to the Cyber-Threat.net Alert: https://cyber-threat.net/noisytcp-cve-2026-99288-linux-tcp-crash/
- Status: experimental, untested. Not in KEV (catalogue 2026.11.17).

**BO Team: Log4Shell on vCenter and a supply-chain near miss**
- `hunts/2026/2026-11-16-bo-team-log4shell-vcenter/`
- Sigma for the hourly pgcache cron script, nofrillsdns or GSocket installer fetches, and comsvcs.dll LSASS dumps; hand KQL for LSASS and NTDS dumping, the published file paths and hashes, and the published infrastructure; a Linux auditd shell-hunt guide; YARA for the pgcache and GSocket downloader strings. Companion to the Cyber-Threat.net article: https://cyber-threat.net/bo-team-log4shell-vcenter-supply-chain/
- Status: experimental, untested. Source: Kaspersky ICS CERT (5 November 2026). CVE-2021-44228 is in KEV (added 2021-12-10).

**ARTEX agent-speed intrusions: FBI FLASH-20261113-001**
- `hunts/2026/2026-11-16-artex-fbi-flash-agent-speed/`
- Sigma for the FLASH IPv4 addresses and DNS lookups of the FLASH domain; hand KQL for sign-ins from FLASH addresses, unusual service-principal sign-ins, application credential and permission changes, Graph API bursts and portal request bursts. The FLASH addresses are historical and can be reassigned. Companion to the Cyber-Threat.net article: https://cyber-threat.net/hunt-lab-detecting-artex-agent-speed-intrusions/
- Status: experimental, untested. Source: FBI FLASH-20261113-001 (13 November 2026, TLP:CLEAR). No CVE.

**SilentAir and LIMINAL PANDA: signalling interception and GTPDoor on the IPX**
- `hunts/2026/2026-11-14-silentair-liminal-panda-signalling/`
- Operator pseudo-logic for SS7 UpdateLocation and Diameter ULR diversion; Sigma for the published GTPDoor v3 MD5; enterprise KQL for SMS sign-in exposure, phone-method changes and risky sign-ins; a Splunk conversion. Write-up link to be added when live.
- Status: experimental, untested. Source: Enea. No CVE.

**SCKit worm: rogue ScreenConnect clients pushed through cloud Run Command**
- `hunts/2026/2026-11-14-sckit-screenconnect-partner-access/`
- Updated from the 12 November pack with the 13 November network indicators (185.241.211.197, 007.from-ak.com, UpdateConnect.ClientSetup.msi, portproxy and hosts-file edits as Q8). Sigma for dropper files, TrapWatch persistence, a second ScreenConnect client and the published network indicators; hand KQL for Run Command children, a second client, Defender exclusions, cookie theft and the 13 November extras; YARA for kit scripts and the published SHA256 values. Companion to the Cyber-Threat.net Alert: https://cyber-threat.net/screenconnect-unauthorised-partner-access-sckit/
- Status: experimental, untested. Indicators from Huntress (11 and 13 November 2026); CVE-2026-127063 and technician-client guidance from the ConnectWise Trust Center (updated 13 November 2026, 21:15 UTC) and the CVE-2026-127063 disclosure. Not in KEV (catalogue 2026.11.13).

**Citrix NetScaler Console CVE-2026-120869: exposure check**
- `hunts/2026/2026-11-14-citrix-netscaler-console-cve-2026-120869/`
- Exposure checklist only: inventory of Console 14.1 builds before 14.1-74.34, restrict the Console IP to a trusted management network, and review audit and configuration history. No exploit-specific Sigma or KQL, because Citrix published no indicators or log signatures. Companion to the Cyber-Threat.net Alert: https://cyber-threat.net/citrix-netscaler-console-cve-2026-120869/
- Status: experimental, untested. Facts from Citrix CTX697320 and CTX697305, and CVE.org CVE-2026-120869; not in KEV (catalogue 2026.11.13). FIRST EPSS on 13 November 2026 is 0.00513 (44.3rd percentile). Exploitation in the wild is not confirmed.

**PHP2Shell on Check Point gateways: portal webshells, TSGA and an ESXi wiper**
- `hunts/2026/2026-11-13-checkpoint-php2shell-tsga-wiper/`
- Read-only gateway and ESXi triage scripts (CVE-2026-123039 socket and log checks, including the sk1000362 `Received =` greps for unexpected DynamicCLI commands, zz*.tpl and challenge_render.tpl webshells, TSGA and TSProxy paths, TCP 11072, upload_progress_pwn session files, vpxuser SSH, destroy_v6 and DREAM_ANNEXATION.txt); Sigma for the webshell drop, TSGA artefacts and process, the two scanning addresses and the wiper note; hand KQL for Sentinel (scan sources, .tpl requests, implant strings, blocked DynamicCLI calls, vpxuser SSH, firewall log gaps); YARA for the webshell, TSGA and TSProxy, the wiper and the eight published SHA256 values (the webshell rule requires the published key or upload path, not only a mention of challenge_render.tpl). Companion to the Cyber-Threat.net Alert (write-up link to be added when live).
- Status: experimental, untested. Indicators from Check Point Research and the Check Point advisory (12 November 2026); KEV catalogue 2026.11.10 (PHP2Shell CVEs listed; CVE-2026-123039 not listed).

**Apache httpd CVE-2026-119618: find HTTP/2 servers on affected builds**
- `hunts/2026/2026-11-13-apache-httpd-mod-http2-cve-2026-119618/`
- Exposure check, not an exploit hunt: read-only host script (build and package version, http2_module loaded, every Protocols line httpd loads, verdict), an outside-in ALPN and h2c check, a crash-watch script, and hand KQL for Defender Vulnerability Management and for AH00052 and kernel segfault bursts. Distribution fixed versions for Red Hat, Ubuntu and Debian, and the Protocols http/1.1 stopgap. Companion to the Cyber-Threat.net Alert (write-up link to be added when live).
- Status: experimental, untested. Facts from Apache (2.4.71, 11 November 2026), Red Hat, Ubuntu and Debian; not in KEV (catalogue 2026.11.10). No Sigma rules: there is no exploit-specific log signature.

**SCKit worm: rogue ScreenConnect clients via cloud Run Command**
- `hunts/2026/2026-11-12-sckit-screenconnect-rogue-client/`
- Sigma for the C:\Windows\Temp dropper files and RelayTrap folder, the TrapWatch task and RelayTrapLiteAlert Run value, rogue client command lines and the Huntress network indicators; hand KQL for Run Command children, a second ScreenConnect client per device, Defender exclusions and cookie theft on technician workstations; YARA for kit scripts and the 16 published SHA256 values. Companion to the Cyber-Threat.net Alert (write-up link to be added when live).
- Status: experimental, untested. Indicators from Huntress (11 November 2026); CVE-2026-127063 and technician-client guidance from the ConnectWise Trust Center update (12 November 2026, 18:45 UTC) and the CVE-2026-127063 disclosure.

**wfx (WFX Phantom) GitHub Actions secret stealer: run gaps and cloud persistence**
- `hunts/2026/2026-11-12-wfx-phantom-github-actions-stealer/`
- Read-only gh scripts for probe PRs, payload and cleanup commits and missing workflow run numbers; Sigma for wfx- AWS sessions, trust policies opened to any AWS account, deleted workflow runs and runner egress to the collection servers and Telegram; hand KQL for CloudTrail, Entra wfx-ci- federated credentials and runner /proc memory reads; YARA for the stealer config, the hidden .ci-*.sh npm hook and injected workflow steps; rotation checklist. Companion to the Cyber-Threat.net Alert (write-up link to be added when live).
- Status: experimental, untested. Indicators from StepSecurity, Aikido and SafeDep (12 November 2026). No CVE, so no `cve-context.yaml`.

**Outlook CVE-2026-124194: outbound SMB or WebDAV NTLMv2 disclosure**
- `hunts/2026/2026-11-11-outlook-cve-2026-124194-ntlm/`
- Sigma for outbound SMB or NetBIOS session traffic (TCP 445 or 139) to a non-private address initiated by the kernel redirector (System/PID 4, ntoskrnl, or an empty image), and for WebDAV PROPFIND or OPTIONS with a Microsoft-WebDAV-MiniRedir or DavClnt user agent; hand KQL and Splunk SPL for those plus davclnt.dll loads and outgoing NTLM events, with the any-process firewall query as the primary network check. Companion to the Cyber-Threat.net November Patch Tuesday Alert (post 1832): https://cyber-threat.net/november-2026-patch-tuesday-outlook-zero-day/
- Status: experimental, untested. CVE from Microsoft; KEV catalogue 2026.11.10, due 24 November 2026. FIRST EPSS had not scored the CVE as of 11 November 2026.

**Cisco BroadWorks CVE-2026-20320: OCI-P blind XXE file read**
- `hunts/2026/2026-11-11-cisco-broadworks-cve-2026-20320-ocip-xxe/`
- Sigma for connections to the OCI-P provisioning ports (TCP 2208 and 2209), to be scoped with the OCI-P Network Access List; hand KQL and Splunk SPL for OCI-P sessions from outside the allow-list, new egress and DNS from BroadWorks servers (the out-of-band XXE channel), the two correlated within 10 minutes, Java child processes, and DTD or entity declarations in OCI-P logs.
- Status: experimental, untested. CVE from Cisco advisory cisco-sa-bworks-xxe-uwUd7CEt; KEV catalogue 2026.11.10, due 24 November 2026. No indicators published.

**Barracuda ESG CVE-2026-116606 and CVE-2026-111560: config-import bypass to root**
- `hunts/2026/2026-11-11-barracuda-esg-cve-2026-116606-config-import/`
- Sigma for timezone values carrying shell metacharacters in proxy or WAF logs in front of a Barracuda Admin UI; hand KQL and Splunk SPL for Admin UI connections from outside the management range, configuration restore, import and timezone events in appliance syslog, and new outbound destinations from the appliance. Companion to the Cyber-Threat.net Alert (post 1669): https://cyber-threat.net/barracuda-esg-cve-2026-116606-pre-auth-root/
- Status: experimental, untested. CVEs from Barracuda and Mandiant (MNDT-2026-0041, MNDT-2026-0042); KEV catalogue 2026.11.10, due 13 November 2026. No indicators published.

**Openwave Webtop Media Transcoder CVE-2026-111793: file-type restriction bypass**
- `hunts/2026/2026-11-11-openwave-webtop-cve-2026-111793-transcoder/`
- Sigma for transcoder requests naming document types a webmail preview service rarely needs (path scope is a placeholder to replace); hand KQL and Splunk SPL for connections to the transcoder from outside the Webtop front ends, unusual file types, and per-account spikes against a 30-day baseline; version inventory against the 1.1.22.0 fix.
- Status: experimental, untested. CVE from Openwave CAN-2026-2032674 and JPCERT/CC JVNVU#93403064; KEV catalogue 2026.11.10, due 24 November 2026. No indicators or request format published.


**Qubole vendor-account AssumeRole and stale third-party trust**
- `hunts/2026/2026-11-10-qubole-sts-assumerole-vendor-trust/`
- Sigma for AssumeRole from the Qubole vendor account and the actor-only IAM user; hand KQL, Splunk SPL and Athena SQL for follow-on secret, parameter, Lambda and S3 activity; IAM Access Analyzer and CLI audit for stale trust. Companion to the Cyber-Threat.net Alert (write-up link to be added when live).
- Status: experimental, untested. Identifiers from Wiz (9 November 2026). No CVE, so no `cve-context.yaml`.

**OpenSSH *sshole musl / Alpine password bypass (CVE-2026-123158)**
- `hunts/2026/2026-11-06-openssh-sshole-musl/`
- Sigma for successful password auth to common `*` shadow accounts and Alpine `alpine`+doas elevation after SSH; hand KQL and an inspect-only host-check script for PasswordAuthentication/UsePAM/musl exposure. Companion to the Cyber-Threat.net Alert.
- Status: experimental, untested. CVE ID and CVSS from GHSA/NVD; OpenSSH and Alpine advisories assigned none. Not in KEV catalogue 2026.11.04; EPSS not yet scored.

**CWPdoor: trojanised Control Web Panel cwpsrv**
- `hunts/2026/2026-11-06-cwpdoor-cwpsrv/`
- YARA for `X-Ngx-Integrity-*` / `ngx_http_integrity_helper` strings and known MD5s; Sigma for C2 `136.0.141.71`; hand KQL and host checks for the integrity socket and binary. Companion to the Cyber-Threat.net Alert.
- Status: experimental, untested. No CVE in the XLab write-up.

### Changed

**KEV and EPSS refresh, 6 November 2026**
- FIRST EPSS scores and check dates refreshed for all CVE hunts; CISA KEV catalogue 2026.11.04. Added `cve-context.yaml` for CVE-2026-123158 (not in KEV; EPSS not yet scored).

### Added

**CRAFTY FALCON (CERT-In CIAD-2026-0058): BFSI API abuse and AI pentest artefacts**
- `hunts/2026/2026-11-05-crafty-falcon-bfsi/`
- Sigma for AI offensive framework artefacts (ARTEX, PentAGI, Cairn, CyberStrikeAI), high-risk AWS SSM / Lambda management calls, and ARTEX login requests carrying a captcha field; hand KQL for micro-value transfer precursors, staging-to-production access and the trojanised ARTEX Docker image, plus an inspect-only Docker host-check script. Companion to the Cyber-Threat.net Alert.
- Status: experimental, untested. Campaign advisory with no CVE, so no `cve-context.yaml`. ARTEX Docker checks follow BadByte (4 November 2026) and are not attributed to CRAFTY FALCON.

### Added

**Synology C3RB3R / outdated DSM exposure and encryption artefacts**
- `hunts/2026/2026-11-03-synology-c3rb3r-dsm/`
- Sigma for `.L0CK3D` / `read-me3.txt` artefacts and inbound DSM management-port exposure; hand KQL and a DSM host-check script. Companion to the Cyber-Threat.net Alert (post 1450).
- Status: experimental, untested. Synology confirmed ransomware against outdated DSM on 29 October 2026 (Synology-SA-24:20 / CVE-2024-10441 linked).

### Changed

**KEV and EPSS refresh, 5 November 2026**
- FIRST EPSS scores and check dates refreshed for all CVE hunts; CISA KEV catalogue 2026.11.04. Added `cve-context.yaml` for CVE-2024-10441 (not in KEV; EPSS 0.01251).

### Added

**VOLTA-AUTODOXER OpenRouter triage and artefacts**
- `hunts/2026/2026-11-02-volta-autodoxer/`
- Sigma for OpenRouter chat-completions egress, named VOLTA report/zip/debug artefacts, and headless Chrome/Chromium cue; hand KQL for Defender XDR. Includes the OpenRouter allowlist caveat.
- Status: experimental, untested. Behavioural cues from Cisco Talos (31 October 2026); no sample detonated.

**LXD trust store and HTTPS API exposure (CVE-2026-112816)**
- `hunts/2026/2026-11-02-lxd-trust-store-cve-2026-112816/`
- Sigma for LXD lifecycle trust/membership changes over TLS and newer security-event identity changes; hand KQL and a host-check script. Companion to the Cyber-Threat.net Alert.
- Status: experimental, untested. No known exploitation as of 2 November 2026.

**Agent-driven intrusion: machine-speed discovery and bulk collection**
- `hunts/2026/2026-11-02-agentic-intrusion-machine-speed/`
- Sigma correlation for interpreter-spawned discovery bursts, plus hand KQL for bulk Graph reads, even-timed probing and password-reset clusters. General guidance after the Chainalysis disclosure; no incident IOCs.
- Status: experimental, untested.

### Changed

**KEV and EPSS refresh, 2 November 2026 (evening)**
- FIRST EPSS scores and check dates refreshed for all CVE hunts; catalogue still 2026.10.30. Added `cve-context.yaml` for CVE-2026-112816 (not in KEV; EPSS 0.00303).

### Added

**GhostAction and Gheist: malicious GitHub Actions stealing secrets**
- `hunts/2026/2026-10-31-ghostaction-gheist/`
- Sigma for GhostAction secret exfiltration and Gheist self-hosted runner activity, plus KQL.
- Status: experimental, untested.

**LiteLLM 1.107.0 cook.pth / sitecustomize credential theft**
- `hunts/2026/2026-10-31-litellm-11070-startup-hooks/`
- Sigma for Python startup-hook files and exfil domain, KQL and YARA for cook.pth.
- Status: experimental, untested.

**Cursor Marketplace SSH persistence (Anthropic.claude-code 2.1.313)**
- `hunts/2026/2026-10-30-cursor-marketplace-ssh-persistence/`
- Sigma for `svc-telemetry` authorized_keys, LaunchAgent/cron/SysMon persistence paths, reverse SSH tunnel command lines, and egress to 134.209.82.225. Hand KQL, SPL and a read-only host-check script. Companion to the Cyber-Threat.net Alert (slug omits product brand from URL).
- Status: experimental, draft, untested. IOCs only from Cursor / OpenSourceMalware / Phorion.

### Changed

**KEV and EPSS refresh, 27 October 2026 (evening)**
- CISA added Node2Shell CVE-2026-111497 to KEV on 27 October 2026 (catalogue 2026.10.27; due 10 November; ransomware use Unknown; forensic triage No). `cve-context.yaml` for the 2026-10-26 Node2Shell hunt and the README table now show it as listed. EPSS for CVE-2026-111497 is 0.55483 (percentile 99.03, model date 27 October).
- Other hunts: catalogue version, checked dates and EPSS refreshed from the same feeds (PHP CVEs remain in KEV; their EPSS model date moved to 27 October).
- README "Why KEV and EPSS can disagree" updated: Node2Shell is no longer an example of "high EPSS, not in KEV"; it joins the PHP CVEs as a gap that closed.
- Node2Shell hunt README: the "no in-the-wild exploitation" line replaced with the KEV listing and ELLIO's 26 October sighting (no PoC links).

### Added

**ESXi audit-log gaps and unpatched inventory (CVE-2026-41709)**
- `hunts/2026/2026-10-29-esxi-audit-log-gaps/`
- Inventory, syslog-silence and shell-without-nearby-auth hunts for Broadcom VMSA-2026-0006 / CISA KEV CVE-2026-41709. Dual Sigma (shell/busybox baseline plus same-message auth-noise filter), hand KQL and SPL. Companion to the Cyber-Threat.net Alert.
- Status: experimental, draft, untested. Keep experimental until sigma-cli conversion and a benign lab simulation are recorded in EVIDENCE.md.

**Magento PolyShell CMS loader domains (CVE-2026-48356)**
- `hunts/2026/2026-10-27-magento-cms-loader-domains/`
- DNS-query Sigma for three Sansec-named loader hosts, with hand-written Defender XDR / Sentinel DNS KQL and Splunk conversion. Companion to the file-event webshell hunt.
- Status: draft, untested. Sigma check clean; Kusto backends do not map dns_query in our tooling.


**Magento / Adobe Commerce PolyShell webshells (CVE-2026-48356)**
- `hunts/2026/2026-10-27-magento-polyshell-webshell/`
- File-event Sigma for PHP/PHTML/PHAR under `*/media/custom_options/`, and for any path ending in `accesson.php`. KQL, ES|QL (ECS file_event) and Splunk conversions. Based on Adobe APSB26-73, CISA KEV and Sansec PolyShell research.
- Status: draft, untested. Sigma check clean; conversions clean, not engine-tested.


**testmetest npm worm: `.github/init.js` loaders, native-addon drops and persistence**
- `hunts/2026/2026-10-27-testmetest-ide-hook-loader/`
- Process creation: node or bun running `.github/init.js`, a hidden `/tmp/.<pid>` or `%TEMP%\.nc<pid>.js` drop, or a `.b-*` stage; processes naming the `net-health-checker` or `pkg-runtime` persistence. File events: the persistence files, `.napi_cache` and the Windows drop. A read-only file-search script for workstations and runners, and GitHub tree-sweep commands. Based on JFrog and SafeDep research.
- Includes two Sigma rules, per-hunt conversion targets, a standard-library Python script with offline tests, sources and test evidence.
- Status: test. The rules were tested on synthetic events and public datasets and the script on Linux; conversions are clean but not engine-tested.
- `.gitignore`: `evidence/` and `iocs.md` added, so private working files cannot be committed by accident.

**Node2Shell (CVE-2026-111497): shell spawned by a Node.js process**
- `hunts/2026/2026-10-26-node2shell-brotli/`
- Process creation: a shell or download tool started directly by node or bun, with package-manager and build-tool parents filtered. Hypotheses for Node.js crashes (SIGSEGV/SIGABRT), Brotli request bodies and exposure.
- Includes Sigma, per-hunt conversion targets, sources and test evidence.
- Status: test. The Sigma rule was tested on synthetic and public datasets; conversions are clean but not engine-tested.

**Arista EOS CVE-2026-7473 (draft)**
- `hunts/2026/2026-10-24-arista-cve-2026-7473/`
- Hypotheses for flow and network data: tunnel traffic to Arista decapsulation IPs that is the wrong tunnel type, or comes from an unknown peer. Based on Arista SA 0137.
- README and sources only. KQL and SPL are held until tested. No Sigma rule, and the README explains why.
- Status: draft, untested.

**DCSync: directory replication rights used by a non-machine account**
- `hunts/2026/2026-10-25-dcsync-replication-by-non-dc-account/`
- Security event 4662 on domain controllers: replication rights (Get-Changes, Get-Changes-All, Get-Changes-In-Filtered-Set) used by an account that is not a machine account.
- Includes Sigma, KQL (Sentinel `SecurityEvent`), Splunk SPL, sources and test evidence.
- Status: test. The Sigma rule was tested against public datasets; the KQL and SPL are converted but not engine-tested.

**LSASS dumping with built-in Windows tools**
- `hunts/2026/2026-10-25-lsass-dump-via-lolbins/`
- Process creation: comsvcs.dll MiniDump through rundll32, and RdrLeakDiag `/fullmemdmp` or `/memdmp`.
- Includes Sigma, KQL (Defender XDR `DeviceProcessEvents`), Splunk SPL (Sysmon, plus an untested CIM variant), sources and test evidence.
- Status: test. The Sigma rule was tested against public datasets; the KQL and SPL are converted but not engine-tested.

**Per-hunt CI conversion targets**
- Every hunt with a `rule.yml` now has a `ci-targets.txt` listing the `sigma convert` targets CI runs for it. Added for the 2026-10-22 hunt and the hunt template.

**KEV and EPSS exploitation context for CVE hunts**
- `cve-context.yaml` in each hunt that covers a CVE (2026-10-22 PHP, 2026-10-24 Arista, 2026-10-26 Node2Shell): CISA KEV status (listed, date added, due date, known ransomware use, catalogue version) and FIRST EPSS score and percentile, each with the date checked. Hunts with no CVE have no file.
- `scripts/refresh_kev_epss.py` (standard library only) refreshes the files and a generated KEV and EPSS table in `README.md`; `--check` validates them offline. A refresh builds everything before writing, so a failed run changes nothing, and it never replaces an existing EPSS score with `null` unless run with `--allow-null`.
- README, CONTRIBUTING, the hunt template and the pull request template explain the fields: KEV is a yes/no catalogue, not a score; EPSS is a daily probability.
- `scripts/tests/test_refresh_kev_epss.sh`: offline safety tests for the refresh script (simulated feeds, run on a temporary copy of the repository), run by CI.
- The refresh script exits with code 3, writing nothing, when FIRST EPSS returns no score for any CVE (an outage, not a gap). Exit codes 0 to 3 are documented in the README and in `--help`.

### Changed

**KEV and EPSS refresh, 27 October 2026**
- CISA added the PHP CVEs (CVE-2026-109618, CVE-2026-109619) to KEV on 26 October 2026 (catalogue 2026.10.26; due 29 October; ransomware use Unknown). `cve-context.yaml` for the 2026-10-22 PHP hunt and the README table now show them as listed. Other hunts: checked dates and catalogue version only.
- README "Why KEV and EPSS can disagree" rewritten: the PHP CVEs are no longer an example of "high EPSS, not in KEV"; Node2Shell CVE-2026-111497 now is.

- `.github/workflows/validate.yml`: new step runs `python scripts/refresh_kev_epss.py --check`.
- `hunts/2026/2026-10-22-php-web-server-spawning-shell/README.md`: status banner now reads "Draft for review: untested" (it previously said "Draft for review: untested, not published").
- DCSync, LSASS, Node2Shell and Arista hunt READMEs: "not published" removed from the status banner, as the repository is public. Each banner's test status is unchanged. All hunt banners now use the template's form, "Draft for review: <test status>" (Arista's was "Draft — untested"), and the Arista Status row uses the template's values: "Experimental (draft, untested)".
- `.github/workflows/validate.yml`: new step runs `scripts/tests/test_refresh_kev_epss.sh`.
- `.github/workflows/validate.yml`: test conversions now read each hunt's `ci-targets.txt`, check every line against an allow-list and fail if the file is missing, empty or names a target that is not allowed.
- `README.md`: says the hunts are free to use, links to the Hunt Lab pages and RSS feed on Cyber-Threat.net, and adds badges for both.
- ECS pipeline maps Sigma's Description field to process.pe.description, so EQL and ES|QL no longer reject rules that use it. Sysmon data via Elastic's Windows integration fills it; Elastic Defend maps the field but doesn't document filling it on process events.
- CI: fail an Elastic (ES|QL) target when a rule's regex can't work on Elastic's regex engine: `^`/`$` anchors, `\b` or `(?…)` groups, `|re|i`/`|re|m`/`|re|s` modifiers, unsupported escapes, or a top-level branch without a leading `.*` (`scripts/check_elastic_regex.py`, with unit tests in `scripts/tests/test_check_elastic_regex.py`, run by CI). PHP web-server hunt: dropped the ES|QL target and corrected the Elastic note.
- CI: test conversions now cover every rule YAML in a hunt folder (any `*.yml` with a `detection` section), not only `rule.yml`.
- ECS pipeline maps Sigma `file_event` rules: `TargetFilename` to `file.path`, `Image` to `process.executable`, `ProcessId` to `process.pid` and `User` to `user.name`, limited to file creation and change events (`event.category` file, `event.type` creation or change). Elastic Defend lists all four fields on its file creation, modification, overwrite and rename events; Sysmon event 11 via Elastic's Windows integration fills them too (`User` only from Sysmon 13.30, and only the name part of `DOMAIN\user`). `User` values must omit the domain, because `user.name` holds the name only.
- CI now fails an Elastic target (ES|QL today; EQL and Lucene too if they are added to the allow-list) whose rule uses a field the target's pipeline doesn't map, so a rule can no longer pass CI and then be rejected or match nothing in Elastic.

## [0.1.0] - 2026-10-22

### Added

**First hunt: Hunt of the week #1**
- `hunts/2026/2026-10-22-php-web-server-spawning-shell/`
- Looks for a shell or download tool spawned by a PHP worker or web server on Linux. This is possible follow-on activity after CVE-2026-109618 and CVE-2026-109619.
- Includes KQL (Defender XDR `DeviceProcessEvents`), Sigma and Splunk SPL.
- Status: draft, untested.

**Templates and tooling**
- Hunt template: `templates/hunt-template/`.
- pySigma ECS field-mapping pipeline for Elastic: `pipelines/ecs-process-creation.yml`.
- GitHub Actions workflow that validates Sigma rules (`sigma check`) and runs test conversions.

**Repository files**
- Issue forms for new hunt requests and false positive reports.
- Pull request template.
- Licences: Detection Rule License 1.1 for Sigma rules, MIT for everything else.
- README, CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1) and SECURITY policy.

[Unreleased]: https://github.com/CyberThreatNet/hunt-lab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CyberThreatNet/hunt-lab/releases/tag/v0.1.0
