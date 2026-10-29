# Cisco SD-WAN KeyDrift controller hunt (CVE-2026-20127)

> **Status banner:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-10-29-cisco-sdwan-keydrift` |
| **Date** | 29 October 2026 |
| **Status** | Experimental |
| **Platforms** | Linux controller host telemetry / syslog; Microsoft Defender XDR / Sentinel (KQL); Splunk |
| **ATT&CK** | T1190 (Exploit Public-Facing Application), T1055 (Process Injection), T1552 (Unsecured Credentials), T1543 (Create or Modify System Process) |
| **CVEs** | CVE-2026-20127. KEV and EPSS are in [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `query.kql` (MIT), `query.spl` (MIT), `rule-runit.yml` + `rule-vdaemon-bin.yml` + `rule-conf-sshd.yml` (Sigma, DRL 1.1) |

## Hypothesis

An operator who exploited CVE-2026-20127 against a Catalyst SD-WAN controller leaves KeyDrift artefacts: modified runit launchers for sshd/aaamgr, staging file `/var/tmp/vdaemon.bin`, and an injected `vdaemon` / `conf_sshd` chain. Defenders should see at least one of those classes on a host that was reachable on management ports while vulnerable.

## Threat context

- Cisco Talos (28 October 2026): UAT-11473 deployed KeyDrift (PolyFlame / LittleFilch) after CVE-2026-20127. Infrastructure overlaps Volt Typhoon Silent Train with high confidence. https://blog.talosintelligence.com/uat-11473-keydrift/
- Cisco advisory cisco-sa-sdwan-rpa-EHchtZk (CVE-2026-20127, CVSS 10). Fixed releases: 20.9.8.2, 20.12.5.3 / 20.12.6.1, 20.15.4.2, 20.18.2.1. https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk
- CISA KEV dateAdded 2026-02-25, due 2026-02-27. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Cyber-Threat.net Silent Train explainer: https://cyber-threat.net/volt-typhoon-silent-train-relay-framework/

**IOCs:** Prefer Talos-published indicators. Defang IPs and domains in tickets. These rules are path- and behaviour-based, not IP signatures.

## Data sources and tables

| Query | Data source | Requirement |
|---|---|---|
| `query.kql` | DeviceFileEvents / DeviceProcessEvents / Syslog | Controller file and process telemetry, or forwarded auth/syslog |
| `rule-runit.yml` | Sigma file_event / linux | Creates or modifications under `/etc/sv/sshd/` or `/etc/sv/aaamgr/` |
| `rule-vdaemon-bin.yml` | Sigma file_event / linux | `/var/tmp/vdaemon.bin` or `/var/tmp/vdaemon.conf` |
| `rule-conf-sshd.yml` | Sigma process_creation / linux | `conf_sshd`, `rsshd`, unexpected `libdssl.so` loaders |
| `query.spl` | linux / syslog sourcetypes | Splunk Add-on for Unix/Linux or raw syslog |

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1190 | Exploit Public-Facing Application |
| T1055 | Process Injection |
| T1552 | Unsecured Credentials |
| T1543 | Create or Modify System Process |

## Tuning and false positives

- Vendor-supported upgrades that rewrite runit scripts — join to change tickets.
- Lab controllers deliberately staging Talos sample paths.
- Auth log `vmanage-admin` lines from known controller System IPs (baseline before alerting).
- Expected volume: near-zero on clean production controllers; any hit warrants admin-tech collection.

## Validation notes

- Draft only. sigma-cli / conversion not run in this pack yet.
- Test plan (isolated lab you own): (1) touch the staging paths and confirm file rules fire; (2) never replay the CVE-2026-20127 exploit against production; (3) rotate lab keys after any KeyDrift sample handling.

## Rule IDs

- `rule-runit.yml`: `eef223e2-437a-43a0-989f-714b05857faf`
- `rule-vdaemon-bin.yml`: `8673046a-2e77-479f-bc1d-2c54bdfbdfc2`
- `rule-conf-sshd.yml`: `c7178e9e-1225-4458-9866-dc136f1b08b0`

## Credits and licence

- Author: Cyber-Threat.net Hunt Lab
- Sigma rules: [DRL 1.1](../../../../LICENSE-DRL). `query.kql`, `query.spl` and this README: [MIT](../../../../LICENSE).
