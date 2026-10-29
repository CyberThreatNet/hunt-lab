# ESXi audit-log gaps and unpatched inventory (CVE-2026-41709)

> **Status banner:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-10-29-esxi-audit-log-gaps` |
| **Date** | 29 October 2026 |
| **Status** | Experimental |
| **Platforms** | Syslog / ESXi hostd & shell logs; Microsoft Defender XDR / Sentinel (KQL); Splunk CIM |
| **ATT&CK** | T1562.003 (Impair Defenses: Indicator Blocking — logging), T1070 (Indicator Removal), T1078.001 (Valid Accounts: Default/local admin context) |
| **CVEs** | CVE-2026-41709. KEV and EPSS are in [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `query.kql` (MIT), `query.spl` (MIT), `rule.yml` + `rule-shell-without-auth.yml` (Sigma, DRL 1.1) |

## Hypothesis

An operator with ESXi admin rights who uses CVE-2026-41709 leaves less of an audit trail than a patched host would. Defenders should see either (a) hosts still below Broadcom's fixed builds, (b) unexpected silence in ESXi audit/shell syslog from hosts that normally talk, or (c) shell/busybox activity without a matching authentication event in the same window.

## Threat context

- Broadcom VMSA-2026-0006: insufficient logging; malicious administrator can perform certain operations without them being logged. Fixed builds listed in the advisory. https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017
- CISA KEV dateAdded 2026-10-28, due 2026-11-11. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CrowdStrike 2026 Legal Threat Landscape Report (28 Oct 2026): Warp Panda exploited CVE-2026-41709 as a zero-day as late as early 2026 in US intrusions that included the legal sector. https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-legal-threat-landscape-report/

The behaviour hunted here is **generic** for audit-gap and inventory detection. CrowdStrike attributes in-the-wild use to Warp Panda; these rules do not attempt to fingerprint that actor.

**IOCs:** none published on the CrowdStrike Legal Threat Landscape page for this CVE. None invented.

## Data sources and tables

| Query | Data source | Requirement |
|---|---|---|
| `query.kql` | CommonSecurityLog / Syslog / DeviceInfo (retarget) | ESXi syslog forwarded off-box; inventory of build IDs |
| `rule.yml` | Sigma product vmware / syslog | hostd / shell / auth syslog lines |
| `rule-shell-without-auth.yml` | Sigma product vmware / syslog | same-message auth-noise filter; time-window join is in KQL/SPL |
| `query.spl` | CIM or sourcetype=*esxi* | Splunk Add-on for VMware or raw syslog |

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1562.003 | Impair Defenses: Indicator Blocking |
| T1070 | Indicator Removal |
| T1078 | Valid Accounts (admin on ESXi) |

## Tuning and false positives

- Planned maintenance windows that pause syslog forwarding.
- New hosts not yet in the inventory baseline.
- Log pipeline outages that silence many hosts at once (treat as infrastructure, not host compromise).
- Auth and shell events landing in different indexes or with clock skew — widen the join window before escalating.
- Expected volume: site-specific; baseline 7–14 days per host before alerting on silence.

## Validation notes

- Draft only. sigma-cli / conversion not run in this pack yet.
- Test plan (isolated lab): (1) forward syslog from a lab ESXi; (2) confirm shell and auth lines parse; (3) stop the syslog agent and confirm the volume query fires; (4) never test the logging-bypass vulnerability itself outside a licensed lab that owns the hosts.

## Rule IDs

- `rule.yml` (ESXi shell/busybox activity): `f3a98772-547e-41f6-a477-7956a0eb4b3b`
- `rule-shell-without-auth.yml` (shell activity excluding same-message auth noise; correlate in SIEM): `f99f6306-9b14-4090-8480-be8ae9fb0acc`

## Credits and licence

- Author: Cyber-Threat.net Hunt Lab
- `rule.yml`, `rule-shell-without-auth.yml`: [DRL 1.1](../../../../LICENSE-DRL). `query.kql`, `query.spl` and this README: [MIT](../../../../LICENSE).
