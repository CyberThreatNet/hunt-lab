# BeyondTrust SAWFLY / BARECLAW (CVE-2026-102764)

Full write-up: [Hunt: BeyondTrust ARMORY CASTLE SAWFLY / BARECLAW](https://cyber-threat.net/hunt-beyondtrust-armory-castle-sawfly-bareclaw/) on Cyber-Threat.net.

> **Draft for review: untested.** Behavioural starting points from Mandiant GTIG and BeyondTrust BT26-05. Mandiant YARA is cited, not relicensed here.

| | |
|---|---|
| **Hunt ID** | `2026-10-28-beyondtrust-sawfly-bareclaw` |
| **Date** | 28 October 2026 |
| **Status** | experimental (untested) |
| **Platforms** | file_event; Linux process_creation; HTTP proxy / WAF |
| **ATT&CK** | T1190, T1505.003, T1003, T1548.001, T1090, T1070.004 |
| **CVEs** | CVE-2026-102764 — [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `rule.yml` (file), `rule-process.yml`, `rule-proxy.yml`, hand KQL, `MANDIANT-YARA.md` |

## Hypothesis

Unauthenticated file ops on vulnerable BeyondTrust Remote Support land a PHP webshell under the site Laravel public root; follow-on uses `bt-secrets`, SUID helpers, `post_boot.d` persistence and a BARECLAW tunneler.

## Notes

- Prefer Mandiant YARA from the GTIG post for content matching; see `MANDIANT-YARA.md`.
- Appliance-local logs may be deleted; rely on forwarded syslog and perimeter proxy.
- No exploit payload is reproduced here.
