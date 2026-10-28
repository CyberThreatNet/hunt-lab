# Ivanti Connect Secure X-DSCGI-PATH (CVE-2026-104935)

> **Draft for review: untested.** Behavioural starting points from Volexity and CISA. Not an exploit signature.

| | |
|---|---|
| **Hunt ID** | `2026-10-28-ivanti-ics-xdscgi` |
| **Date** | 28 October 2026 |
| **Status** | experimental (untested) |
| **Platforms** | HTTP proxy / WAF with custom headers; Sentinel Front Door diagnostics |
| **ATT&CK** | T1190, T1059, T1003, T1040, T1070, T1558.003 |
| **CVEs** | CVE-2026-104935 — [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `rule.yml` (proxy), hand KQL (CommonSecurityLog + Front Door) |

## Hypothesis

Exploit traffic hits public `welcome.cgi` while `X-DSCGI-PATH` names a privileged CGI or `/home/runtime/tmp/<md5>` race target. ICT may miss in-memory activity.

## Notes

- Prefer URL-vs-header mismatch over single-path blocklists.
- Endpoint-only MDE tables do not see HTTP headers.
- Integrity Checker clean ≠ not compromised.
