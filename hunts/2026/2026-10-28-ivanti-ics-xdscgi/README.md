# Ivanti Connect Secure X-DSCGI-PATH (CVE-2026-104935 chain)

Full write-up: [Hunt: Ivanti Connect Secure X-DSCGI-PATH mismatch](https://cyber-threat.net/hunt-ivanti-connect-secure-x-dscgi-path/) on Cyber-Threat.net.

> **Draft for review: untested.** Behavioural starting points from Volexity and CISA. Not an exploit signature.

| | |
|---|---|
| **Hunt ID** | `2026-10-28-ivanti-ics-xdscgi` |
| **Date** | 28 October 2026 (extended 2 November 2026) |
| **Status** | experimental (untested) |
| **Platforms** | HTTP proxy / WAF with custom headers; Sentinel Front Door diagnostics |
| **ATT&CK** | T1190, T1059, T1003, T1040, T1070, T1558.003 |
| **CVEs** | CVE-2026-104935, CVE-2026-118527 (network), CVE-2026-111357 (context only) — [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `rule.yml` (proxy), hand KQL (CommonSecurityLog + Front Door) |

## Hypothesis

Exploit traffic hits public `welcome.cgi` while `X-DSCGI-PATH` names a privileged CGI or `/home/runtime/tmp/<md5>` race target. ICT may miss in-memory activity.

## Coverage (2 Nov 2026)

| CVE | Component / path | Covered by this hunt? | Why |
|---|---|---|---|
| CVE-2026-104935 | Auth bypass: public `welcome.cgi` URL vs attacker-controlled `X-DSCGI-PATH` (observed target `wu.cgi`) | Yes | Same artefacts the Sigma/KQL/Splunk queries flag. |
| CVE-2026-118527 | Predictable upload path: `wu.cgi` writes to `/home/runtime/tmp/<MD5(filename)>`; race via `X-DSCGI-PATH` | Yes (network race) | Queries already match `wu.cgi` and `/home/runtime/tmp/`. Alone it needs an authenticated session; in the wild chain, 104935 supplies that access. |
| CVE-2026-111357 | Local privilege escalation: `dsinvoked` trusts attacker-modified DSCache / in-memory `libdsplibs.so` | No (partial pack) | Host/memory forensics, not HTTP headers. No new proxy/WAF rule added: primary sources do not publish reliable network observables for this step. |

Primary sources used for the coverage decision: CISA KEV entries and 13/30 Oct alert, Volexity chain write-up (updated for CVE-2026-111357), Ivanti advisory link via KEV notes, CCB Belgium and NHS England summaries.

## Notes

- Prefer URL-vs-header mismatch over single-path blocklists.
- Endpoint-only MDE tables do not see HTTP headers.
- Integrity Checker clean ≠ not compromised.
- CVE-2026-111357 remains context-only until a host-side detection with primary-source artefacts is published.
