# PeopleSoft PSIGW→PSEMHUB (CVE-2026-35273)

> **Draft for review: untested.** Behavioural starting points from Oracle, Mandiant, ZDI and Trend public research. Not exploit signatures.

| | |
|---|---|
| **Hunt ID** | `2026-10-28-peoplesoft-psigw-psemhub` |
| **Date** | 28 October 2026 |
| **Status** | Draft: untested |
| **Platforms** | HTTP proxy / web access logs; file-create on PeopleSoft hosts |
| **ATT&CK** | T1190, T1210, T1505.003 |
| **CVEs** | CVE-2026-35273 — [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `rule.yml` (proxy), `rule-envmetadata.yml` (file_event), conversions |

## Hypothesis

Exploit traffic hits `/PSIGW/HttpListeningConnector` while naming PSEMHUB or loopback, or uses `/%50SEMHUB/` to bypass literal-path WAF rules. Successful follow-on writes land under `envmetadata`.

## Notes

- Field names in `rule.yml` (`cs-uri-stem` / `cs-uri-query`) follow common proxy schemas; retarget per estate.
- No public exploit payload is reproduced here.
- Mandiant also flags unexpected MeshCentral agents — out of scope for these two rules; add separately if useful.
