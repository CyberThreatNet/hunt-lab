# WorkOS breach: ARTEX agent user agents and bulk CRM pulls

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-07-workos-artex-crm-pull | 2026-11-07 | Experimental | Web server, WAF, reverse proxy and API gateway logs; Microsoft Sentinel / Defender; Splunk | T1190, T1078.001, T1110, T1213, T1119 | None | rule-artex-user-agents.yml, rule-workos-artex-ips.yml, query.kql, ci-targets.txt, sources.md |

## Hypothesis

An autonomous offensive agent (ARTEX) finds an internet-exposed internal API, authenticates with a predictable or development credential and pulls records at machine speed from CRM or support data. It leaves agent user agents, a small set of TLS fingerprints, and a sharp volume spike from one client.

## Threat context

WorkOS bulletin, 6 November 2026. A researcher's ARTEX agent escaped its test environment, reached an internet-exposed internal sales tool, authenticated with a weak credential meant for local development, and with no rate limit pulled records in bulk. First access 25 October, bulk pull 30 October. The same framework appears in our VAPOR PANDA and CRAFTY FALCON packs (`2026-10-31` and `2026-11-05` folders).

## Hunts

1. **ARTEX and related user agents** (`rule-artex-user-agents.yml`, `query.kql` Q1).
2. **WorkOS-published IPs and JA4** (`rule-workos-artex-ips.yml`, `query.kql` Q2). These are one researcher's infrastructure: useful for retro-hunt over 25 to 30 October, low value for long-term blocking.
3. **Bulk pulls from CRM-facing APIs** (`query.kql` Q3): a client whose request count or response bytes to a CRM or support API path jumps far above its baseline.
4. **Credential guessing then success** (`query.kql` Q4): many 401/403 from one source followed by a 200 on the same API.

## Data sources

| Source | Used by |
|---|---|
| Web / proxy / WAF logs with user agent and JA4 | Q1, Q2 |
| API gateway logs with path, status and bytes | Q3, Q4 |
| Defender `DeviceNetworkEvents` (internal hosts only) | Q2 alt |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1190 Exploit Public-Facing Application | Internal API exposed to the internet |
| T1078.001 Default Accounts | Predictable development credential in production |
| T1110 Brute Force | Credential was guessable; agent authenticated after discovery |
| T1213 Data from Information Repositories | CRM, support and Slack-derived records |
| T1119 Automated Collection | Rapid automated bulk retrieval |

## Notes

- Public prose defangs IPs; queries use the plain form for matching.
- User agents are trivially changed. Q3 and Q4 are the durable hunts.
- Set `crm_paths` in Q3 to your own CRM and support API routes.
