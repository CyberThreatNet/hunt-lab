# CWPdoor: trojanised Control Web Panel cwpsrv

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-06-cwpdoor-cwpsrv | 2026-11-06 | Experimental | Linux CWP hosts; network/DNS; EDR file scan; Splunk; Microsoft Sentinel / Defender | T1554, T1071, T1036, T1070 | None assigned in XLab write-up | cwpdoor.yar, rule-cwpdoor-c2.yml, query.kql, host-checks.sh, ci-targets.txt, sources.md |

## Hypothesis

Operators replace `/usr/local/cwpsrv/bin/cwpsrv` with a recompiled backdoor that listens on the Unix socket `ngx_http_integrity_helper` and accepts RSA-signed HTTP headers (`X-Ngx-Integrity-*`) for encrypted command execution. The updater and binaries were served from `136.0.141.71`.

## Threat context

Primary source: QiAnXin XLab, 5 November 2026. Installer first seen 29 June 2026. VT archive with Ebury on 30 September 2026. Targets cwpsrv 1.15.10 and 1.24.0. More than 340,000 internet-facing CWP instances observed by Hunter in the prior month (exposure, not confirmed infections). Initial access bug not disclosed.

## Hunts

1. **Integrity socket and binary strings** (`host-checks.sh`, `cwpdoor.yar`).
2. **Network / DNS to C2** (`rule-cwpdoor-c2.yml`, `query.kql` Q1).
3. **File hash matches** (`host-checks.sh`, `cwpdoor.yar` MD5 conditions where the engine supports hash).

## Data sources

| Source | Used by |
|---|---|
| Host `ss`, `ps`, `strings`, `md5sum` | host-checks.sh |
| YARA scan of cwpsrv binary | cwpdoor.yar |
| Firewall / proxy / DNS / EDR network | rule-cwpdoor-c2.yml, query.kql |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1554 Compromise Host Software Binary | Trojanised cwpsrv |
| T1071 Application Layer Protocol | HTTP integrity headers as C2 |
| T1036 Masquerading | Same path and restored timestamps |
| T1070 Indicator Removal | Log suppression and history wipe |

## Notes

- Defang the IP in public prose as `136.0.141[.]71`. Queries use the dotted form for matching.
- Root is required to install the backdoor; absence of a public initial-access CVE does not mean hosts are safe.
- Ebury co-occurrence is unconfirmed as the same actor.
