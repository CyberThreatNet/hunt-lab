# Magento PolyShell CMS loader domains (CVE-2026-48356)


| | |
|---|---|
| **Hunt ID** | `2026-10-27-magento-cms-loader-domains` |
| **Date** | 27 October 2026 |
| **Status** | Draft, untested (Sigma check clean; Splunk conversion clean; KQL hand-written) |
| **ATT&CK** | T1071.001, T1505.003 |
| **CVEs** | CVE-2026-48356. KEV and EPSS (dated): [`cve-context.yaml`](cve-context.yaml) |
| **Files** | [`rule.yml`](rule.yml), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md), hand KQL and Splunk |

Lean hunt for DNS resolution of JavaScript loader hosts Sansec tied to
PolyShell post-exploitation of Magento / Adobe Commerce
(CVE-2026-48356).

## Hypothesis

If operators inject a CMS/static-block JS loader after a PolyShell
compromise, visitor browsers (and sometimes the store admin browser or
monitoring fetches) will resolve the stage-two payload hosts. DNS query
logs should show those names even when Magento file telemetry is thin.

## Rule

`rule.yml` — `dns_query` for three Sansec-published domains. Seed list
only; expect rename and replacement.

## ATT&CK

- T1071.001 Application Layer Protocol: Web Protocols (loader fetch)
- T1505.003 Server Software Component: Web Shell (related persistence;
  see companion file-event hunt)

## Limits

- Domains go stale quickly.
- Does not detect the localStorage stage-one cache Sansec describes.
- Companion file-event package:
  `2026-10-27-magento-polyshell-webshell` (custom_options PHP + accesson.php).
