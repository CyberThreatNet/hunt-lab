# Magento / Adobe Commerce PolyShell webshells (CVE-2026-48356)

Full write-up: [Adobe Commerce / Magento CVE-2026-48356 PolyShell exploited](https://cyber-threat.net/adobe-commerce-magento-cve-2026-48356-polyshell-exploited/) on Cyber-Threat.net.


| | |
|---|---|
| **Hunt ID** | `2026-10-27-magento-polyshell-webshell` |
| **Date** | 27 October 2026 |
| **Status** | Draft, untested (Sigma check clean; conversions clean, not engine-tested) |
| **ATT&CK** | T1190, T1505.003 |
| **CVEs** | CVE-2026-48356. KEV and EPSS (dated): [`cve-context.yaml`](cve-context.yaml) |
| **Files** | [`rule.yml`](rule.yml), [`rule-persistence.yml`](rule-persistence.yml), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md), [`EVIDENCE.md`](EVIDENCE.md) |

Hunt for post-exploitation file drops from the guest-cart custom-options
upload flaw in Magento Open Source and Adobe Commerce, tracked as
CVE-2026-48356 and listed in CISA KEV. Public research (Sansec) nicknames
the chain **PolyShell**.

## Hypothesis

If an unpatched Magento or Adobe Commerce store is hit via the guest-cart
REST custom-options upload path, operators land a polyglot (image + PHP)
under `pub/media/custom_options/quote/` and often spray a secondary
`accesson.php` backdoor into `assets/images/` folders across the Magento
tree. File-create telemetry on those paths should surface the drop even
when the HTTP exploit itself is not logged.

## Rules

| File | What it catches |
|------|-----------------|
| `rule.yml` | PHP / PHTML / PHAR created under `*/media/custom_options/` |
| `rule-persistence.yml` | Any file whose path ends with `accesson.php` |

Both are `file_event` rules. They convert under the house ECS
`pipelines/ecs-process-creation.yml` (which also maps `TargetFilename` →
`file.path`), Microsoft XDR / Sentinel ASIM Kusto, and Splunk without a
pipeline. See `ci-targets.txt`.

## ATT&CK

- T1190 Exploit Public-Facing Application (initial access via the upload)
- T1505.003 Server Software Component: Web Shell (persistence)

## Scope and limits

- Path and filename based. Not an exploit signature for CVE-2026-48356.
- Needs file-create coverage of the Magento document root (Sysmon 11,
  Elastic Defend, Defender for Endpoint DeviceFileEvents, and so on).
- `accesson.php` is the name Sansec published; rename variants will miss.
- No public PoC is linked here; do not run untrusted samples against
  production.

## Sources

See `sources.md`. Primary: Adobe APSB26-73, CISA KEV, NVD, Sansec research.
