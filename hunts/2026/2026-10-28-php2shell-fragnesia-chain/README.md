# PHP2Shell chained with Fragnesia (CVE-2026-109618 / 109619 / 46300)


| | |
|---|---|
| **Hunt ID** | `2026-10-28-php2shell-fragnesia-chain` |
| **Date** | 28 October 2026 |
| **Status** | Draft, untested (Sigma check clean; conversions clean, not engine-tested) |
| **ATT&CK** | T1190, T1059.004, T1068, T1556.003, T1505.003 |
| **CVEs** | CVE-2026-109618, CVE-2026-109619, CVE-2026-46300. KEV and EPSS (dated): [`cve-context.yaml`](cve-context.yaml) |
| **Files** | [`rule.yml`](rule.yml), [`rule-pam.yml`](rule-pam.yml), [`query.kql`](query.kql), [`query-pam.kql`](query-pam.kql), [`query.spl`](query.spl), [`query-pam.spl`](query-pam.spl), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md) |

Companion to the existing [2026-10-22 PHP worker spawn hunt](../2026-10-22-php-web-server-spawning-shell/). This pack covers the **chain** Dream Research published on 26 October 2026: custom PHP2Shell remote code execution followed by the Fragnesia (CVE-2026-46300) local privilege escalation that overwrites `/etc/pam.d/su`.

## Hypothesis

If an unpatched internet-facing PHP management interface is hit with PHP2Shell and the host kernel is vulnerable to Fragnesia, defenders should see (a) a PHP worker or web server spawning a shell or interpreter, then (b) a create or change of `/etc/pam.d/su` (Dream: replaced so authentication uses `pam_permit.so`). Either signal alone is worth triage; both on the same host in a short window is high priority.

## Rules

| File | What it catches |
|------|-----------------|
| `rule.yml` | PHP worker / httpd / apache2 / nginx / frankenphp / lsphp / appweb spawning sh, bash, dash, curl, wget, nc, ncat, perl, python, python3, base64 or su |
| `rule-pam.yml` | File create/change under `/etc/pam.d/`, with `/etc/pam.d/su` called out |

`rule.yml` is `process_creation`; `rule-pam.yml` is `file_event`. Both convert under the house ECS `pipelines/ecs-process-creation.yml`, Microsoft XDR / Sentinel ASIM Kusto, and Splunk without a pipeline. See `ci-targets.txt`. Hand KQL/SPL mirror the rules for estates that prefer copy-paste over converted Sigma.

## ATT&CK

- T1190 Exploit Public-Facing Application (PHP2Shell initial access)
- T1059.004 Command and Scripting Interpreter: Unix Shell
- T1068 Exploitation for Privilege Escalation (Fragnesia)
- T1556.003 Modify Authentication Process: Pluggable Authentication Modules
- T1505.003 Server Software Component: Web Shell (Dream: parked PHP root webshells)

## Scope and limits

- Behavioural only. Not an exploit signature for PHP2Shell or Fragnesia.
- Dream did not publish a public webshell path or filename; do not invent indicators.
- Vendor and firewall OS versions in the Dream report are redacted; inventory internet-facing management interfaces and apply vendor firmware guidance when published.
- PAM rule will fire on legitimate package and config-management writes — baseline before alerting.
- Cross-check hits against the 2026-10-22 PHP spawn hunt for estates that already run it.

## Sources

See `sources.md`. Primary: Dream Research (26 Oct 2026), CISA KEV (catalogue 2026.10.28), PHP.net security releases (21 Oct 2026), Ubuntu CVE-2026-46300, NVD.
