# Hunt of the week #1: possible PHP RCE follow-on activity

> **Draft for review: untested, not published.** This is a behavioural starting point that needs tuning, not an exploit signature. Neither query has been run against live or lab data yet.

| | |
|---|---|
| **Hunt ID** | `2026-10-22-php-web-server-spawning-shell` |
| **Date** | 22 October 2026 |
| **Status** | Experimental (draft, untested) |
| **Platforms** | Linux web servers only. KQL for Microsoft Defender XDR advanced hunting (Defender for Endpoint on Linux). Sigma for Linux `process_creation`. SPL for the Splunk CIM Endpoint data model. |
| **ATT&CK** | T1190, T1059.004, T1105, T1505.003 |
| **CVEs** | CVE-2026-109618, CVE-2026-109619 |
| **Files** | [`query.kql`](query.kql) (MIT), [`query.spl`](query.spl) (MIT), [`rule.yml`](rule.yml) (Sigma, DRL 1.1) |

## Hypothesis

If an attacker gains code execution in a PHP worker, the PHP or web server process will start a shell, a download tool (`curl`, `wget`) or a scripting interpreter. It rarely does that in normal operation.

## Threat context

- On 21 October 2026 the PHP project released PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. The releases fix **CVE-2026-109618** and **CVE-2026-109619**, which the project says can allow unauthenticated remote code execution.
- mod_php carries the highest risk. PHP-FPM, php-cgi, FrankenPHP and LiteSpeed are also affected.
- PHP 8.1 and older get no upstream fix. The advisory lists temporary mitigations.
  - Source: [php.net security advisory](https://www.php.net/archive/2026.php)
- The NCSC asks UK organisations to:
  - find every PHP installation, starting with anything internet-facing;
  - update it, or apply the mitigations, or take it offline;
  - check for compromise.
  - Source: [NCSC: Critical security issue affecting PHP](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)
- CERT-EU has published the same advice: [CERT-EU advisory 2026-018](https://www.cert.europa.eu/publications/security-advisories/2026-018/).

**Important caveat:** php.net and the NCSC describe the flaws as unauthenticated RCE, but neither says what attackers do afterwards. This hunt is built on the **generic web-shell and RCE follow-on pattern**. It is **not** behaviour reported for these CVEs.

**No IOCs** are given, because none have been published in the sources above. Do not add indicators unless a cited source publishes them.

## Data sources and tables

| Query | Data source | Requirement |
|---|---|---|
| `query.kql` | `DeviceProcessEvents` ([schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)) | Microsoft Defender for Endpoint on the Linux web servers. In Microsoft Sentinel, the Defender XDR connector must stream `DeviceProcessEvents`. |
| `rule.yml` | Sigma `product: linux`, `category: process_creation` | auditd or Sysmon for Linux (or an EDR), mapped by a pySigma pipeline |
| `query.spl` | CIM `Endpoint.Processes` | An add-on that populates the Endpoint data model from Linux process telemetry |

Columns used in KQL:
- `Timestamp`, `DeviceName`
- `InitiatingProcessFileName`, `InitiatingProcessCommandLine`
- `FileName`, `ProcessCommandLine`
- `AccountName`

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1190 | Exploit Public-Facing Application |
| T1059.004 | Command and Scripting Interpreter: Unix Shell |
| T1105 | Ingress Tool Transfer |
| T1505.003 | Server Software Component: Web Shell |

## How the logic works

**Parent processes:**
- A PHP process whose file name matches `^php(-fpm|-cgi)?[0-9.]*$`. Examples are `php`, `php-fpm`, `php-fpm8.3`, `php-cgi` and `php8.2`.
- Or a PHP-capable web server: `httpd`, `apache2`, `frankenphp` or `lsphp`.
- With mod_php, PHP runs inside Apache, so the parent is the Apache process.

**Child processes:** `sh`, `bash`, `dash`, `curl`, `wget`, `nc`, `ncat`, `perl`, `python3` and `base64`.

The KQL summarises by device, parent, parent command line and child, so rare combinations stand out. Rows are ordered by first seen.

## Tuning and false positives

**Check names first.** Process names vary by distribution and set-up (for example `php-fpm8.3`, or `apache2` versus `httpd`). Before relying on the hunt, check what `InitiatingProcessFileName` shows in your estate.

**Expect noise from:**
- PHP applications that legitimately shell out with `exec`, `system` or `proc_open`. Examples are image, PDF or mail tools. PHP `mail()` typically runs `sh -c /usr/sbin/sendmail -t -i`.
- Cron, deployment and Composer jobs run with the PHP CLI. The regex also matches the `php` CLI binary.
- Monitoring or health-check scripts run by the web server user.

**Exclude known-good activity** by device, account or command line rather than by widening the lists. The KQL and SPL files include commented exclusion examples.

**Coverage gaps:**
- Windows (IIS with php-cgi) and containers are not covered. A Windows variant is a follow-up.
- The hunt only sees hosts with process telemetry.

**Elastic users:** the Sigma `|re` pattern relies on a `$` anchor. Elastic's EQL and ES|QL regex matching is evaluated against the whole field value, so check the converted query. You may need to rewrite the pattern as `.*/php(-fpm|-cgi)?[0-9.]*` for Elastic back ends.

## Validation notes

**Done (22 Oct 2026):**
- `rule.yml` parses as YAML.
- It passes `sigma check` (sigma-cli 3.1.0, pySigma 1.5.1) with no errors, no condition errors and no issues. The filename validators were excluded, because this repository uses one `rule.yml` per hunt folder.
- It converts without errors to:
  - Defender XDR KQL (`-t kusto -p microsoft_xdr`), producing a `DeviceProcessEvents` query;
  - Splunk (`-t splunk -p splunk_cim` and `--without-pipeline`);
  - Elastic ES|QL and EQL (`-p pipelines/ecs-process-creation.yml`).
- The hand-written `query.kql` uses only documented `DeviceProcessEvents` columns.

**Not done:**
- Neither query has been run against live or lab data.
- The KQL and SPL have not been parsed by a Kusto or Splunk engine.

**Plan to test:**
1. Use an isolated lab server only, never a system you do not own. Onboard it to a Defender for Endpoint trial (or Sysmon for Linux or auditd).
2. Create a test PHP page that runs a harmless command through `exec()`, which starts `/bin/sh`. It should produce one hit. Delete the page straight afterwards.
3. Compare the rule against a week of normal production telemetry to measure noise. Record the volume and exclusions here.

## Follow-up idea: Plex2Shell variant

BleepingComputer [reports](https://www.bleepingcomputer.com/news/security/cisa-hackers-chain-plex-flaws-in-plex2shell-attacks-to-breach-servers/) that the Plex2Shell chain (CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656) plants malicious shared libraries that Plex loads. It was used to drop a cryptominer.

CISA added the four flaws to KEV on [20 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/20/cisa-adds-six-known-exploited-vulnerabilities-catalog).

A later pack could look for:
- new `.so` files written in Plex's directories;
- unexpected child processes of Plex Media Server.

## Credits and licence

- Original rule by Cyber-Threat.net Hunt Lab. It is related to SigmaHQ's [Linux Webshell Indicators](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml) rule, which is credited in the rule's references.
- `rule.yml` is licensed under the [Detection Rule License (DRL) 1.1](../../../LICENSE-DRL).
- `query.kql`, `query.spl` and this README are licensed under the [MIT Licence](../../../LICENSE).

Provided as-is, without warranty. Test and tune before production use.
