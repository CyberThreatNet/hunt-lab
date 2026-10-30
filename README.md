# Cyber-Threat.net Hunt Lab

[![Validate Sigma rules](https://github.com/CyberThreatNet/hunt-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/CyberThreatNet/hunt-lab/actions/workflows/validate.yml)
[![Sigma rules: DRL 1.1](https://img.shields.io/badge/Sigma%20rules-DRL%201.1-blue)](LICENSE-DRL)
[![Queries and docs: MIT](https://img.shields.io/badge/queries%20%26%20docs-MIT-green)](LICENSE)
[![MITRE ATT&CK mapped](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](https://attack.mitre.org/)
[![Hunt Lab on Cyber-Threat.net](https://img.shields.io/badge/Hunt%20Lab-cyber--threat.net-0b5394)](https://cyber-threat.net/category/hunt-lab/)
[![Hunt Lab RSS feed](https://img.shields.io/badge/RSS-Hunt%20Lab-orange)](https://cyber-threat.net/category/hunt-lab/feed/)

Free threat-hunting queries and detection rules from **Hunt Lab** at [Cyber-Threat.net](https://cyber-threat.net).

Each week's threats and CVEs become copy-ready hunts for threat hunters, SOC analysts and detection engineers. Hunts are written in **KQL** (Microsoft Sentinel and Defender XDR), **Sigma** and **Splunk SPL**, and mapped to MITRE ATT&CK. Each folder matches a "Hunt of the week" or CVE query pack entry on the site.

Read the write-ups behind each hunt on the [Hunt Lab pages at Cyber-Threat.net](https://cyber-threat.net/category/hunt-lab/), and follow new hunts with the [Hunt Lab RSS feed](https://cyber-threat.net/category/hunt-lab/feed/). Everything here is free to use under the licences below.

Repository: <https://github.com/CyberThreatNet/hunt-lab>

> **Defensive content only.** No exploit code, no proofs of concept and no step-by-step exploitation. Indicators appear only where a cited source publishes them. They are never invented. Behavioural hunts are labelled as such.

## Latest hunts

| Date | Hunt | CVE | ATT&CK | Write-up | Folder |
|---|---|---|---|---|---|
| 2026-10-30 | GitLab CI regex unauthenticated RCE (CVE-2026-97229) | CVE-2026-97229 | T1190, T1059 | — | [`2026-10-30-gitlab-ci-regex-rce`](hunts/2026/2026-10-30-gitlab-ci-regex-rce/) |
| 2026-10-29 | Cisco SD-WAN KeyDrift / UAT-11473 (CVE-2026-20127) | CVE-2026-20127 | T1190, T1055, T1552, T1543 | — | [`2026-10-29-cisco-sdwan-keydrift`](hunts/2026/2026-10-29-cisco-sdwan-keydrift/) |
| 2026-10-29 | ESXi audit-log gaps and unpatched inventory (CVE-2026-41709) | CVE-2026-41709 | T1562.003, T1070, T1078 | [Article](https://cyber-threat.net/esxi-cve-2026-41709-kev-logging-gap-zero-day/) | [`2026-10-29-esxi-audit-log-gaps`](hunts/2026/2026-10-29-esxi-audit-log-gaps/) |
| 2026-10-28 | PHP2Shell chained with Fragnesia (CVE-2026-109618 / 109619 / 46300) | CVE-2026-109618, CVE-2026-109619, CVE-2026-46300 | T1190, T1059.004, T1068, T1556.003, T1505.003 | [Article](https://cyber-threat.net/php2shell-fragnesia-dream-25-rooted-servers/) | [`2026-10-28-php2shell-fragnesia-chain`](hunts/2026/2026-10-28-php2shell-fragnesia-chain/) |
| 2026-10-28 | PeopleSoft PSIGW→PSEMHUB (CVE-2026-35273) | CVE-2026-35273 | T1190, T1210, T1505.003 | [Article](https://cyber-threat.net/peoplesoft-cve-2026-35273-ssrf-rce-mass-exploited/) | [`2026-10-28-peoplesoft-psigw-psemhub`](hunts/2026/2026-10-28-peoplesoft-psigw-psemhub/) |
| 2026-10-28 | Ivanti Connect Secure X-DSCGI-PATH (CVE-2026-104935) | CVE-2026-104935 | T1190 | [Article](https://cyber-threat.net/hunt-ivanti-connect-secure-x-dscgi-path/) | [`2026-10-28-ivanti-ics-xdscgi`](hunts/2026/2026-10-28-ivanti-ics-xdscgi/) |
| 2026-10-28 | BeyondTrust SAWFLY / BARECLAW (CVE-2026-102764) | CVE-2026-102764 | T1190, T1505.003, T1003, T1548.001, T1090, T1070.004 | [Article](https://cyber-threat.net/hunt-beyondtrust-armory-castle-sawfly-bareclaw/) | [`2026-10-28-beyondtrust-sawfly-bareclaw`](hunts/2026/2026-10-28-beyondtrust-sawfly-bareclaw/) |
| 2026-10-27 | testmetest npm worm: `.github/init.js` loaders started by IDE and A… | — | T1195.002, T1059.007, T1543.002, T1543.001, T1027, T1485 | [Article](https://cyber-threat.net/testmetest-npm-worm-github-init-js-hooks/) | [`2026-10-27-testmetest-ide-hook-loader`](hunts/2026/2026-10-27-testmetest-ide-hook-loader/) |
| 2026-10-27 | Magento / Adobe Commerce PolyShell webshells (CVE-2026-48356) | CVE-2026-48356 | T1190, T1505.003 | [Article](https://cyber-threat.net/adobe-commerce-magento-cve-2026-48356-polyshell-exploited/) | [`2026-10-27-magento-polyshell-webshell`](hunts/2026/2026-10-27-magento-polyshell-webshell/) |
| 2026-10-27 | Magento PolyShell CMS loader domains (CVE-2026-48356) | CVE-2026-48356 | T1071.001, T1505.003 | [Article](https://cyber-threat.net/hunt-magento-polyshell-cms-loader-domains/) | [`2026-10-27-magento-cms-loader-domains`](hunts/2026/2026-10-27-magento-cms-loader-domains/) |
| 2026-10-26 | Shell spawned by a Node.js process (Node2Shell, CVE-2026-111497) | CVE-2026-111497 | T1190, T1059, T1499.004 | [Article](https://cyber-threat.net/node2shell-brotli-cve-2026-111497/) | [`2026-10-26-node2shell-brotli`](hunts/2026/2026-10-26-node2shell-brotli/) |
| 2026-10-24 | Arista EOS CVE-2026-7473 | CVE-2026-7473 | T1599, T1572 | [Article](https://cyber-threat.net/arista-eos-cve-2026-7473-no-fix-coming/) | [`2026-10-24-arista-cve-2026-7473`](hunts/2026/2026-10-24-arista-cve-2026-7473/) |
| 2026-10-22 | Shell or download tool spawned by a PHP worker or web server (Linux) | CVE-2026-109618, CVE-2026-109619 | T1190, T1059.004, T1105, T1505.003 | [Article](https://cyber-threat.net/php2shell-patch-php-now-then-go-hunting/) | [`2026-10-22-php-web-server-spawning-shell`](hunts/2026/2026-10-22-php-web-server-spawning-shell/) |

**[★ Star this repo](https://github.com/CyberThreatNet/hunt-lab)** · [Follow the site](https://cyber-threat.net/) · [RSS](https://cyber-threat.net/feed/) · [Hunt Lab category](https://cyber-threat.net/category/hunt-lab/) · [Hunt Lab RSS](https://cyber-threat.net/category/hunt-lab/feed/)

## Repository layout

```text
hunt-lab/
├── hunts/
│   └── <YYYY>/
│       └── <YYYY-MM-DD>-<slug>/
│           ├── README.md    # hypothesis, context, data sources, ATT&CK, tuning, validation (MIT)
│           ├── cve-context.yaml  # KEV and EPSS for the hunt's CVEs (generated; CVE hunts only)
│           ├── query.kql    # Defender XDR advanced hunting / Microsoft Sentinel (MIT)
│           ├── query.spl    # Splunk (MIT)
│           └── rule.yml     # Sigma rule (DRL 1.1)
├── templates/
│   └── hunt-template/       # copy this to start a new hunt
├── pipelines/
│   └── ecs-process-creation.yml   # pySigma ECS field mapping for Elastic (process_creation and file_event)
├── scripts/
│   ├── refresh_kev_epss.py  # refreshes and checks KEV and EPSS context
│   └── tests/               # offline safety tests for the script (run by CI)
├── .github/                 # issue forms, PR template, validation workflow
├── LICENSE                  # MIT (queries, docs, tooling)
├── LICENSE-DRL              # Detection Rule License 1.1 (Sigma rules)
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
└── CHANGELOG.md
```

## Hunts

| Date | Hunt | ATT&CK | Status |
|---|---|---|---|
| 2026-10-30 | [GitLab CI regex unauthenticated RCE (CVE-2026-97229)](hunts/2026/2026-10-30-gitlab-ci-regex-rce/) | T1190, T1059 | Experimental, draft, untested |
| 2026-10-22 | [Shell or download tool spawned by a PHP worker or web server (Linux)](hunts/2026/2026-10-22-php-web-server-spawning-shell/) (CVE-2026-109618, CVE-2026-109619) | T1190, T1059.004, T1105, T1505.003 | Draft, untested |
| 2026-10-24 | [Arista EOS CVE-2026-7473](hunts/2026/2026-10-24-arista-cve-2026-7473/) | T1599, T1572 | Draft, untested |
| 2026-10-25 | [DCSync: directory replication rights used by a non-machine account](hunts/2026/2026-10-25-dcsync-replication-by-non-dc-account/) | T1003.006 | Test (public datasets) |
| 2026-10-25 | [LSASS dumping with built-in Windows tools: comsvcs MiniDump and RdrLeakDiag](hunts/2026/2026-10-25-lsass-dump-via-lolbins/) | T1003.001, T1218.011 | Test (public datasets) |
| 2026-10-26 | [Shell spawned by a Node.js process (Node2Shell, CVE-2026-111497)](hunts/2026/2026-10-26-node2shell-brotli/) | T1190, T1059, T1499.004 | Test (public datasets) |
| 2026-10-27 | [testmetest npm worm: `.github/init.js` loaders started by IDE and AI-assistant hooks, native-addon drops and persistence](hunts/2026/2026-10-27-testmetest-ide-hook-loader/) | T1195.002, T1059.007, T1543.002, T1543.001, T1027, T1485 | Test (synthetic data; script tested on Linux) |
| 2026-10-27 | [Magento / Adobe Commerce PolyShell webshells (CVE-2026-48356)](hunts/2026/2026-10-27-magento-polyshell-webshell/) | T1190, T1505.003 | Draft, untested |
| 2026-10-27 | [Magento PolyShell CMS loader domains (CVE-2026-48356)](hunts/2026/2026-10-27-magento-cms-loader-domains/) | T1071.001, T1505.003 | Draft, untested |
| 2026-10-28 | [BeyondTrust SAWFLY / BARECLAW (CVE-2026-102764)](hunts/2026/2026-10-28-beyondtrust-sawfly-bareclaw/) | T1190, T1505.003, T1003, T1548.001, T1090, T1070.004 | Draft, untested |
| 2026-10-28 | [eMudhra trust-store follow-up](hunts/2026/2026-10-28-emudhra-trust-store/) | T1553.004 | Draft, untested |
| 2026-10-28 | [Ivanti Connect Secure X-DSCGI-PATH (CVE-2026-104935)](hunts/2026/2026-10-28-ivanti-ics-xdscgi/) | T1190 | Draft, untested |
| 2026-10-28 | [PeopleSoft PSIGW→PSEMHUB (CVE-2026-35273)](hunts/2026/2026-10-28-peoplesoft-psigw-psemhub/) | T1190, T1210, T1505.003 | Draft, untested |
| 2026-10-28 | [MLflow scorer invoke (CVE-2026-116692)](hunts/2026/2026-10-28-mlflow-scorer-invoke/) | T1190 | Draft, untested |
| 2026-10-28 | [PHP2Shell chained with Fragnesia (CVE-2026-109618 / 109619 / 46300)](hunts/2026/2026-10-28-php2shell-fragnesia-chain/) | T1190, T1059.004, T1068, T1556.003, T1505.003 | Draft, untested |
| 2026-10-29 | [ESXi audit-log gaps and unpatched inventory (CVE-2026-41709)](hunts/2026/2026-10-29-esxi-audit-log-gaps/) | T1562.003, T1070, T1078 | Experimental, draft, untested |
| 2026-10-29 | [Cisco SD-WAN KeyDrift / UAT-11473 (CVE-2026-20127)](hunts/2026/2026-10-29-cisco-sdwan-keydrift/) | T1190, T1055, T1552, T1543 | Experimental, draft, untested |

## Exploitation context: CISA KEV and FIRST EPSS

Every hunt that covers a CVE has a `cve-context.yaml` file giving two public, dated signals for each CVE. Hunts with no CVE (for example the DCSync and LSASS hunts) have no file and show as "n/a" below.

- **CISA KEV** (Known Exploited Vulnerabilities catalogue) is a **yes or no list**, not a score. A CVE is listed when CISA has reliable evidence that it is being exploited in the wild. For listed CVEs we record the date it was added, the remediation due date CISA sets for US federal agencies, and CISA's `knownRansomwareCampaignUse` value (`Known` or `Unknown`). "Not in KEV" does not mean "not exploited": it means CISA has not listed it.
- **FIRST EPSS** (Exploit Prediction Scoring System) is a **probability from 0 to 1** that the CVE will see exploitation activity in the next 30 days, with a percentile against every scored CVE. It is recalculated daily, so always read it with its date. Newly published CVEs may not be scored yet; the file then records `null` with a note rather than a guess.
- **EPSS is not a severity score.** Severity (how bad it would be if exploited) is what CVSS measures. EPSS only estimates how likely exploitation activity is.

**Why KEV and EPSS can disagree.** KEV is evidence: CISA has seen exploitation. EPSS is a model: a prediction from signals about the CVE. The two often line up, but not always, and the table below has both kinds of difference:

- Arista CVE-2026-7473 is **in KEV** but has a **low EPSS** score. Exploitation has been confirmed, even though the model rates further activity as unlikely.
- The PHP CVEs (CVE-2026-109618 and CVE-2026-109619) and Node2Shell CVE-2026-111497 show the gap can close. Both had **high EPSS** scores before CISA listed them: the PHP CVEs on [26 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog), and Node2Shell on [27 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/27/cisa-adds-two-known-exploited-vulnerabilities-catalog). A high EPSS score can arrive days before KEV evidence does.

Neither replaces your own exposure and asset context. Use them to help prioritise.

| Field | Meaning |
|---|---|
| `cve` | CVE ID |
| `kev_listed` | `true` if the CVE is in the CISA KEV catalogue, otherwise `false` |
| `kev_date_added`, `kev_due_date` | KEV `dateAdded` and `dueDate` (`YYYY-MM-DD`), `null` if not listed |
| `kev_ransomware` | KEV `knownRansomwareCampaignUse`: `Known` or `Unknown`, `null` if not listed |
| `kev_catalog_version` | KEV `catalogVersion` that was read |
| `kev_checked`, `epss_checked` | Date the feed was read (Europe/London) |
| `epss`, `epss_percentile` | EPSS score and percentile, both from 0 to 1 as FIRST publishes them; `null` if not yet scored. The table below shows the percentile from 0 to 100 (0.98463 in the file is 98.46 in the table) |
| `epss_date` | Date of the EPSS model run that produced the score |
| `epss_note` | Why `epss` is `null`; otherwise `null` |

The files and the table below are generated by [`scripts/refresh_kev_epss.py`](scripts/refresh_kev_epss.py) (Python standard library only). It reads the [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) (see also the [KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) and the [FIRST EPSS API](https://api.first.org/epss/) ([about EPSS](https://www.first.org/epss/)). Values are refreshed by hand, and the Checked column gives the date of each one. CI runs the script with `--check`. That works offline and fails if a file is malformed, if a CVE named in a hunt's `rule.yml` tags or README "CVEs" row has no entry, or if this table is out of date.

```bash
python3 scripts/refresh_kev_epss.py          # refresh from the live feeds
python3 scripts/refresh_kev_epss.py --check  # validate only (what CI runs)
```

If FIRST returns no EPSS row for a CVE that already has a score, the script keeps the previous score and its dates and prints a warning, rather than replacing it with `null`. If FIRST returns no row for every CVE, the script treats that as an outage of the EPSS API rather than a gap, and writes nothing.

| Exit code | Meaning |
|---|---|
| 0 | Success: the refresh was written, or `--check` passed |
| 1 | `--check` found a problem, or a refresh failed (network, feed format, local file); nothing was written |
| 2 | Bad command-line arguments |
| 3 | EPSS outage: FIRST returned no score for any CVE; nothing was written. Try again later |

<!-- kev-epss:start (generated by scripts/refresh_kev_epss.py; do not edit by hand) -->

| Hunt | CVE | In KEV | KEV added | KEV due | Ransomware use (KEV) | EPSS (0-1) | EPSS percentile (0-100) | Checked |
|---|---|---|---|---|---|---|---|---|
| [2026-10-22-php-web-server-spawning-shell](hunts/2026/2026-10-22-php-web-server-spawning-shell/) | CVE-2026-109618 | Yes | 2026-10-26 | 2026-10-29 | Unknown | 0.99999 | 100.00 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-22-php-web-server-spawning-shell](hunts/2026/2026-10-22-php-web-server-spawning-shell/) | CVE-2026-109619 | Yes | 2026-10-26 | 2026-10-29 | Unknown | 0.99999 | 100.00 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-24-arista-cve-2026-7473](hunts/2026/2026-10-24-arista-cve-2026-7473/) | CVE-2026-7473 | Yes | 2026-06-09 | 2026-06-23 | Unknown | 0.01108 | 65.79 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-25-dcsync-replication-by-non-dc-account](hunts/2026/2026-10-25-dcsync-replication-by-non-dc-account/) | n/a (no CVE) | n/a | | | | | | |
| [2026-10-25-lsass-dump-via-lolbins](hunts/2026/2026-10-25-lsass-dump-via-lolbins/) | n/a (no CVE) | n/a | | | | | | |
| [2026-10-26-node2shell-brotli](hunts/2026/2026-10-26-node2shell-brotli/) | CVE-2026-111497 | Yes | 2026-10-27 | 2026-11-10 | Unknown | 0.82641 | 99.67 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-27-magento-cms-loader-domains](hunts/2026/2026-10-27-magento-cms-loader-domains/) | CVE-2026-48356 | Yes | 2026-10-27 | 2026-11-10 | Unknown | 0.44579 | 98.77 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-27-magento-polyshell-webshell](hunts/2026/2026-10-27-magento-polyshell-webshell/) | CVE-2026-48356 | Yes | 2026-10-27 | 2026-11-10 | Unknown | 0.44579 | 98.77 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-27-testmetest-ide-hook-loader](hunts/2026/2026-10-27-testmetest-ide-hook-loader/) | n/a (no CVE) | n/a | | | | | | |
| [2026-10-28-beyondtrust-sawfly-bareclaw](hunts/2026/2026-10-28-beyondtrust-sawfly-bareclaw/) | CVE-2026-102764 | Yes | 2026-10-16 | 2026-10-19 | Unknown | 0.18950 | 97.29 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-emudhra-trust-store](hunts/2026/2026-10-28-emudhra-trust-store/) | CVE-2026-108014 | No | – | – | – | 0.00128 | 2.46 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-emudhra-trust-store](hunts/2026/2026-10-28-emudhra-trust-store/) | CVE-2026-108015 | No | – | – | – | 0.00128 | 2.46 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-ivanti-ics-xdscgi](hunts/2026/2026-10-28-ivanti-ics-xdscgi/) | CVE-2026-104935 | Yes | 2026-10-13 | 2026-10-16 | Unknown | 0.86766 | 99.74 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-mlflow-scorer-invoke](hunts/2026/2026-10-28-mlflow-scorer-invoke/) | CVE-2026-116692 | No | – | – | – | 0.00704 | 53.23 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-peoplesoft-psigw-psemhub](hunts/2026/2026-10-28-peoplesoft-psigw-psemhub/) | CVE-2026-35273 | Yes | 2026-06-12 | 2026-06-15 | Known | 0.96678 | 99.88 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-php2shell-fragnesia-chain](hunts/2026/2026-10-28-php2shell-fragnesia-chain/) | CVE-2026-46300 | Yes | 2026-10-28 | 2026-10-31 | Unknown | 0.15719 | 96.85 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-php2shell-fragnesia-chain](hunts/2026/2026-10-28-php2shell-fragnesia-chain/) | CVE-2026-109618 | Yes | 2026-10-26 | 2026-10-29 | Unknown | 0.99999 | 100.00 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-28-php2shell-fragnesia-chain](hunts/2026/2026-10-28-php2shell-fragnesia-chain/) | CVE-2026-109619 | Yes | 2026-10-26 | 2026-10-29 | Unknown | 0.99999 | 100.00 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-29-cisco-sdwan-keydrift](hunts/2026/2026-10-29-cisco-sdwan-keydrift/) | CVE-2026-20127 | Yes | 2026-02-25 | 2026-02-27 | Unknown | 0.89294 | 99.78 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-29-esxi-audit-log-gaps](hunts/2026/2026-10-29-esxi-audit-log-gaps/) | CVE-2026-41709 | Yes | 2026-10-28 | 2026-11-11 | Unknown | 0.00764 | 55.31 | 2026-10-30 (KEV catalogue 2026.10.29) |
| [2026-10-30-gitlab-ci-regex-rce](hunts/2026/2026-10-30-gitlab-ci-regex-rce/) | CVE-2026-97229 | Yes | 2026-10-29 | 2026-11-01 | Unknown | 0.18427 | 97.23 | 2026-10-30 (KEV catalogue 2026.10.29) |

<!-- kev-epss:end -->

## Using the queries

Read the hunt's `README.md` first. It lists the tables and telemetry the query needs, and the known false positives.

### Microsoft Defender XDR advanced hunting and Microsoft Sentinel (KQL)

1. Open the Defender portal and go to **Hunting > Advanced hunting**. Paste `query.kql` and run it.
2. In **Microsoft Sentinel**, open **Logs** (or advanced hunting in the Defender portal) and run the same query.
   - Defender tables such as `DeviceProcessEvents` must be streamed by the Microsoft Defender XDR connector.
   - Sentinel tables also carry `TimeGenerated`, if you prefer it to `Timestamp`.
3. Adjust the `let` lists and the `lookback` window at the top of each query.

### Splunk (SPL)

`query.spl` targets the CIM **Endpoint** data model (`Endpoint.Processes`).
- Your process telemetry must be CIM-mapped.
- Set `summariesonly=true` if you only want accelerated data.
- If you do not use the CIM, adapt the field names to your sourcetype, or convert the Sigma rule (see below).

### Sigma (any SIEM) with pySigma / sigma-cli

`rule.yml` is the portable source of truth. Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and the back ends you need. These are the versions CI uses:

```bash
python -m pip install sigma-cli==3.1.0 pysigma==1.5.1 \
  pysigma-backend-kusto==1.0.1 pysigma-backend-splunk==2.1.0 pysigma-backend-elasticsearch==2.1.1

# Validate
sigma check -x filename_length -x duplicate_filename hunts/

# Microsoft Defender XDR (KQL)
sigma convert -t kusto -p microsoft_xdr hunts/2026/2026-10-22-php-web-server-spawning-shell/rule.yml
# Microsoft Sentinel ASIM (KQL)
sigma convert -t kusto -p sentinel_asim <rule.yml>
# Splunk (CIM field names)
sigma convert -t splunk -p splunk_cim <rule.yml>
```

### Elastic Security (ES|QL, EQL, Lucene)

Sigma's `process_creation` and `file_event` fields need mapping to the Elastic Common Schema (ECS). Use the pipeline in this repository (it maps only those two categories):

```bash
sigma convert -t esql   -p pipelines/ecs-process-creation.yml <rule.yml>
sigma convert -t eql    -p pipelines/ecs-process-creation.yml <rule.yml>
sigma convert -t lucene -p pipelines/ecs-process-creation.yml <rule.yml>
```

The pipeline also limits `file_event` rules to file creation and change events (`event.category` file, `event.type` creation or change). It maps `User` to `user.name`, which holds the account name without the domain, so write `User` values without `DOMAIN\`.

Always review the converted output. Regular-expression semantics differ between back ends, and each hunt README notes any known differences.

## Query template

Every hunt uses the template in [`templates/hunt-template/`](templates/hunt-template/). The README covers:

- **Hypothesis:** one sentence on what an attacker would do and how it would show in telemetry.
- **Threat or CVE context:** linked to the primary source (vendor advisory, NCSC, CISA KEV, CERT-EU).
- **Data sources and tables:** including the sensor or licence needed.
- **Queries:** KQL and Sigma as standard, with SPL, ES|QL, EQL, YARA or osquery where they add value.
- **Tuning and false positives:** known benign causes, suggested exclusions and coverage gaps.
- **ATT&CK mapping.**
- **Validation notes:** what was tested, where, when, and with which benign simulation.

Each query file starts with a header giving the hunt ID, table, ATT&CK IDs, source link and licence.

### ATT&CK mapping convention

- **README:** a table of technique IDs with names, e.g. `T1190 | Exploit Public-Facing Application`, using the current [MITRE ATT&CK Enterprise](https://attack.mitre.org/) matrix.
- **Sigma:** tags in Sigma's v2 format:
  - tactics in lower case with hyphens (`attack.initial-access`);
  - technique IDs in lower case (`attack.t1190`, `attack.t1059.004`);
  - CVEs as `cve.YYYY-NNNNN`.
- **KQL and SPL:** an `ATT&CK:` line in the header comment.
- **Sub-techniques:** map to a sub-technique when the behaviour is specific to it. Otherwise map to the parent technique. Only map techniques the query can actually observe.

## Disclaimer

These queries and rules are provided **as-is, without warranty of any kind**.
- Hunts marked "Draft, untested" have not been run against live data.
- Always test and tune in a non-production environment and on your own telemetry before using any query for alerting or response.
- Run validation and simulations only on systems you own or are authorised to test.
- Nothing here is legal advice or a guarantee of detection.

## Contributing

Contributions are welcome. You can:
- propose a hunt;
- report a false positive;
- improve a query.

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [issue forms](https://github.com/CyberThreatNet/hunt-lab/issues/new/choose). Everyone taking part must follow the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## Licence

This repository uses two licences:

| Content | Licence | File |
|---|---|---|
| Sigma rules (`rule.yml` in `hunts/` and `templates/`) | Detection Rule License (DRL) 1.1 | [LICENSE-DRL](LICENSE-DRL) |
| Everything else: KQL, SPL and other queries, documentation, pipelines and CI | MIT | [LICENSE](LICENSE) |

**Why the split?**
- **Sigma rules use DRL 1.1,** the licence SigmaHQ uses. Our rules can then flow to and from the SigmaHQ community on the same terms. DRL 1.1 allows use and adaptation, as long as you keep author attribution and a link to the rule and the licence. Any rule adapted from SigmaHQ keeps its original author credit.
- **The other queries and docs use MIT,** a short, permissive licence that is easy to adopt.

Copyright © 2026 Cyber-Threat.net.
