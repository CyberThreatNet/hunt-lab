# Changelog

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Hunts are listed by publication date.

## [Unreleased]

### Changed

**KEV and EPSS refresh, 27 October 2026 (evening)**
- CISA added Node2Shell CVE-2026-111497 to KEV on 27 October 2026 (catalogue 2026.10.27; due 10 November; ransomware use Unknown; forensic triage No). `cve-context.yaml` for the 2026-10-26 Node2Shell hunt and the README table now show it as listed. EPSS for CVE-2026-111497 is 0.55483 (percentile 99.03, model date 27 October).
- Other hunts: catalogue version, checked dates and EPSS refreshed from the same feeds (PHP CVEs remain in KEV; their EPSS model date moved to 27 October).
- README "Why KEV and EPSS can disagree" updated: Node2Shell is no longer an example of "high EPSS, not in KEV"; it joins the PHP CVEs as a gap that closed.
- Node2Shell hunt README: the "no in-the-wild exploitation" line replaced with the KEV listing and ELLIO's 26 October sighting (no PoC links).

### Added

**ESXi audit-log gaps and unpatched inventory (CVE-2026-41709)**
- `hunts/2026/2026-10-29-esxi-audit-log-gaps/`
- Inventory, syslog-silence and shell-without-nearby-auth hunts for Broadcom VMSA-2026-0006 / CISA KEV CVE-2026-41709. Dual Sigma (shell/busybox baseline plus same-message auth-noise filter), hand KQL and SPL. Companion to the Cyber-Threat.net Alert.
- Status: experimental, draft, untested. Keep experimental until sigma-cli conversion and a benign lab simulation are recorded in EVIDENCE.md.

**Magento PolyShell CMS loader domains (CVE-2026-48356)**
- `hunts/2026/2026-10-27-magento-cms-loader-domains/`
- DNS-query Sigma for three Sansec-named loader hosts, with hand-written Defender XDR / Sentinel DNS KQL and Splunk conversion. Companion to the file-event webshell hunt.
- Status: draft, untested. Sigma check clean; Kusto backends do not map dns_query in our tooling.


**Magento / Adobe Commerce PolyShell webshells (CVE-2026-48356)**
- `hunts/2026/2026-10-27-magento-polyshell-webshell/`
- File-event Sigma for PHP/PHTML/PHAR under `*/media/custom_options/`, and for any path ending in `accesson.php`. KQL, ES|QL (ECS file_event) and Splunk conversions. Based on Adobe APSB26-73, CISA KEV and Sansec PolyShell research.
- Status: draft, untested. Sigma check clean; conversions clean, not engine-tested.


**testmetest npm worm: `.github/init.js` loaders, native-addon drops and persistence**
- `hunts/2026/2026-10-27-testmetest-ide-hook-loader/`
- Process creation: node or bun running `.github/init.js`, a hidden `/tmp/.<pid>` or `%TEMP%\.nc<pid>.js` drop, or a `.b-*` stage; processes naming the `net-health-checker` or `pkg-runtime` persistence. File events: the persistence files, `.napi_cache` and the Windows drop. A read-only file-search script for workstations and runners, and GitHub tree-sweep commands. Based on JFrog and SafeDep research.
- Includes two Sigma rules, per-hunt conversion targets, a standard-library Python script with offline tests, sources and test evidence.
- Status: test. The rules were tested on synthetic events and public datasets and the script on Linux; conversions are clean but not engine-tested.
- `.gitignore`: `evidence/` and `iocs.md` added, so private working files cannot be committed by accident.

**Node2Shell (CVE-2026-111497): shell spawned by a Node.js process**
- `hunts/2026/2026-10-26-node2shell-brotli/`
- Process creation: a shell or download tool started directly by node or bun, with package-manager and build-tool parents filtered. Hypotheses for Node.js crashes (SIGSEGV/SIGABRT), Brotli request bodies and exposure.
- Includes Sigma, per-hunt conversion targets, sources and test evidence.
- Status: test. The Sigma rule was tested on synthetic and public datasets; conversions are clean but not engine-tested.

**Arista EOS CVE-2026-7473 (draft)**
- `hunts/2026/2026-10-24-arista-cve-2026-7473/`
- Hypotheses for flow and network data: tunnel traffic to Arista decapsulation IPs that is the wrong tunnel type, or comes from an unknown peer. Based on Arista SA 0137.
- README and sources only. KQL and SPL are held until tested. No Sigma rule, and the README explains why.
- Status: draft, untested.

**DCSync: directory replication rights used by a non-machine account**
- `hunts/2026/2026-10-25-dcsync-replication-by-non-dc-account/`
- Security event 4662 on domain controllers: replication rights (Get-Changes, Get-Changes-All, Get-Changes-In-Filtered-Set) used by an account that is not a machine account.
- Includes Sigma, KQL (Sentinel `SecurityEvent`), Splunk SPL, sources and test evidence.
- Status: test. The Sigma rule was tested against public datasets; the KQL and SPL are converted but not engine-tested.

**LSASS dumping with built-in Windows tools**
- `hunts/2026/2026-10-25-lsass-dump-via-lolbins/`
- Process creation: comsvcs.dll MiniDump through rundll32, and RdrLeakDiag `/fullmemdmp` or `/memdmp`.
- Includes Sigma, KQL (Defender XDR `DeviceProcessEvents`), Splunk SPL (Sysmon, plus an untested CIM variant), sources and test evidence.
- Status: test. The Sigma rule was tested against public datasets; the KQL and SPL are converted but not engine-tested.

**Per-hunt CI conversion targets**
- Every hunt with a `rule.yml` now has a `ci-targets.txt` listing the `sigma convert` targets CI runs for it. Added for the 2026-10-22 hunt and the hunt template.

**KEV and EPSS exploitation context for CVE hunts**
- `cve-context.yaml` in each hunt that covers a CVE (2026-10-22 PHP, 2026-10-24 Arista, 2026-10-26 Node2Shell): CISA KEV status (listed, date added, due date, known ransomware use, catalogue version) and FIRST EPSS score and percentile, each with the date checked. Hunts with no CVE have no file.
- `scripts/refresh_kev_epss.py` (standard library only) refreshes the files and a generated KEV and EPSS table in `README.md`; `--check` validates them offline. A refresh builds everything before writing, so a failed run changes nothing, and it never replaces an existing EPSS score with `null` unless run with `--allow-null`.
- README, CONTRIBUTING, the hunt template and the pull request template explain the fields: KEV is a yes/no catalogue, not a score; EPSS is a daily probability.
- `scripts/tests/test_refresh_kev_epss.sh`: offline safety tests for the refresh script (simulated feeds, run on a temporary copy of the repository), run by CI.
- The refresh script exits with code 3, writing nothing, when FIRST EPSS returns no score for any CVE (an outage, not a gap). Exit codes 0 to 3 are documented in the README and in `--help`.

### Changed

**KEV and EPSS refresh, 27 October 2026**
- CISA added the PHP CVEs (CVE-2026-109618, CVE-2026-109619) to KEV on 26 October 2026 (catalogue 2026.10.26; due 29 October; ransomware use Unknown). `cve-context.yaml` for the 2026-10-22 PHP hunt and the README table now show them as listed. Other hunts: checked dates and catalogue version only.
- README "Why KEV and EPSS can disagree" rewritten: the PHP CVEs are no longer an example of "high EPSS, not in KEV"; Node2Shell CVE-2026-111497 now is.

- `.github/workflows/validate.yml`: new step runs `python scripts/refresh_kev_epss.py --check`.
- `hunts/2026/2026-10-22-php-web-server-spawning-shell/README.md`: status banner now reads "Draft for review: untested" (it previously said "Draft for review: untested, not published").
- DCSync, LSASS, Node2Shell and Arista hunt READMEs: "not published" removed from the status banner, as the repository is public. Each banner's test status is unchanged. All hunt banners now use the template's form, "Draft for review: <test status>" (Arista's was "Draft — untested"), and the Arista Status row uses the template's values: "Experimental (draft, untested)".
- `.github/workflows/validate.yml`: new step runs `scripts/tests/test_refresh_kev_epss.sh`.
- `.github/workflows/validate.yml`: test conversions now read each hunt's `ci-targets.txt`, check every line against an allow-list and fail if the file is missing, empty or names a target that is not allowed.
- `README.md`: says the hunts are free to use, links to the Hunt Lab pages and RSS feed on Cyber-Threat.net, and adds badges for both.
- ECS pipeline maps Sigma's Description field to process.pe.description, so EQL and ES|QL no longer reject rules that use it. Sysmon data via Elastic's Windows integration fills it; Elastic Defend maps the field but doesn't document filling it on process events.
- CI: fail an Elastic (ES|QL) target when a rule's regex can't work on Elastic's regex engine: `^`/`$` anchors, `\b` or `(?…)` groups, `|re|i`/`|re|m`/`|re|s` modifiers, unsupported escapes, or a top-level branch without a leading `.*` (`scripts/check_elastic_regex.py`, with unit tests in `scripts/tests/test_check_elastic_regex.py`, run by CI). PHP web-server hunt: dropped the ES|QL target and corrected the Elastic note.
- CI: test conversions now cover every rule YAML in a hunt folder (any `*.yml` with a `detection` section), not only `rule.yml`.
- ECS pipeline maps Sigma `file_event` rules: `TargetFilename` to `file.path`, `Image` to `process.executable`, `ProcessId` to `process.pid` and `User` to `user.name`, limited to file creation and change events (`event.category` file, `event.type` creation or change). Elastic Defend lists all four fields on its file creation, modification, overwrite and rename events; Sysmon event 11 via Elastic's Windows integration fills them too (`User` only from Sysmon 13.30, and only the name part of `DOMAIN\user`). `User` values must omit the domain, because `user.name` holds the name only.
- CI now fails an Elastic target (ES|QL today; EQL and Lucene too if they are added to the allow-list) whose rule uses a field the target's pipeline doesn't map, so a rule can no longer pass CI and then be rejected or match nothing in Elastic.

## [0.1.0] - 2026-10-22

### Added

**First hunt: Hunt of the week #1**
- `hunts/2026/2026-10-22-php-web-server-spawning-shell/`
- Looks for a shell or download tool spawned by a PHP worker or web server on Linux. This is possible follow-on activity after CVE-2026-109618 and CVE-2026-109619.
- Includes KQL (Defender XDR `DeviceProcessEvents`), Sigma and Splunk SPL.
- Status: draft, untested.

**Templates and tooling**
- Hunt template: `templates/hunt-template/`.
- pySigma ECS field-mapping pipeline for Elastic: `pipelines/ecs-process-creation.yml`.
- GitHub Actions workflow that validates Sigma rules (`sigma check`) and runs test conversions.

**Repository files**
- Issue forms for new hunt requests and false positive reports.
- Pull request template.
- Licences: Detection Rule License 1.1 for Sigma rules, MIT for everything else.
- README, CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1) and SECURITY policy.

[Unreleased]: https://github.com/CyberThreatNet/hunt-lab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CyberThreatNet/hunt-lab/releases/tag/v0.1.0
