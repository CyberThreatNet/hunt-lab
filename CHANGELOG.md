# Changelog

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Hunts are listed by publication date.

## [Unreleased]

### Added

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

### Changed

- `.github/workflows/validate.yml`: test conversions now read each hunt's `ci-targets.txt`, check every line against an allow-list and fail if the file is missing, empty or names a target that is not allowed.

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
