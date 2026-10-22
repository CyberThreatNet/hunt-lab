# Changelog

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Hunts are listed by publication date.

## [Unreleased]

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
