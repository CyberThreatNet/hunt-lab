# Synology C3RB3R / outdated DSM exposure and encryption artefacts

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-03-synology-c3rb3r-dsm | 2026-11-03 | Experimental | Synology DSM; network edge; Splunk; Microsoft Sentinel / Defender | T1190, T1486, T1490 | CVE-2024-10441 (linked), CVE-2024-50629, CVE-2024-10445 | rule.yml, rule-proxy-dsm-exposure.yml, query.kql, host-checks.sh, ci-targets.txt, sources.md |

## Hypothesis

An internet-reachable Synology DSM management interface on a build below Synology-SA-24:20 is being used as the entry point for ransomware. After access, operators encrypt shared-folder files (`.L0CK3D` / `read-me3.txt`) and may delete or empty snapshots and backups.

## Threat context

Synology warned on 29 October 2026 that attackers are exploiting a DSM vulnerability patched in December 2024 to encrypt data on outdated DSM. The notice links Synology-SA-24:20 (CVE-2024-10441 remote code execution, CVE-2024-50629 file read, CVE-2024-10445 file write). Synology has not named which CVE is used. Trade reporting attributes the encryptor to C3RB3R, with `read-me3.txt` notes and `.L0CK3D` extensions. Fixed builds: DSM 7.2.2-72806-1, 7.2.1-69057-6, 7.2-64570-4, 7.1.1-42962-7, 6.2.4-25556-8 (and later). No public network IOC list from Synology as of 3 November 2026.

These hunts look for exposure and post-compromise artefacts, not for the unpublished exploit itself.

## Hunts

1. **DSM version and exposure** (`host-checks.sh`). Confirm the installed DSM build against the fixed table. Confirm whether ports 5000/5001 (or custom HTTPS admin ports) are reachable from untrusted networks.
2. **Internet to DSM admin** (`rule-proxy-dsm-exposure.yml`, `query.kql` Q1). Inbound accepts to Synology management ports from public addresses.
3. **Encryption artefacts** (`rule-file-l0ck3d.yml`, `query.kql` Q2). Creation of `*.L0CK3D` or `read-me3.txt` on file shares or endpoints that sync from the NAS.
4. **Backup and snapshot destruction** (`query.kql` Q3, host checks). Sudden deletion of snapshots, Hyper Backup destinations going empty, or mass file deletes on backup volumes.

## Data sources

| Source | How to collect | Used by |
|---|---|---|
| DSM Control Panel / CLI | `host-checks.sh` on the NAS or via SSH | Hunt 1 |
| Firewall / reverse-proxy / VPN logs | Splunk or Sentinel ingestion of edge accepts | Hunt 2 |
| Endpoint or file-server telemetry | Microsoft Defender `DeviceFileEvents`, Synology Log Center exports, share audit | Hunt 3 |
| Backup product logs | Hyper Backup, Active Backup, Veeam, Rubrik, etc. | Hunt 4 |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1190 Exploit Public-Facing Application | Entry through exposed DSM management on outdated builds |
| T1486 Data Encrypted for Impact | `.L0CK3D` encryption and ransom note |
| T1490 Inhibit System Recovery | Snapshot / backup deletion after access |

## Notes

- Synology has not published exploit packet signatures. Do not treat a single public IP hitting 5001 as proof of CVE use; combine with version and artefacts.
- pySigma has no first-class Synology product table; Splunk conversion is best-effort. Hand-written KQL is in `query.kql`.
