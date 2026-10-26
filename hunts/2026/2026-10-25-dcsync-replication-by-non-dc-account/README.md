# DCSync: directory replication rights used by a non-machine account

> **Draft for review: tested against public datasets.** The Sigma rule matched every true-positive event in two public datasets and produced no false positives among the 57 non-target event 4662 records in the public test data (see [Validation notes](#validation-notes)). The KQL and SPL converted cleanly but have **not** been run in Sentinel or Splunk.

| | |
|---|---|
| **Hunt ID** | `2026-10-25-dcsync-replication-by-non-dc-account` |
| **Date** | 25 October 2026 |
| **Status** | Test (Sigma rule tested on public datasets; KQL/SPL converted, not engine-tested) |
| **Platforms** | Windows domain controllers. Sigma `product: windows`, `service: security`. KQL for Microsoft Sentinel / Log Analytics `SecurityEvent`. SPL for Windows Security events in Splunk (XML rendering). |
| **ATT&CK** | T1003.006 |
| **CVEs** | n/a (technique hunt) |
| **Files** | [`rule.yml`](rule.yml) (Sigma, DRL 1.1), [`query.kql`](query.kql) (MIT), [`query.spl`](query.spl) (MIT), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md), [`EVIDENCE.md`](EVIDENCE.md) |

## Hypothesis

If an attacker who holds a privileged account asks a domain controller to replicate password data to them (DCSync), the domain controller logs event 4662 showing a **user** account, not a domain controller's computer account, using the directory replication rights.

## Threat context

- DCSync abuses the normal Directory Replication Service protocol. Anyone holding the "Replicating Directory Changes" and "Replicating Directory Changes All" rights can request password hashes for any account, including `krbtgt`, without touching LSASS on the domain controller. MITRE tracks it as [T1003.006](https://attack.mitre.org/techniques/T1003/006/).
- It is a **generic** technique used widely after domain compromise, by both criminal and state groups. This hunt is not tied to a specific campaign or CVE.
- **No IOCs** are given. The hunt is behaviour-based.

## Data sources and tables

| File | Data source | Requirement |
|---|---|---|
| `rule.yml` | Windows Security event 4662 on domain controllers | "Audit Directory Service Access" (Success) **and** a SACL on the domain naming context root auditing the replication rights. Without the SACL, 4662 is not written for these rights. |
| `query.kql` | `SecurityEvent` (Sentinel / Log Analytics) | Azure Monitor Agent on domain controllers collecting event 4662 ("All events" or a custom XPath). |
| `query.spl` | `WinEventLog:Security` | Splunk Add-on for Microsoft Windows with XML rendering, so `SubjectUserName` and `Properties` are extracted. |

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1003.006 | OS Credential Dumping: DCSync |

## How the logic works

- **Event:** 4662 ("An operation was performed on an object") with `AccessMask` `0x100` (control access, i.e. an extended right was used).
- **Rights:** `Properties` contains one of the replication extended-right GUIDs:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` DS-Replication-Get-Changes
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` DS-Replication-Get-Changes-All
  - `89e95b76-444d-4c62-991a-0facbeda640c` DS-Replication-Get-Changes-In-Filtered-Set
- **Excluded:** computer accounts (names ending `$`, which is how domain controllers replicate), `Window Manager` sessions and `NT AUTHORITY` accounts. Entra Connect sync accounts are **not** excluded out of the box: add yours by exact name (see Tuning).
- **AccessMask normalisation:** some collection pipelines render `0x100` as decimal `256` or as `%%7688`. If your SIEM does this, adjust the KQL/SPL match.
- DS-Replication-Manage-Topology (`1131f6ac-…`) is deliberately **not** matched; it is used in routine replication management, and the test corpus contains two such events that are correctly ignored.
- The upstream SigmaHQ rule also matches `9923a32a-3607-11d2-b9be-0000f87a36b2`, which it labels DS-Replication-Synchronize. Microsoft's schema reference gives that GUID as **DS-Install-Replica** ("Add/Remove Replica In Domain"), the right DCShadow abuses; DS-Replication-Synchronize is `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2`. Neither right is needed to pull password data, so both are left out to keep this hunt about DCSync. The only event in the test corpora with `9923a32a` is the DCShadow sample (`persistence_security_dcshadow_4742.evtx`), which belongs in a DCShadow hunt.

## Tuning and false positives

- **Entra Connect (Azure AD Connect):** its AD DS connector account legitimately holds replication rights and is usually named `MSOL_` followed by a hex string. The rule ships **without** a prefix exclusion: add your own account by exact name in the commented `filter_optional_entra_connect` block. Never exclude by the `MSOL_` prefix, because an attacker who can create accounts can choose that prefix (an `MSOL_backup` account would DCSync unseen).
- **Other products with replication rights** (some identity-governance, password-audit and backup tools). List every account that holds these rights (a periodic ACL review of the domain root is worth doing anyway) and exclude those accounts by name, not by pattern.
- **Expected volume:** near zero in a healthy domain once sync accounts are excluded. Any hit from an ordinary admin or user account deserves an investigation.
- **Coverage gaps:** no hit if the SACL is missing; a DCSync performed with a stolen **domain controller computer account** is excluded by design (SigmaHQ has a separate "Suspicious Machine Account Replication" rule for that case, which compares the source IP with known DCs).
- The machine-account filter (`SubjectUserName` ending in `$`) also hides group managed service accounts, non-DC computer accounts and any user account deliberately named with a trailing `$`. A compromised computer account granted replication rights will not be flagged. Pair this hunt with SigmaHQ's companion rule for replication by machine accounts that are not domain controllers, or with an allow-list of your DC names.

## Validation notes

Full commands and per-file results are in [`EVIDENCE.md`](EVIDENCE.md). Summary (25 October 2026):

| Check | Result |
|---|---|
| `sigma check` (sigma-cli 3.1.0, pySigma 1.5.1) | 0 errors, 0 condition errors, 0 issues |
| `sigma convert -t kusto -p azure_monitor` | Clean, `SecurityEvent` query |
| `sigma convert -t splunk -p splunk_windows` | Clean |
| True positives, EVTX-ATTACK-SAMPLES `Credential Access/CA_DCSync_4662.evtx` (chainsaw 2.17.1) | **3/3** DCSync events matched (Get-Changes ×2, Get-Changes-All ×1) |
| True positives, OTRF Security-Datasets `empire_dcsync_dcerpc_drsuapi_DsGetNCChanges` and `covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges` (Zircolite 4.7.0) | **6/6** matched (3 per dataset) |
| Non-target files in EVTX-ATTACK-SAMPLES (277 files, includes 30 other 4662 events) | **0** hits. 3 DC-to-DC replication events by `DC1$` and 2 Manage-Topology events correctly not matched. |
| Background: OTRF APT29 day 1 + day 2 compound datasets (783,367 events, 27 event 4662s) | **0** hits. 1 legitimate DC replication by a machine account correctly not matched. |

**False-positive denominator:** the corpora hold about 842,000 events in all, but only event 4662 records can match this rule. There are 57 non-target 4662s (30 in EVTX-ATTACK-SAMPLES, 27 in APT29; all 6 OTRF atomic 4662s are true positives), 4 of them legitimate machine-account replication. 57 is the honest denominator.

**Limits of the test:** these are lab datasets, not production domains. They contain no Entra Connect or third-party sync account. The KQL and SPL have not been parsed by a Kusto or Splunk engine.

## Credits and licence

- Adapted from SigmaHQ rule [Active Directory Replication from Non Machine Account - DcSync Indicator](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml) by Roberto Rodriguez (@Cyb3rWard0g). The original author is kept in `rule.yml` as DRL 1.1 requires. Changes: added the `AccessMask` 0x100 condition, dropped the `9923a32a` GUID (DS-Install-Replica; see How the logic works), dropped the `MSOL_` prefix exclusion, raised level to high for hunting.
- `rule.yml`: [DRL 1.1](../../../LICENSE-DRL). `query.kql`, `query.spl` and this README: [MIT](../../../LICENSE).
- Test data: EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0); OTRF Security-Datasets by Roberto Rodriguez / OTRF (MIT), including the compound APT29 day 1 and day 2 datasets, an emulation of the MITRE ATT&CK Evaluations round 2 (APT29) scenario.

Provided as-is, without warranty. Test and tune before production use.
