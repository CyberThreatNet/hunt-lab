# Sources for 2026-10-25-dcsync-replication-by-non-dc-account

All sources checked on 25 October 2026 (Europe/London).

| Claim | Source |
|---|---|
| DCSync technique definition | [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Event 4662 fields (AccessMask, Properties, SubjectUserName) | [Microsoft Learn: 4662(S, F) An operation was performed on an object](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662) |
| Replication extended-right GUIDs, SACL requirement | [OTRF Threat Hunter Playbook: Active Directory replication](https://threathunterplaybook.com/library/windows/active_directory_replication.html) |
| Upstream rule and exclusions (`$`, Window Manager, NT AUT; upstream's MSOL_ prefix exclusion is deliberately not used) | [SigmaHQ win_security_ad_replication_non_machine_account.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml) |
| Entra Connect AD DS connector account holds replication rights | [Microsoft Learn: Entra Connect accounts and permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) |
| Test data (true positives) | [EVTX-ATTACK-SAMPLES `CA_DCSync_4662.evtx`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/master/Credential%20Access) (GPL-3.0); [OTRF Security-Datasets credential_access host datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows/credential_access/host) (MIT) |
| Test data (background) | [OTRF Security-Datasets, compound APT29 day 1 and day 2](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) (Roberto Rodriguez / OTRF), an emulation of the MITRE ATT&CK Evaluations round 2 (APT29) scenario. MIT licence. |
| DS-Install-Replica GUID `9923a32a-3607-11d2-b9be-0000f87a36b2` (why it is not matched) | [Microsoft Learn: DS-Install-Replica extended right](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-install-replica) |
| DS-Replication-Synchronize GUID `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2` (not matched) | [Microsoft Learn: DS-Replication-Synchronize extended right](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-synchronize) |

## Not verified / not used

- No specific campaign or threat actor is claimed for this hunt.
- No IOCs.
