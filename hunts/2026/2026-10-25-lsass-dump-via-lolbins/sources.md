# Sources for 2026-10-25-lsass-dump-via-lolbins

All sources checked on 25 October 2026 (Europe/London).

| Claim | Source |
|---|---|
| LSASS memory dumping technique | [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| Rundll32 proxy execution | [MITRE ATT&CK T1218.011](https://attack.mitre.org/techniques/T1218/011/) |
| comsvcs.dll MiniDump as a living-off-the-land dump method | [LOLBAS: comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) |
| rdrleakdiag.exe /fullmemdmp and /memdmp | [LOLBAS: Rdrleakdiag.exe](https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/) |
| Upstream rules | [SigmaHQ comsvcs rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml); [SigmaHQ RdrLeakDiag rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml) |
| LSA protection (RunAsPPL) | [Microsoft Learn: Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) |
| ASR rule blocking credential stealing from LSASS | [Microsoft Learn: ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) |
| Test data | [EVTX-ATTACK-SAMPLES Credential Access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/master/Credential%20Access) (GPL-3.0); [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (Roberto Rodriguez / OTRF, MIT), including the compound APT29 day 1 and day 2 datasets, an emulation of the MITRE ATT&CK Evaluations round 2 (APT29) scenario |
| comsvcs ordinal evasions (`#-4294967272`, `#65560`, zero padding) | [SigmaHQ comsvcs rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml) and its references |

## Not verified / not used

- No specific campaign or threat actor is claimed.
- No IOCs.
