# Test evidence: 2026-10-25-lsass-dump-via-lolbins

Run on 25 October 2026 (re-run after the review fixes, about 18:05 GMT, with the widened ordinal branch and `/memdmp`) (Europe/London) on an isolated Linux analysis box. Free, open-source tools only. Raw tool outputs are kept privately and are not published. Tool and dataset versions as in the DCSync hunt's EVIDENCE.md (sigma-cli 3.1.0 / pySigma 1.5.1, chainsaw 2.17.1, Zircolite 4.7.0 git a5d868b; EVTX-ATTACK-SAMPLES commit 4ceed2f; OTRF Security-Datasets master as of 25 Oct 2026).

## Commands

```bash
sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename rule.yml
# Found 0 errors, 0 condition errors and 0 issues.
sigma convert -t kusto  -p microsoft_xdr  rule.yml   # clean -> DeviceProcessEvents
sigma convert -t splunk -p splunk_windows rule.yml   # clean
sigma convert -t splunk -p splunk_cim     rule.yml   # clean -> Processes.* fields

chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s rule.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -q -o <output-dir>/chainsaw-lsass-dump-via-lolbins.json
zircolite.py -e <data-dir>/mordor -f json -j -r rule.yml -o <output-dir>/zircolite-mordor-lsass-dump-via-lolbins.json
zircolite.py -e <data-dir>/apt29  -f json -j -r rule.yml -o <output-dir>/zircolite-apt29-lsass-dump-via-lolbins.json
```

## Results

Account and host names quoted below are those recorded in the public datasets.


| Dataset / file | Expected | Hits | Notes |
|---|---|---|---|
| EVTX `Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx` | 1 (TP, technique; target notepad.exe) | **1** | Sysmon 1: `rundll32 C:\windows\system32\comsvcs.dll, MiniDump <pid> <path> full`, parent WmiPrvSE (target was notepad.exe) |
| EVTX `Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx` | 1 (TP) | **1** | Sysmon 1: `rdrleakdiag.exe /p <pid> /o <dir> /fullmemdmp /snap` |
| EVTX: other 276 files | 0 | **0** | Corpus contains 1,491 Sysmon 1 and 42 Security 4688 events |
| Mordor `psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json` | 2 (TP events, one execution) | **2** | One launch, logged as Sysmon 1 and Security 4688 |
| Mordor: 5 non-target files (2 DCSync, mimikatz logonpasswords, RDP Task Manager dump, dumpert) | 0 | **0** | |
| APT29 day 1 + day 2 (783,367 events) | 0 | **0** | 1,028 Sysmon 1 and 1,016 Security 4688 events |

**Totals:** 4/4 true-positive events detected, from three executions: one comsvcs MiniDump in EVTX-ATTACK-SAMPLES (against notepad.exe, identical technique), one rdrleakdiag dump, and one comsvcs MiniDump in OTRF logged as both Sysmon 1 and Security 4688. No false positives among the 3,617 other process-creation events (Sysmon 1 and Security 4688) in the corpora (roughly 3,600). The corpora hold about 842,000 events in all, but only process-creation events can match this rule. Three executions prove the logic works, not that it is quiet in your estate.

## Known misses (out of scope by design, confirmed)

These LSASS dumps in the same datasets were **not** detected, as expected, because they do not use comsvcs or RdrLeakDiag: `rdp_interactive_taskmanager_lsass_dump` (Task Manager), `cmd_lsass_memory_dumpert_syscalls` (direct syscalls), `sysmon_10_11_lsass_memdump.evtx`, `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx`, `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`. A companion LSASS process-access hunt is the right way to cover them.

## Not tested

- The ordinal branch (a `#` in any command line that mentions `comsvcs`, covering `#24`, `#+24`, `#-4294967272`, `#65560`, `#0024`), the `/memdmp` form and the `OriginalFileName` branch: no sample in the datasets. Widening them left every hit count unchanged.
- A renamed comsvcs.dll or an 8.3 short path (`COMSVC~1.DLL`): these will not match by design (see README).
- KQL and SPL execution in a real engine (conversion only).
- Production noise.
