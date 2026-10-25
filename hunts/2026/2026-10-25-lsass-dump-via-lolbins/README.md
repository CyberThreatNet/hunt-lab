# LSASS dumping with built-in Windows tools: comsvcs MiniDump and RdrLeakDiag

> **Draft for review: tested against public datasets, not published.** The Sigma rule matched every in-scope true-positive event (three executions) in two public datasets and produced no false positives among roughly 3,600 non-target process-creation events in the public test data (see [Validation notes](#validation-notes)). The KQL and SPL converted cleanly but have **not** been run in Defender XDR or Splunk.

| | |
|---|---|
| **Hunt ID** | `2026-10-25-lsass-dump-via-lolbins` |
| **Date** | 25 October 2026 |
| **Status** | Test (Sigma rule tested on public datasets; KQL/SPL converted, not engine-tested) |
| **Platforms** | Windows endpoints and servers. Sigma `product: windows`, `category: process_creation` (Sysmon event 1 or Security 4688 with command line). KQL for Defender XDR `DeviceProcessEvents`. SPL for Sysmon in Splunk, plus a CIM variant. |
| **ATT&CK** | T1003.001, T1218.011 |
| **CVEs** | n/a (technique hunt) |
| **Files** | [`rule.yml`](rule.yml) (Sigma, DRL 1.1), [`query.kql`](query.kql), [`query.spl`](query.spl), [`query-cim.spl`](query-cim.spl) (MIT), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md), [`EVIDENCE.md`](EVIDENCE.md) |

## Hypothesis

If an attacker with administrative rights wants credentials from memory without bringing a tool that antivirus would recognise, they will use a binary that ships with Windows to write a full memory dump of LSASS. The process-creation log will show `rundll32` calling the `MiniDump` export of `comsvcs.dll`, or `rdrleakdiag.exe` run with `/fullmemdmp` or `/memdmp`.

## Threat context

- Dumping LSASS memory is one of the most common ways to steal credentials on Windows ([T1003.001](https://attack.mitre.org/techniques/T1003/001/)). The [LOLBAS project](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) documents `comsvcs.dll` MiniDump, and [RdrLeakDiag](https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/) as a dump tool.
- This is a **generic** technique, seen in many ransomware and intrusion reports. The hunt is not tied to a specific campaign or CVE.
- **No IOCs** are given. The hunt is behaviour-based.

## Data sources and tables

| File | Data source | Requirement |
|---|---|---|
| `rule.yml` | Sigma `windows` / `process_creation` | Sysmon event 1, or Security 4688 with "Include command line in process creation events" enabled |
| `query.kql` | `DeviceProcessEvents` | Microsoft Defender for Endpoint |
| `query.spl` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, EventCode 1 | Sysmon plus the Splunk Add-on for Sysmon |
| `query-cim.spl` | CIM `Endpoint.Processes` | Any add-on populating the Endpoint data model. **Untested**: field prefixes may need removing with `from` |

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1218.011 | System Binary Proxy Execution: Rundll32 |

## How the logic works

The rule fires on any of:
1. a command line containing both `comsvcs` and `minidump` (case-insensitive);
2. a command line containing `comsvcs` and `#`, i.e. any export-by-ordinal call into comsvcs. This catches `#24`, `#+24` and the published evasions `#-4294967272` (negative wrap), `#65560` (16-bit wrap) and zero-padded forms such as `#0024`;
3. `rdrleakdiag.exe` (by path or by its original file name) run with `/fullmemdmp` or `/memdmp` (the rule matches `memdmp`, so any dash or slash form).

It does **not** require `lsass` in the command line, because the dump target is passed as a process ID.

## Tuning and false positives

- **Legitimate use is rare.** Support staff occasionally capture a process dump this way when troubleshooting; check for a change record and exclude by account and host, never by pattern.
- **Expected volume:** close to zero. Treat a hit as an incident until shown otherwise.
- **Evasions not covered:** the comsvcs branches key on the string "comsvcs" in the command line. A copy of comsvcs.dll under another name, or an 8.3 short path (for example `C:\Windows\System32\COMSVC~1.DLL`), will not match. Pair this hunt with an image-load or LSASS process-access detection (Sysmon 7 or 10, or Defender's equivalent). A renamed rundll32.exe is still caught, because the comsvcs branches match only the command line, not the name of the binary that runs it.
- **Coverage gaps (by design):** this hunt only covers the two built-in binaries. It does **not** catch Task Manager "Create dump file", ProcDump, direct-syscall tools (for example Dumpert), or Mimikatz in memory. The test data confirmed those are missed (see Evidence). Pair this hunt with an LSASS process-access hunt (Sysmon event 10, or `DeviceEvents` `OpenProcessApiCall` on `lsass.exe`).
- **Prevention beats detection here:** enable [LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) and the Defender [attack surface reduction rule](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) that blocks credential stealing from LSASS.

## Validation notes

Full commands and per-file results are in [`EVIDENCE.md`](EVIDENCE.md). Summary (25 October 2026):

| Check | Result |
|---|---|
| `sigma check` (sigma-cli 3.1.0, pySigma 1.5.1) | 0 errors, 0 condition errors, 0 issues |
| `sigma convert -t kusto -p microsoft_xdr` | Clean, `DeviceProcessEvents` query |
| `sigma convert -t splunk -p splunk_windows` and `-p splunk_cim` | Clean. `query.spl` was then scoped by hand to Sysmon event 1 (`source` and `EventCode` added after conversion) |
| True positives, EVTX-ATTACK-SAMPLES (chainsaw 2.17.1) | **2/2**: `sysmon_10_1_memdump_comsvcs_minidump.evtx` (1, dumps notepad.exe, not LSASS), `sysmon_rdrleakdiag_lsass_dump.evtx` (1) |
| True positives, OTRF `psh_lsass_memory_dump_comsvcs` (Zircolite 4.7.0) | **2/2** events from **one** execution: the same `rundll32 … comsvcs.dll MiniDump … full` launch, logged as both Sysmon 1 and Security 4688 |
| Non-target EVTX-ATTACK-SAMPLES files (276 files; corpus has 1,491 Sysmon 1 and 42 Security 4688 events) | **0** hits |
| Background: 5 other OTRF atomic files and APT29 day 1 + day 2 (783,367 events) | **0** hits |

**Limits of the test:**
- In the EVTX comsvcs sample the dumped process is `notepad.exe`, not LSASS. The technique and command line are identical, which is why it counts as a true positive for this rule.
- **Three executions, not four:** the 4 true-positive events come from one comsvcs MiniDump in EVTX-ATTACK-SAMPLES (against notepad.exe), one rdrleakdiag dump, and one comsvcs MiniDump in OTRF logged twice (Sysmon 1 and Security 4688). Three executions prove the logic works, not that it is quiet in your estate.
- **False-positive denominator:** the corpora hold about 842,000 events, but only process-creation events can match this rule: 3,617 non-target Sysmon 1 and Security 4688 events (1,531 in EVTX-ATTACK-SAMPLES, 42 in the OTRF atomic files, 2,044 in APT29).
- The ordinal branch and the `OriginalFileName` branch had no matching sample and are **untested**. After widening the ordinal branch to any `#` and adding `/memdmp`, the hit counts are unchanged (2 in EVTX-ATTACK-SAMPLES, 2 in OTRF atomic, 0 in APT29).
- The KQL and SPL have not been parsed by a Kusto or Splunk engine. Lab datasets are not a production baseline.

## Credits and licence

- Combines and adapts two SigmaHQ rules: [Process Memory Dump Via Comsvcs.DLL](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml) (Florian Roth, Modexp, Nasreddine Bencherchali, Swachchhanda Shrawan Poudel) and [Process Memory Dump via RdrLeakDiag.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml) (Cedric Maurugeon, Florian Roth, Swachchhanda Shrawan Poudel, Nasreddine Bencherchali). Original authors are kept in `rule.yml` as DRL 1.1 requires.
- `rule.yml`: [DRL 1.1](../../../LICENSE-DRL). Queries and this README: [MIT](../../../LICENSE).
- Test data: EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0); OTRF Security-Datasets by Roberto Rodriguez / OTRF (MIT), including the compound APT29 day 1 and day 2 datasets, an emulation of the MITRE ATT&CK Evaluations round 2 (APT29) scenario.

Provided as-is, without warranty. Test and tune before production use.
