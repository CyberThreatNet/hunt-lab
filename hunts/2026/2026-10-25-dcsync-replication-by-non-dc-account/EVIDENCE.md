# Test evidence: 2026-10-25-dcsync-replication-by-non-dc-account

Run on 25 October 2026 (re-run after the review fixes at about 18:05 GMT) (Europe/London) on an isolated Linux analysis box. Free, open-source tools only. Raw tool outputs are kept privately and are not published.

## Tools

| Tool | Version |
|---|---|
| sigma-cli / pySigma | 3.1.0 / 1.5.1 (backends: kusto 1.0.1, splunk 2.1.0) |
| chainsaw | 2.17.1 (WithSecure), mapping `sigma-event-logs-all.yml` |
| Zircolite | 4.7.0 (git a5d868b), JSON-lines input |

## Datasets

| Dataset | Version | Events |
|---|---|---|
| [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | commit 4ceed2f (24 Jan 2023) | 278 files, 37,364 records, 33 event 4662s |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), atomic `credential_access/host`: `empire_dcsync_dcerpc_drsuapi_DsGetNCChanges`, `covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges`, plus 4 non-target files | master, 25 Oct 2026 | 21,151 events in 6 files |
| OTRF Security-Datasets compound `apt29` day 1 + day 2 (manual) | master, 25 Oct 2026 | 783,367 events, 27 event 4662s |

Account and host names quoted below are those recorded in the public datasets.

## Commands and results

```bash
sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename rule.yml
# Found 0 errors, 0 condition errors and 0 issues.

sigma convert -t kusto -p azure_monitor rule.yml     # clean -> SecurityEvent query
sigma convert -t splunk -p splunk_windows rule.yml   # clean

chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s rule.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -q -o <output-dir>/chainsaw-dcsync-replication-by-non-dc-account.json
zircolite.py -e <data-dir>/mordor -f json -j -r rule.yml -o <output-dir>/zircolite-mordor-dcsync-replication-by-non-dc-account.json
zircolite.py -e <data-dir>/apt29  -f json -j -r rule.yml -o <output-dir>/zircolite-apt29-dcsync-replication-by-non-dc-account.json
```

| Dataset / file | Expected | Hits | Notes |
|---|---|---|---|
| EVTX `Credential Access/CA_DCSync_4662.evtx` | 3 (true positive) | **3** | User `Administrator`, AccessMask 0x100, Get-Changes ×2, Get-Changes-All ×1 |
| EVTX: other 277 files | 0 | **0** | Includes 30 other 4662 events: 3 replication by `DC1$` (suppressed by the machine-account filter) and 2 Manage-Topology (`1131f6ac`, not in scope) |
| Mordor `empire_dcsync_…_2020-09-21185829.json` | 3 (true positive) | **3** | User `pgustavo` on `MORDORDC` |
| Mordor `covenant_dcsync_…_2020-08-05020926.json` | 3 (true positive) | **3** | User `pgustavo` on `MORDORDC` |
| Mordor: 4 non-target files (mimikatz logonpasswords, RDP Task Manager LSASS dump, dumpert, comsvcs) | 0 | **0** | |
| APT29 day 1 + day 2 | 0 | **0** | 1 legitimate replication by `NEWYORK$` suppressed |

**Totals:** 9/9 true-positive events detected (3 in EVTX-ATTACK-SAMPLES, 6 across two OTRF atomic datasets). No false positives among the 57 other event 4662 records in the test corpora, 4 of which are legitimate domain-controller replication by machine accounts. The corpora hold about 842,000 events in all, but only event 4662 records can match this rule, so 57 is the honest denominator. Small public samples are not your domain: tune before alerting.

## Not tested

- KQL and SPL execution in a real Kusto or Splunk engine (conversion only).
- The `NT AUT` exclusion (no such accounts in the data). The rule no longer excludes `MSOL_` by prefix; any exact-name exclusion you add is yours to test.
- Production noise: lab datasets are not a substitute for a week of your own domain controller logs.
