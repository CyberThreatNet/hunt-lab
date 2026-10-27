# Test evidence: 2026-10-27-testmetest-ide-hook-loader

Run on 27 October 2026, between about 07:30 and 08:40 GMT (Europe/London), on our isolated Linux analysis machine (Debian, Python 3.13.5, node 20.19.2, git 2.47.3). Free, open-source tools only. Raw tool outputs and the synthetic test events are kept privately and are not published. Tool and dataset versions as in the 2026-10-26 hunt: sigma-cli 3.1.0 / pySigma 1.5.1 (backends kusto 1.0.1, splunk 2.1.0, elasticsearch 2.1.1), chainsaw 2.17.1, Zircolite 4.7.0 git a5d868b; EVTX-ATTACK-SAMPLES commit 4ceed2f; OTRF Security-Datasets master as of 25 Oct 2026. No malware sample, infected host or armed repository was downloaded or used.

## Commands

```bash
sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename hunts/
# Found 0 errors, 0 condition errors and 0 issues. (A first draft used attack.defense-evasion, which
# pySigma's ATT&CK v20 data rejects; T1027 is now under attack.stealth.)

# Every line of ci-targets.txt, run from the repository root as the CI step does:
sigma convert -t kusto  -p microsoft_xdr  rule.yml   # clean -> DeviceProcessEvents
sigma convert -t kusto  -p sentinel_asim  rule.yml   # clean -> imProcessCreate
sigma convert -t splunk --without-pipeline rule.yml  # clean
sigma convert -t esql   -p pipelines/ecs-process-creation.yml rule.yml   # clean -> process.executable, process.command_line
# CI converts both rule files for every listed target; Elastic outputs use the repo's ECS pipeline for process_creation and file_event.
sigma convert -t kusto -p microsoft_xdr rule-persistence.yml   # clean -> DeviceFileEvents
sigma convert -t kusto -p sentinel_asim rule-persistence.yml   # clean -> imFileEvent
sigma convert -t splunk --without-pipeline rule-persistence.yml  # clean
sigma convert -t esql   -p pipelines/ecs-process-creation.yml rule-persistence.yml   # clean -> file.path; event.category file, event.type creation or change (re-run on 27 Oct 2026 after the pipeline gained its file_event mapping)

# Synthetic positives and negatives (JSON lines, Sysmon-style field names)
zircolite.py -e <data-dir>/synthetic/proc -f json -j -r rule.yml -o <output-dir>/zircolite-proc.json
zircolite.py -e <data-dir>/synthetic/file -f json -j -r rule-persistence.yml -o <output-dir>/zircolite-file.json

# Public background data
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s rule.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -o <output-dir>/chainsaw-rule.json
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s rule-persistence.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -o <output-dir>/chainsaw-rule-persistence.json
zircolite.py -e <data-dir>/mordor -f json -j -r <rule> -o <output-dir>/z-mordor-<rule>.json   # both rules
zircolite.py -e <data-dir>/apt29  -f json -j -r <rule> -o <output-dir>/z-apt29-<rule>.json    # both rules

# Engine check: mutated copies ('net-health-checker' -> 'cmd.exe' in rule.yml;
# '/var/tmp/.fontconfig_state' -> '.exe' in rule-persistence.yml)
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s <output-dir>/mut-rule.yml    ... # 329 hits
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s <output-dir>/mut-persist.yml ... # 24 hits

# File-search script
python3 tests/test_scan_testmetest.py                      # 19 tests, synthetic fixtures built at run time
python3 scan_testmetest.py <analysis-folder> <repo-clone> --git   # our analysis machine, about 52,000 files, home and /tmp checks on
npm install --ignore-scripts express typescript eslint bcrypt sqlite3   # in an empty folder: 185 top-level packages
python3 scan_testmetest.py <that-folder> --no-host

# GitHub tree sweep (README hunt 4)
curl -s https://api.github.com/repos/CyberThreatNet/hunt-lab/git/trees/HEAD?recursive=1 | jq -r "<filter from README>"
echo '<synthetic tree JSON>' | jq -r "<filter from README>"
# git ls-tree loop from README, in a synthetic repository with a 13,000,000-byte .github/init.js on main only
```

## Results

| Dataset / file | Expected | Hits | Notes |
|---|---|---|---|
| `rule.yml`, synthetic positives P1 to P10 | 10 | **10** | `node .github/init.js` (Linux), `bun .github/init.js`, `node .github\init.js` (Windows), `node /tmp/.48213`, the same with a trailing argument, `node …\Temp\.nc4242.js`, `bun run /tmp/.b-x7k2/index.js`, `systemctl --user enable --now net-health-checker.service`, `python3 ~/.local/share/runtimes/sync.py`, `launchctl bootstrap … com.user.pkg-runtime.plist` |
| `rule.yml`, synthetic negatives N1 to N13 | 0 | **0** | `node scripts/init.js`; `node .github/scripts/release.js`; `node /tmp/build-1234/index.js`; `node /tmp/.cache/app.js`; `bash /tmp/.48213` (not node); `node …\Temp\nc4242.js` (no dot); npm install; `systemctl --user restart syncthing.service`; `cat .github/init.js`; `bun run build`; `node /tmp/.12ab/index.js`; `node /tmp/.123/index.js`; `node /tmp/.48213x` |
| Same events, rule as first drafted | | 11 | The first `/tmp/.<digits>` regular expression also matched N11 in Zircolite (unanchored search). Fixed with `filter_drop_not_pid`; N12 and N13 were added after the fix |
| `rule-persistence.yml`, synthetic positives F1 to F11 | 11 | **11** | All seven persistence paths, a file under `~/.config/net-health-checker/`, `.napi_cache` on Linux and Windows, `%TEMP%\.nc4242.js` |
| `rule-persistence.yml`, synthetic negatives M1 to M7 | 0 | **0** | `~/.local/bin/health-checker.sh`, `syncthing.service`, `sharp.node`, `Temp\nc4242.js`, `.napi_cache.bak`, a node binary under `~/.local/share/runtimes/`, `/var/tmp/fontconfig_state` |
| EVTX-ATTACK-SAMPLES, 278 files | 0 | **0** | Both rules. Mutated copies gave 329 and 24 hits, so chainsaw does evaluate both product-less rules |
| OTRF atomic files (6 files) | 0 | **0** | Both rules |
| OTRF APT29 day 1 + day 2 | 0 | **0** | Both rules |
| `scan_testmetest.py` offline tests | 19 pass | **19 pass** | Positive fixture (13 MB sparse `init.js` with the published wrapper start, all six hook types, lockfile, installed packages, `.napi_cache`, `binding.gyp`, hash match via `--ioc-file`, seven persistence paths, four temp drops, a git repository with campaign branches and commit markers and `init.js` only in history); negative fixture (benign hooks, `node -p` `binding.gyp`, a package named `testmetester`, `chore/cleanup` branch, normal temp files); error cases (missing folder, bad `--ioc-file`: exit 2; small `init.js`: one `REVIEW`) |
| `scan_testmetest.py` on our analysis machine | 0 | **0** | About 52,000 files plus home and temp checks, `--git` on; under a second |
| `scan_testmetest.py` on 185 real npm packages | 0 | **2, then 0** | First run flagged bcrypt and sqlite3 `binding.gyp`, which use `<!(node -p "…")`. The check now needs a node script followed by `echo <file>.c` for `HIGH` |
| Tree sweep, clean public repository | 0 | **0** | Unauthenticated API call |
| Tree sweep, synthetic tree JSON | 3 paths + warning | **3 + warning** | `.github/init.js` (13,729,714), nested `.claude/settings.json`, `.cursor/rules/setup.mdc`; truncated tree prints the warning |
| `git ls-tree` loop, synthetic repository | 1 | **1** | Found on `main`, not on the branch where it was deleted. A first version of the `awk` line read the wrong column and found nothing; fixed |

**Totals:** 21/21 synthetic positives and 0/20 synthetic negatives across the two rules; 0 hits in the public datasets, none of which contain Node.js activity, so the 0 there is weak. 19/19 script tests; 0 false positives on real files after one fix.

## Known misses (by design)

- Payloads piped to `bun run -` (SafeDep and JFrog both describe this path): no file or script name appears on the command line.
- New builds that change the file names, paths, wrapper start or persistence names. Hashes change with every build.
- `node` binaries with other names (`node22`, Electron, single-executable applications).
- The native addon itself loading inside `node` during `npm install`: no new process is started until the drop is run.
- Credential theft and exfiltration over HTTPS; there is no network rule in this hunt (see the Alert for the published network indicators).

## Not tested

- **No real sample or telemetry.** All positives are synthetic.
- **macOS and Windows** runs of `scan_testmetest.py`. The code uses only portable standard-library calls, but the Windows temp-folder and macOS Launch Agent checks have only been exercised with Linux paths standing in.
- **KQL, SPL and ES|QL execution** in a real engine (conversion only). In particular, ES|QL `rlike` uses Lucene regular expressions anchored to the whole value; the patterns were written for that but not run in Elastic. Whether `DeviceFileEvents.FolderPath` carries the file name for every Linux and macOS sensor has not been checked.
- **Authenticated GitHub sweeps** across an organisation, including rate limits and very large repositories (trees over the API's size limit are truncated; the command warns).
- **Production noise**, especially on developer machines and CI runners.
