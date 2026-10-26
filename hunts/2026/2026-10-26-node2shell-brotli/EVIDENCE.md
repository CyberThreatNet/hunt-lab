# Test evidence: 2026-10-26-node2shell-brotli

Run on 26 October 2026, between about 12:30 and 13:10 GMT (Europe/London); filters revised and every check below re-run between about 13:10 and 13:30 GMT after editorial review, on an isolated Linux analysis box. Free, open-source tools only. Raw tool outputs and the synthetic test events are kept privately and are not published. Tool and dataset versions as in the 2026-10-25 hunts: sigma-cli 3.1.0 / pySigma 1.5.1 (backends kusto 1.0.1, splunk 2.1.0, elasticsearch 2.1.1), chainsaw 2.17.1, Zircolite 4.7.0 git a5d868b; EVTX-ATTACK-SAMPLES commit 4ceed2f; OTRF Security-Datasets master as of 25 Oct 2026.

## Commands

```bash
sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename rule.yml
# Found 0 errors, 0 condition errors and 0 issues.

# Every line of ci-targets.txt, run from the repository root as the CI step does:
sigma convert -t kusto  -p microsoft_xdr  rule.yml   # clean -> DeviceProcessEvents
sigma convert -t kusto  -p sentinel_asim  rule.yml   # clean -> imProcessCreate
sigma convert -t splunk --without-pipeline rule.yml  # clean
sigma convert -t esql   -p pipelines/ecs-process-creation.yml rule.yml   # clean -> process.parent.executable etc.
# Not declared: -p splunk_windows (no Windows mapping for a rule with no product; output identical to --without-pipeline)
#               -p splunk_cim ("Rule type not yet supported by the Splunk data model CIM pipeline", needs product windows)
#               -p azure_monitor (no ParentCommandLine field for SecurityEvent)

# Real package-manager parent command lines, captured on the analysis box (Debian, node 20.19.2) by printing
# /proc/$PPID/cmdline from a package.json script: npm 9 "npm run go", npx "npm exec" (npm rewrites its process
# title; parent image /usr/bin/node, child /usr/bin/dash); yarn 1.22.22 "node <project>/node_modules/.bin/yarn go";
# pnpm 9 "node <project>/node_modules/.bin/pnpm go". pnpm 12 runs as a native binary, so its parent is not node.

# Synthetic positives and negatives (JSON lines, Sysmon-style field names)
zircolite.py -e <data-dir>/synthetic -f json -j -r rule.yml -o <output-dir>/zircolite-synthetic.json

# Public background data
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s rule.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -o <output-dir>/chainsaw.json
zircolite.py -e <data-dir>/mordor -f json -j -r rule.yml -o <output-dir>/zircolite-mordor.json
zircolite.py -e <data-dir>/apt29  -f json -j -r rule.yml -o <output-dir>/zircolite-apt29.json

# Engine check: the same rule with the node.exe parent swapped for cmd.exe
chainsaw hunt <data-dir>/EVTX-ATTACK-SAMPLES -s <output-dir>/mutated-rule.yml \
  --mapping <tools-dir>/chainsaw/mappings/sigma-event-logs-all.yml --json -o <output-dir>/chainsaw-mutated.json
```

## Results

| Dataset / file | Expected | Hits | Notes |
|---|---|---|---|
| Synthetic positives P1 to P7 | 7 | **7** | Linux `node` → `/bin/sh`; Linux `node` → `curl`; Linux `bun` → `bash`; Windows `node.exe` → `cmd.exe`; Windows `node.exe` → `powershell.exe`; Linux and Windows servers installed by pnpm (`node_modules/.pnpm/…/next start`) → shell, which the earlier bare `pnpm` filter hid |
| Synthetic negatives N1 to N18 | 0 | **0** | N1 to N6 as before (npm install script with `npm-cli.js` parent, which is realistic only for Windows or exec-time argv; pnpm build; `node` → `git`; `python3` → `sh`; Windows npm `run build`; `nodemon.exe`). Added after review: Linux `npm run build` and `npm exec foo` process titles; `node /usr/bin/npm run build` and `node /usr/local/bin/npx eslint .`; yarn 1 local (`.bin/yarn`) and global; pnpm 9 local (`.bin/pnpm`) and `pnpm.cjs`; yarn berry `.yarn/releases/yarn-4.5.0.cjs`; Windows npx (`npx-cli.js`), yarn (`yarn.js`) and pnpm (`pnpm.cjs`) |
| Same 25 synthetic events, rule as first drafted | | 9 | Matched P1 to P5 and **wrongly** N7 to N10 (all Linux npm/npx cases); missed P6 and P7. This is the bug the revision fixes |
| EVTX-ATTACK-SAMPLES, 278 files | 0 | **0** | Corpus has 1,491 Sysmon 1 and 42 Security 4688 events and no `node.exe` parent |
| EVTX-ATTACK-SAMPLES with the mutated rule (parent `cmd.exe`) | > 0 | **64** | Confirms chainsaw evaluates a `process_creation` rule with no `product`; not a test of the real rule. Re-run gives 64 for both the first-draft and revised filters; the 79 reported in the first draft came from a mutated copy that was not kept, so we no longer rely on that figure |
| OTRF atomic files (6 files, 21,151 events) | 0 | **0** | No `node.exe` parent |
| OTRF APT29 day 1 + day 2 (783,367 events) | 0 | **0** | About 2,000 process-creation events; no `node.exe` parent |

**Totals:** 7/7 synthetic positives, 0/18 synthetic negatives, 0 hits in about 3,600 real process-creation events. Because none of the real events involve Node.js, the 0 is a weak result: it shows the rule does not misfire on unrelated Windows activity, not that it is quiet where Node.js runs.

## Known misses (by design)

- Code that runs inside the Node.js process without starting a child process.
- Node.js embedded in other executables (Electron apps, single-executable applications, `pkg`-style binaries) and versioned binary names such as `node22`.
- Shells started through a second `node` process whose command line contains a filtered string (`npm-cli.js`, `/.bin/pnpm `, `corepack` and so on). Documented in the README.
- On Linux, a Node.js process that sets its own process title to something beginning `npm ` or `npx ` (as npm itself does) before starting a shell. The filter keys on that title. Documented in the README.
- Package managers started in ways the filter does not list (for example a custom wrapper script, or yarn berry run from a path other than `.yarn/releases/`) are **not** excluded and will show up as false positives rather than misses.

## Not tested

- **No real exploit telemetry.** No public exploit for CVE-2026-111497 exists that we would run, and none was run. The positives are synthetic events we wrote.
- **Linux process telemetry** from Sysmon for Linux, auditd or an EDR: only synthetic events, though the Linux npm, npx, yarn and pnpm parent command lines are copied from real processes on the analysis box. Whether your collector records the rewritten npm title or the original exec-time argv depends on the collector; the rule covers both forms. Field names such as `ParentImage` depend on your collector and pipeline.
- **Windows package-manager command lines** (N5, N16 to N18) are written from the standard npm `.cmd` shims, not captured from a Windows host.
- **Hunts 2 to 4** in the README (crashes, Brotli request bodies, inventory). Hunts 2 and 3 have no query in this folder. The inventory commands in hunt 4 were run once on the analysis box (Debian trixie, distribution Node.js 20.19.2 linked to the system libbrotli1 1.1.0-2+b7), where `process.versions.brotli` reports 1.1.0. Debian's fixed package (1.1.0-2+deb13u1) reports the same version, so on distribution builds the brotli package version is what to check.
- **KQL, SPL and ES|QL execution** in a real engine (conversion only). ES|QL `ends_with`, `starts_with` and `like` are case-sensitive, so Windows paths in Elastic data that differ in case from the rule (for example `\Node.exe`) will not match unless the fields are lowercased.
- **Production noise**, especially on developer and CI hosts.
