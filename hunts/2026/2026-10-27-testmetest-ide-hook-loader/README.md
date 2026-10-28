# testmetest npm worm: .github/init.js loaders started by IDE and AI-assistant hooks, native-addon drops and persistence

Full write-up: [testmetest npm worm: GitHub init.js hooks](https://cyber-threat.net/testmetest-npm-worm-github-init-js-hooks/) on Cyber-Threat.net.

> **Draft for review: partly tested.** Both Sigma rules matched all their synthetic positive events (10/10 process, 11/11 file) and none of their synthetic negatives (0/13, 0/7), and produced no hits in the public Windows datasets (which contain no Node.js activity, so this proves only that they are quiet there). The file-search script passed 19 offline tests on synthetic fixtures and reported nothing on our analysis machine's own folders or on a fresh `npm install` of 185 real packages, once a false positive found in that run (bcrypt and sqlite3 `binding.gyp`) was fixed. It has only been run on Linux. No real infection telemetry or sample was used. See [Validation notes](#validation-notes).

| | |
|---|---|
| **Hunt ID** | `2026-10-27-testmetest-ide-hook-loader` |
| **Date** | 27 October 2026 |
| **Status** | Test (Sigma rules and script tested on synthetic data; conversions clean, not engine-tested). The GitHub repository sweep commands are tested only against a clean public repository and synthetic input |
| **Platforms** | Developer workstations (Linux, macOS, Windows) and CI runners that install npm packages or open cloned repositories in Claude Code, Gemini CLI, Cursor or VS Code; GitHub organisations. Sigma `process_creation` and `file_event` with no `product` |
| **ATT&CK** | T1195.002, T1059.007, T1543.002, T1543.001, T1027, T1485 (rules); T1552.001, T1567.001, T1497.001 (context only) |
| **CVEs** | None |
| **Files** | [`rule.yml`](rule.yml) (Sigma, process creation, DRL 1.1), [`rule-persistence.yml`](rule-persistence.yml) (Sigma, file events, DRL 1.1), [`ci-targets.txt`](ci-targets.txt), [`scan_testmetest.py`](scan_testmetest.py) and [`tests/`](tests/) (MIT), [`sources.md`](sources.md), [`EVIDENCE.md`](EVIDENCE.md) |

## Hypothesis

If a developer or CI runner installed a testmetest-campaign package, or opened a repository the campaign armed, then we expect to see one or more of: `node` or `bun` running `.github/init.js` straight after a coding tool opens a folder; `node` running a hidden temp file (`/tmp/.<pid>` on Linux, `%TEMP%\.nc<pid>.js` on Windows) during `npm install`; or the `net-health-checker` and `pkg-runtime` persistence files and services appearing in the user's home folder. In GitHub, armed repositories carry an oversized `.github/init.js` (about 13 MB) and hook files that run it.

## Threat context

What is **reported** (see [`sources.md`](sources.md)):

- **The npm side.** SafeDep reported 18 packages from one operator published between 19 and 25 October 2026 under the npm accounts `alexjoipamiba`, `testnewtestme` and `iobandamwer`; JFrog's reconciled inventory lists 25 package names, of which 14 have versions JFrog classes as malicious. Earlier releases (19–22 October) used a `binding.gyp` command-expansion trigger; the 24–25 October `@iobandamwer` builds ship a native addon (`addon.node`, `addon_win.node`) that decrypts a hidden `.napi_cache` payload from `postinstall`. The addon writes the next stage to `/tmp/.<pid>` or `%TEMP%\.nc<pid>.js` and runs it with `node`. JFrog found no code that deletes that file, so it may still be there.
- **What it does.** Steals SSH, npm, PyPI, Git, cloud, Vault and Kubernetes credentials, browser data and AI coding-assistant tokens; exfiltrates to a new GitHub repository in the victim's account (falling back to a web endpoint); and republishes itself with stolen registry tokens. SafeDep reports it exits on CIS-region locales and tries to stop Harden-Runner.
- **The GitHub side.** JFrog found 42 third-party repositories across 11 legitimate owners carrying `.github/init.js` wrappers of 12.9 to 13.7 MB, started by planted hooks such as a Claude Code `SessionStart` hook running `node .github/init.js || bun .github/init.js`, plus equivalents in `.gemini/settings.json`, `.cursor/mcp.json`, `.cursor/rules/setup.mdc` and `.vscode/tasks.json` (and sometimes `package.json`, `composer.json` or a `Makefile`). JFrog decoded the wrappers to a hidden npm-publishing payload that harvests tokens and publishes packages, not the full worm with its wiper; check for the worm's persistence anyway before revoking anything. JFrog notes the wrappers looked empty through GitHub code search and the contents API; the Git tree and blob APIs showed the real size.
- **Persistence and the wiper.** SafeDep reports two persistence units. `net-health-checker` checks the stolen GitHub token every 45 seconds for 48 hours and deletes the home folder if the token stops working (HTTP 401 or 403). `pkg-runtime` runs `sync.py` hourly to look for signed commands. **Remove persistence before revoking tokens.**
- **Advisory IDs.** OSV lists 12 malicious-package IDs for JFrog's 14 packages: MAL-2026-18177, -18178, -18179, -18180, -18181, -18182, -18185, -18186, -18292, -18329, -18330 and -18333 (checked 27 October 2026); none was found for `npm-publish-testmetest` or `retry-utils-testmetest`. The GitHub advisory GHSA-m6qq-33mj-mv9w (in OSV as MAL-2026-18202) flags `sdk-utils-testmetest`, for which JFrog lists no malicious release, so SCA alerts on that name are expected.
- **Attribution.** SafeDep describes it as a Miasma-family variant while noting that it has not confirmed the lineage. JFrog calls it a Shai-Hulud-descended payload and says its evidence does not establish that the original Miasma operators are responsible. Neither firm names an actor.

Indicators below are used **only** where a cited source published them. Hashes change with every build (SafeDep), so absence of a hash match means little.

## Hunts

### 1. node or bun running the loader, the temp drop or the persistence (Sigma `rule.yml`, tested)

Process creation where the image ends in `node`, `nodejs`, `bun`, `node.exe` or `bun.exe` and the command line contains `.github/init.js` (either slash), runs `/tmp/.<digits>` or `\.nc<digits>.js`, or runs `index.js` from a `/.b-*` folder; or any process whose command line names `net-health-checker`, `.local/share/runtimes/sync.py` or `com.user.pkg-runtime`.

### 2. Persistence and payload files created (Sigma `rule-persistence.yml`, tested)

File creation of `~/.local/bin/net-health-checker.sh`, anything under `~/.config/net-health-checker/`, `~/.local/share/runtimes/sync.py`, the `net-health-checker` and `pkg-runtime` systemd user units and macOS Launch Agents, `/var/tmp/.fontconfig_state`, any `.napi_cache` file, and `%TEMP%\.nc<digits>.js`. CI checks this file but converts only `rule.yml`; local conversions are in [`EVIDENCE.md`](EVIDENCE.md).

### 3. File search on a workstation or runner (`scan_testmetest.py`, tested on Linux)

Python 3.8 or later, standard library only. **Read-only:** it never runs, imports, edits or deletes what it finds, and makes no network calls. Run it **from a terminal, before** opening a suspect folder in an IDE or AI assistant.

```bash
python3 scan_testmetest.py ~/src ~/work            # project folders + home persistence + temp folders
python3 scan_testmetest.py --git ~/src             # also branches, commit messages and history (read-only git)
python3 scan_testmetest.py --no-host ./repo --json # one folder only, JSON output
```

It reports `HIGH` or `REVIEW` findings for: `.github/init.js` (HIGH over 12 MB, the size of every published wrapper) and `.github/init.ps1`; the published wrapper start (`var _r = 0, _s = 1, _t = 2`); hook files listed above that reference `.github/init.js` or `init.ps1`; `package.json` and lockfiles naming campaign packages; installed campaign packages under `node_modules` (marking JFrog's malicious versions); `.napi_cache` files; a `binding.gyp` that runs a node script and then echoes a stub C file name; published SHA-256 values (full values from SafeDep and JFrog, and JFrog's 8-character prefixes for the `init.js` wrappers); the persistence paths; `/tmp/.<digits>`, `/tmp/.hc`, `/tmp/.svc`, `.b-*` folders and `%TEMP%\.nc<digits>.js`. With `--git` it also flags `chore/ci-<hex>` and `deps/upd-<digits>` branches, commit messages containing `AutoSyncComplete:`, `msync-3f7a` or `shellpanel execution smoke` (HIGH) or `skip-checks:true` (REVIEW), and `.github/init.js` anywhere in history. Exit code 0 means nothing found, 1 means findings, 2 means an error. `--ioc-file` adds your own hashes.

Run the tests with `python3 tests/test_scan_testmetest.py` (offline; fixtures are synthetic and built at run time).

### 4. GitHub organisation sweep (commands, partly tested)

Code search and the contents API can miss the wrappers (JFrog). List each repository's Git tree instead. With the GitHub CLI, per repository:

```bash
gh api "repos/OWNER/REPO/git/trees/HEAD?recursive=1" --jq '.truncated as $t
  | (.tree[] | select(.type=="blob")
     | select(.path|test("(^|/)\\.github/init\\.(js|ps1)$|(^|/)\\.claude/settings(\\.local)?\\.json$|(^|/)\\.gemini/settings\\.json$|(^|/)\\.cursor/(mcp\\.json|rules/.*\\.mdc)$|(^|/)\\.vscode/tasks\\.json$|(^|/)(CLAUDE|AGENTS)\\.md$"))
     | "\(.size)\t\(.path)"),
    (if $t then "WARNING: tree truncated, clone the repository instead" else empty end)'
```

A `.github/init.js` over 12,000,000 bytes is the strongest signal; hook files are normal in many projects, so open them and look for `init.js`. This checks the default branch only. For every branch of a cloned repository (mirror-clone it; do not open it in an editor):

```bash
git for-each-ref --format='%(refname)' refs/heads refs/remotes refs/tags | while read -r ref; do
  git ls-tree -r -l "$ref" | awk -F'\t' -v r="$ref" '$2 ~ /(^|\/)\.github\/init\.(js|ps1)$/ {split($1,a," "); print r"\t"$2"\t"a[4]" bytes"}'
done
```

Also look for branches named `chore/ci-<hex>` or `deps/upd-<digits>`, commits with `skip-checks:true`, and, in any account an affected identity can reach, new repositories with the description `project-utils` (SafeDep) or files `data/snap-<timestamp>-<n>.json` (JFrog).

## Data sources and tables

| Hunt | Data source | Requirement |
|---|---|---|
| 1 (`rule.yml`) | Sigma `process_creation` | Sysmon event 1 (Windows or Linux), Security 4688 with command line, Endpoint Security or EDR process telemetry on macOS |
| 2 (`rule-persistence.yml`) | Sigma `file_event` | Sysmon event 11, Sysmon for Linux file create, EDR file telemetry. Home-folder coverage on Linux and macOS is often missing by default |
| 1, 2 (converted) | `DeviceProcessEvents` / `DeviceFileEvents` (Defender XDR), ASIM `imProcessCreate` / `imFileEvent` (Sentinel), Splunk, ES\|QL | Conversion only; not run in an engine |
| 3 | Local file system and git | Python 3.8+, optional `git` |
| 4 | GitHub Git trees API, local clones | `gh` or any HTTP client; unauthenticated calls are rate-limited |

## ATT&CK mapping

| ID | Technique | Where |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hunts 1, 3, 4 |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Hunt 1 |
| T1543.002 | Create or Modify System Process: Systemd Service | Hunts 1 to 3 |
| T1543.001 | Create or Modify System Process: Launch Agent | Hunts 1 to 3 |
| T1027 | Obfuscated Files or Information | Hunts 2, 3 (`.napi_cache`, wrappers) |
| T1485 | Data Destruction | Hunt 2 (the watchdog that wipes the home folder) |
| T1552.001 | Unsecured Credentials: Credentials In Files | Context only |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Context; hunt 4 |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Context only |

The rules are tagged against ATT&CK as loaded by pySigma on 27 October 2026 (v20), where T1027 sits under `stealth`. The IDE and AI-assistant hooks have no exact ATT&CK technique; we have mapped the resulting execution to T1059.007 rather than force a fit.

## Tuning and false positives

- `.github/init.js` run by node is rare in real projects, but not impossible. Check the file's size and git history before escalating.
- `/tmp/.<digits>`: the rule drops command lines where the digits run straight into other characters (for example `/tmp/.12ab/x.js`). Other software using a pure-digit hidden temp file will still match.
- `selection_persistence` matches any process naming the persistence, including responders running `systemctl` or `launchctl` to clean up. Expect hits during remediation.
- The script's `binding.gyp` check ignores the common `<!(node -p ...)` and `<!(node -e ...)` forms used by bcrypt, sqlite3 and node-addon-api. A `binding.gyp` that runs a `.js` file without the stub-echo pattern is `REVIEW` only.
- `skip-checks:true` is a legitimate GitHub feature; the script reports it as `REVIEW`.
- ES|QL `like` and `ends_with` are case-sensitive; `rlike` matches the whole string, which is why the regular expressions start with `.*`.
- ES|QL compares `event.category` and `event.type` as single values. Elastic documents that `==` returns null when a field holds more than one value, and that functions do the same unless documented otherwise, so an event whose `event.type` holds two values would be dropped. Sysmon event 11 and Defend's sample file event each carry one value, so we don't expect this to bite, but it hasn't been run in Elastic. EQL and Lucene match if any value matches.
- On macOS, Elastic Defend documents no file-creation event, so the LaunchAgents paths match only on modification or rename events. Defend's `launch_daemon` events, which carry the path in `Persistence.path` rather than `file.path`, aren't covered.

## Validation notes

Full commands and results are in [`EVIDENCE.md`](EVIDENCE.md). Summary (27 October 2026):

| Check | Result |
|---|---|
| `sigma check` over `hunts/` (sigma-cli 3.1.0, pySigma 1.5.1) | 0 errors, 0 condition errors, 0 issues |
| Conversions in `ci-targets.txt` (4 targets; CI runs every target for both `rule.yml` and `rule-persistence.yml`) | All clean; Elastic output uses `file.path` |
| Synthetic events (Zircolite 4.7.0) | `rule.yml` **10/10** positives, **0/13** negatives. `rule-persistence.yml` **11/11** positives, **0/7** negatives |
| EVTX-ATTACK-SAMPLES (chainsaw 2.17.1) | **0** hits for both rules; mutated copies gave 329 and 24 hits, so chainsaw does evaluate them |
| OTRF atomic files and APT29 day 1 + day 2 (Zircolite) | **0** hits (see EVIDENCE.md) |
| `scan_testmetest.py` | 19/19 offline tests pass (positive, negative and error cases); 0 findings on about 52,000 files on our analysis machine and on a fresh install of 185 npm packages after one false-positive fix |
| GitHub tree sweep | Returned no matches on a clean public repository; `jq` filter returned the expected paths on synthetic tree JSON; the `git ls-tree` loop found a synthetic 13 MB `.github/init.js` on one branch and not on another |

**Limits of the test:** no real sample, infected host or armed repository was used, and none should be fetched to test this. The positives are events and files we wrote from the published descriptions. The script has not been run on macOS or Windows. The converted queries have not been run in Defender XDR, Sentinel, Splunk or Elastic. Process command lines on Linux depend on your collector.

## Credits and licence

- Written by the Cyber-Threat.net Hunt Lab from the public research of JFrog Security Research and SafeDep (see [`sources.md`](sources.md)).
- `rule.yml` and `rule-persistence.yml`: [DRL 1.1](../../../LICENSE-DRL). This README, `scan_testmetest.py` and `tests/`: [MIT](../../../LICENSE).
- Test data: EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0); OTRF Security-Datasets by Roberto Rodriguez / OTRF (MIT), including the compound APT29 day 1 and day 2 datasets.

Provided as-is, without warranty. Test and tune before production use.
