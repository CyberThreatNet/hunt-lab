# Sources for 2026-10-27-testmetest-ide-hook-loader

All sources checked on 27 October 2026 (Europe/London).

| Claim | Source |
|---|---|
| 42 armed repositories across 11 owners; wrappers decode to a hidden CI/npm-publisher payload (not the full worm); `.github/init.js` wrappers 12.9 to 13.7 MB and their SHA-256 prefixes; wrapper start `var _r = 0, _s = 1, _t = 2`; `SessionStart` hook `node .github/init.js \|\| bun .github/init.js`; hook files in `.claude`, `.gemini`, `.cursor`, `.vscode`, `package.json`, `composer.json`, `Makefile`; wrappers looked empty via code search and the contents API | [JFrog Security Research: Beyond testmetest](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/), Guy Korolevski and Yair Benamou, 26 Oct 2026 |
| Native addon decrypts `.napi_cache`, drops `/tmp/.<pid>` (Linux) or `%TEMP%\.nc<PID>.js` (Windows) and `/tmp/.hc`, no deletion code found; `binding.gyp` command expansion; `.b-*` temp folder; package inventory (25 names) and malicious versions; `chore/ci-<hex>` and `deps/upd-<digits>` branches; `skip-checks:true`; `data/snap-<timestamp>-<n>.json`; `shellpanel execution smoke`; `/tmp/.svc`; decoded payload hashes; remove persistence before revoking the token; enumerate Git trees | Same JFrog report |
| 18 packages, 19 to 25 Oct; `binding.gyp` trigger until 22 Oct, then (24–25 Oct, `iobandamwer`) a `postinstall` native addon; accounts `alexjoipamiba`, `testnewtestme`, `iobandamwer`; `binding.gyp` trigger; `index.js` writes `/tmp/.b-*/index.js` and runs it with `bun run`; addon writes `/tmp/.<pid>` and runs it with `node`; credential theft list; exits on CIS locales, stops Harden-Runner; victim exfiltration repository with description `project-utils`, `AutoSyncComplete:` commits; `net-health-checker` (45 s checks for 48 h, wipes home on 401/403) and `pkg-runtime` (`sync.py` hourly, `msync-3f7a`); persistence paths, systemd user units and Launch Agents; on-disk SHA-256 values; hashes change per build; detection ideas (`binding.gyp` with `<!(node`, high-entropy `.napi_cache`) | [SafeDep: testmetest npm worm](https://safedep.io/testmetest-npm-worm-miasma-variant), Kunal Singh, 22 Oct 2026, updated 26 Oct 2026 |
| Holding (`0.0.1-security`) packages and unpublished names | npm registry JSON for each package name, fetched 27 Oct 2026 |
| SafeDep: Miasma-family variant, lineage not confirmed. JFrog: Shai-Hulud-descended payload; evidence does not establish the original Miasma operators are responsible; label "testmetest campaign". Neither names an actor | SafeDep and JFrog, above |
| ATT&CK techniques and tactic names | [T1195.002](https://attack.mitre.org/techniques/T1195/002/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1543.002](https://attack.mitre.org/techniques/T1543/002/), [T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1567.001](https://attack.mitre.org/techniques/T1567/001/), [T1497.001](https://attack.mitre.org/techniques/T1497/001/); tactic names from pySigma's ATT&CK data (v20) |
| GitHub Git trees API (`recursive`, `truncated`) | [GitHub REST API: Git trees](https://docs.github.com/en/rest/git/trees) |
| Test data | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0); [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT) |
| 12 MB size threshold; the `filter_drop_not_pid` logic; which hook files to search; `HIGH` versus `REVIEW` levels | Our own choices, based on the sources above |

## Not verified / not used

- No sample was obtained or run. Hashes are copied from the reports, not computed by us.
- JFrog gives the wrapper size range as both "12.9 to 13.7 MB" and "12.3 to 13.1 MB" (probably decimal versus binary megabytes); the published byte counts (12,964,907 to 13,730,579) are what we used.
- JFrog's inventory lists `path-stream-utils-testmetest` twice; we used the row that names malicious versions 0.0.1 and 0.0.2.
- Secondary reports (The Register, Rafter, Corgea, OSV MAL-2026-18292, GitHub advisories) were read for context only; no claim here rests on them.
- Network indicators (C2 address, exfiltration domain, download URL) are not used in these rules; they are in the Cyber-Threat.net Alert, defanged.
- No threat actor is named.
