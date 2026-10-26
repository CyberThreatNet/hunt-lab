# Node2Shell (CVE-2026-111497): Node.js or Bun server processes spawning shells, plus crash and Brotli-request hunting notes

> **Draft for review: partly tested, not published.** The Sigma rule matched all 7 synthetic positive events and none of the 18 synthetic negatives (including real npm, npx, yarn and pnpm parent command lines from Linux), and produced no hits in the public Windows datasets (which contain no Node.js activity, so this proves only that it is quiet there, not that it is quiet in your estate). No real exploitation telemetry exists publicly. The crash and Brotli-request hunts below are hypotheses with data-source notes only. See [Validation notes](#validation-notes).

| | |
|---|---|
| **Hunt ID** | `2026-10-26-node2shell-brotli` |
| **Date** | 26 October 2026 |
| **Status** | Test (Sigma rule tested on synthetic and public datasets; conversions clean, not engine-tested). Hunts 2 to 4 are hypotheses only |
| **Platforms** | Linux and Windows servers and containers running Node.js or Bun. Sigma `category: process_creation` with no `product`, so it applies to Sysmon event 1 (Windows), Sysmon for Linux event 1, Security 4688 with command line, auditd-derived process events, or EDR process telemetry |
| **ATT&CK** | T1190, T1059 (.001, .003, .004), T1499.004 |
| **CVEs** | CVE-2026-111497 |
| **Files** | [`rule.yml`](rule.yml) (Sigma, DRL 1.1), [`ci-targets.txt`](ci-targets.txt), [`sources.md`](sources.md), [`EVIDENCE.md`](EVIDENCE.md) |

## Hypothesis

If an attacker gets code running inside a Node.js or Bun server by sending it malformed Brotli data (CVE-2026-111497), the most visible next step is the server process starting a shell, PowerShell or a download tool. Failed attempts are likely to crash the process instead, so unexpected Node.js crashes shortly after requests carrying `Content-Encoding: br` are also worth a look.

## Threat context

- CVE-2026-111497 is an out-of-bounds write in Google's Brotli decoder (1.0.3 to 1.2.0), bundled in Node.js, Bun, Python `brotli`/`brotlicffi`, .NET and others. Node.js says it can lead to "a crash, disclosure of process memory, or remote code execution". Fixed in official Node.js builds 22.23.4, 24.22.1 and 26.12.1, and in Bun 1.4.4. Distribution-packaged Node.js (Debian, Ubuntu) links the system Brotli library and is fixed by the distribution's brotli package instead (see hunt 4).
- **No in-the-wild exploitation has been reported** and it is not in CISA KEV (catalogue 2026.10.23). Imperva has shown code execution on the official Node.js 24.22.0 Linux arm64 image, through `fetch()` responses and Express 5 / body-parser 2 request bodies, not on every attempt; SecurityWeek reports Imperva has not made its exploit public. Public proofs of concept crash unpatched Node.js 20, 22, 24 and 26 (SIGSEGV, exit 139), which is why hunt 2 looks for crashes.
- **No IOCs.** The hunts are behaviour-based. The Sigma rule fires on any code execution inside a Node.js server process, whatever the cause, so it is also useful beyond this CVE.
- Patching is the fix. These hunts are for checking whether anything happened before you patched, and for catching it if you cannot patch yet.

## Hunts

### 1. Node.js or Bun server process spawning a shell or download tool (Sigma rule, tested)

`rule.yml` flags a parent image ending in `node`, `nodejs`, `bun`, `node.exe` or `bun.exe` that starts `sh`, `bash`, `dash`, `zsh`, `busybox`, `curl`, `wget`, `nc`, `ncat`, `socat`, `perl`, `python3` or `base64` (Linux), or `cmd.exe`, `powershell.exe`, `pwsh.exe`, `curl.exe`, `certutil.exe`, `bitsadmin.exe` or `mshta.exe` (Windows). It drops the package managers' own direct children (npm and npx by their Linux process title or entry point, the yarn and pnpm entry points, corepack) and native build tools (node-gyp, prebuild-install).

### 2. Node.js crashes on internet-facing hosts (hypothesis, not tested)

A failed exploit attempt is likely to kill the process. Look for:
- **Linux:** kernel `segfault` lines naming `node` or `bun` (`dmesg`, `/var/log/kern.log`, journald), auditd `ANOM_ABEND` records for `comm="node"`, systemd units for Node services restarting with `status=11/SEGV` or `status=6/ABRT`, and container restarts with exit code 139 (SIGSEGV) or 134 (SIGABRT).
- **Windows:** Application log event ID 1000 (Application Error) with faulting application `node.exe` or `bun.exe`, and Windows Error Reporting event 1001.
- **Correlate** each crash with the web or proxy log for that service in the preceding minute or so (our suggested window), looking for requests with `Content-Encoding: br`, or with the outbound fetches the service makes.

Crashes have many ordinary causes (out of memory, native add-ons). A crash on its own is not evidence of exploitation.

### 3. Brotli-encoded request bodies to Node.js services (hypothesis, not tested)

Legitimate clients rarely send Brotli-compressed request bodies. In reverse-proxy, load-balancer or WAF logs, look for requests to Node.js back ends whose **request** `Content-Encoding` header contains `br` (including stacked values such as `gzip, br`). Most proxies do not log request headers by default. You may need to add `Content-Encoding` to the log format (for example a custom log field in nginx, HAProxy, Envoy or your cloud load balancer) before this hunt is possible. Do not confuse this with `Accept-Encoding: br` or response `Content-Encoding`, which are normal.

### 4. Vulnerable-version inventory (hypothesis, commands tested on one box)

Not a detection, but the hunt is only meaningful once you know where unpatched runtimes are:

```bash
node -v                      # official builds: unpatched below 22.23.4 / 24.22.1 / 26.12.1, and all of 20.x and older
bun --version                # unpatched below 1.4.4
npm ls express body-parser   # Express 5 / body-parser 2 decode Brotli request bodies
pip show brotli brotlicffi   # PyPI wheels: unpatched below 1.2.1 / 1.2.1.0
dotnet --list-runtimes       # unpatched below 8.0.33 / 9.0.22 / 10.0.14
dpkg -l 'libbrotli*'         # Debian/Ubuntu system library (used by distribution nodejs and python3-brotlicffi)
```

**Official builds versus distribution builds.** For official Node.js builds (nodejs.org, the official Docker images, nvm and similar), the Node.js version is what matters. Node.js packaged by Linux distributions is different: Debian and Ubuntu build it against the system Brotli library, so the fix is the distribution's brotli package (Debian: 1.0.9-2+deb12u1 for bookworm via DLA-4855-1, 1.1.0-2+deb13u1 for trixie via DSA-6582-1, 1.2.0-4.1 in sid), followed by a restart of every Node.js process. On those builds neither `node -v` nor `process.versions.brotli` tells you whether you are patched (the fixed trixie package still reports 1.1.0); check the installed brotli package version instead. The same applies to distribution packages such as Debian's `python3-brotlicffi`. See the [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497) and [Ubuntu's CVE page](https://ubuntu.com/security/CVE-2026-111497); on 26 October Ubuntu had not yet published a fixed brotli package.

## Data sources and tables

| Hunt | Data source | Requirement |
|---|---|---|
| 1 (`rule.yml`) | Sigma `process_creation` | Sysmon event 1 (Windows or Linux), Security 4688 with command line, or EDR process telemetry with parent image and parent command line |
| 1 (converted) | `DeviceProcessEvents` (Defender XDR), ASIM `imProcessCreate` (Sentinel), Splunk, ES\|QL with the repo's ECS pipeline | Conversion only; not run in an engine |
| 2 | Kernel log, journald, auditd, container runtime events; Windows Application log (event 1000/1001) | Collection of those logs into your SIEM |
| 3 | Reverse proxy, load balancer or WAF access logs | Request `Content-Encoding` header logged |
| 4 | Host and image inventory, SBOMs, dependency scanners | n/a |

## ATT&CK mapping

| ID | Technique | Where |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Hunts 1 to 3 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Hunt 1 (Linux) |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Hunt 1 (Windows) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Hunt 1 (Windows) |
| T1499.004 | Endpoint Denial of Service: Application or System Exploitation | Hunt 2 |

T1499 is in the README only, not in the rule's tags, because the Sigma rule does not detect denial of service.

## How the logic works

- **Parent:** matched by path suffix, so `/usr/local/bin/node`, `/usr/bin/nodejs`, `~/.bun/bin/bun` and `C:\Program Files\nodejs\node.exe` all match. Versioned binary names (for example `node22`) and Node.js embedded in other executables (Electron apps, single-executable applications, packaged binaries) will **not** match. Add your own names if you run them.
- **Child:** shells, PowerShell and common download or scripting tools. `git`, `ffmpeg`, `convert` and similar tools that apps call for real work are deliberately left out.
- **Filters:** excluded when the parent is a package manager itself: a parent command line starting `npm ` or `npx ` (on Linux npm rewrites its process title to `npm run <script>` or `npm exec …`), or containing `/bin/npm `, `/bin/npx `, `npm-cli.js`, `npx-cli.js`, the pnpm entry points (`pnpm.cjs`, `/bin/pnpm `, `/.bin/pnpm `), the yarn entry points (`yarn.js`, `/bin/yarn `, `/.bin/yarn `, `.yarn/releases/yarn-`), `corepack` or `node-gyp`; or a child command line containing `node-gyp`, `prebuild-install` or `npm run `. These are install and build activity, not a running server. The filters are deliberately narrow: a server started *through* `npm start`, yarn or pnpm runs as its own `node` process (for example `npm start` → `sh -c node server.js` → `node server.js`), so shells spawned by the server itself are still matched, and so are servers installed under `node_modules/.pnpm/`. Three cautions. First, an attacker with code execution could start a second `node` process whose command line contains one of these strings and launch the shell from that, which the filter would hide. Second, on Linux npm rewrites its process title; the filter keys on that title, so an attacker-chosen process title could hide a shell from this rule. Third, package managers started in ways not listed (custom wrappers, other yarn berry paths) are not excluded and will show up as noise. On production servers that never install packages or run scripts at runtime, remove the filters for higher fidelity.
- **No product** in the logsource, so a single rule covers Linux and Windows. Some backends need `product: windows`; see `ci-targets.txt` for which conversions are declared.

## Tuning and false positives

- **Expect noise on developer machines and CI runners.** Test runners, bundlers, VS Code extensions and Electron apps start shells under `node` all day. Scope the hunt to production servers and containers first.
- **Apps that shell out on purpose:** image, PDF, git or media wrappers using `child_process`. Exclude by host plus exact child command line, never by parent alone.
- **Process managers:** pm2, nodemon and forever can start shells. Exclude by their command lines if they show up.
- **Other known noise:** the VS Code remote server (`~/.vscode-server/…/node`) spawns `bash`; test runners such as jest, vitest and mocha spawn `sh` for git; `python3` children are noisy on build hosts. Electron apps are a miss rather than a false positive, because their parent is not `node` (see above).
- **Elastic:** ES|QL `ends_with`, `starts_with` and `like` are case-sensitive. Windows image paths whose case differs from the rule (for example `\Node.exe`) will not match unless you lowercase the fields.
- **Later:** splitting into separate Linux and Windows rules would allow cleaner field mappings and per-platform tuning.
- **Expected volume on a production API server:** low. A hit on an internet-facing service that has never shelled out before deserves a look straight away.
- **Coverage gaps:** code that runs inside the Node.js process without starting a child (for example, reading files or opening network connections from JavaScript) is not caught. Pair this with network egress monitoring for your Node.js services.

## Validation notes

Full commands and results are in [`EVIDENCE.md`](EVIDENCE.md). Summary (26 October 2026):

| Check | Result |
|---|---|
| `sigma check` (sigma-cli 3.1.0, pySigma 1.5.1) | 0 errors, 0 condition errors, 0 issues |
| Conversions in `ci-targets.txt` (4 targets) | All clean. `splunk_cim` and `azure_monitor` fail and are not declared; `splunk_windows` is not declared because its output is identical to `--without-pipeline` for this rule (see `ci-targets.txt`) |
| Synthetic events, Linux and Windows (Zircolite 4.7.0) | **7/7** positives matched (including servers installed by pnpm); **0/18** negatives matched (real Linux npm/npx process titles, npm/npx/yarn/pnpm entry points on Linux and Windows, yarn berry, a non-listed child, a non-Node parent, `nodemon.exe`). The rule as first drafted fired on 4 of the Linux npm/npx negatives and missed both pnpm-installed servers |
| EVTX-ATTACK-SAMPLES, 278 files (chainsaw 2.17.1) | **0** hits. A mutated copy of the rule (parent `cmd.exe`) gave 64 hits, so chainsaw does evaluate this product-less rule |
| OTRF atomic files and APT29 day 1 + day 2 (Zircolite) | **0** hits |

**Limits of the test:** the events are synthetic (the Linux npm, npx, yarn and pnpm parent command lines are copied from real processes; the Windows ones are written from the standard npm shims). The positives are events we wrote, not telemetry from a real exploit or a real Node.js host. They show the logic matches the fields as intended, nothing more. None of the public datasets contain a `node.exe` parent, so "0 hits" there says nothing about noise in an estate that runs Node.js. No Linux process telemetry was tested apart from the synthetic events. Hunts 2 and 3 have not been tested at all. The converted queries have not been run in Defender XDR, Sentinel, Splunk or Elastic.

## Credits and licence

- Written by the Cyber-Threat.net Hunt Lab. The parent/child approach follows our [PHP web server hunt](../2026-10-22-php-web-server-spawning-shell/) and the common SigmaHQ web-shell pattern.
- `rule.yml`: [DRL 1.1](../../../LICENSE-DRL). This README: [MIT](../../../LICENSE).
- Test data: EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0); OTRF Security-Datasets by Roberto Rodriguez / OTRF (MIT), including the compound APT29 day 1 and day 2 datasets.

Provided as-is, without warranty. Test and tune before production use.
