# Sources for 2026-10-26-node2shell-brotli

All sources checked on 26 October 2026 (Europe/London).

| Claim | Source |
|---|---|
| Brotli decoder out-of-bounds write; crash, memory disclosure or remote code execution via `node:zlib`; rated High; fixed in 22.23.4, 24.22.1 and 26.12.1; end-of-life lines affected | [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |
| Brotli 1.0.3 to 1.2.0 affected; CNA Google; CVSS 4.0 9.2 | [NVD CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497) |
| Not in KEV | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), JSON feed catalogVersion 2026.10.23 |
| Code execution on official Node.js 24.22.0 Linux arm64 via `fetch()` and Express 5 / body-parser 2; not every attempt; bare HTTP server does not decode request bodies by receiving them | [Imperva: Node2Shell](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/) |
| Bun 1.4.4 fixed, bundles Brotli 1.2.1 | [Bun blog v1.4.4](https://bun.com/blog/bun-v1.4.4); `brotli.ts` at tag bun-v1.4.4 pins v1.2.1 |
| Imperva has not made its exploit public; first public PoC reached code execution only against a deliberately weakened build | [SecurityWeek](https://www.securityweek.com/node2shell-brotli-flaw-triggers-patching-across-microsoft-node-js-python-packages/), Eduard Kovacs, 26 Oct 2026 |
| Public PoCs crash unpatched Node.js 20, 22, 24 and 26 (SIGSEGV, exit 139) | Editorial review of two public GitHub labs, 26 Oct 2026; repositories deliberately not linked |
| Debian/Ubuntu Node.js link the system libbrotli; Debian brotli fixed 1.0.9-2+deb12u1 (DLA-4855-1), 1.1.0-2+deb13u1 (DSA-6582-1), sid 1.2.0-4.1; Ubuntu nodejs "uses system brotli", no fixed brotli package yet | [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497); [Ubuntu CVE page](https://ubuntu.com/security/CVE-2026-111497) |
| npm/npx on Linux rewrite the process title to `npm run <script>` / `npm exec`; yarn 1 and pnpm 9 local installs run as `node …/node_modules/.bin/yarn` or `…/.bin/pnpm`; pnpm 12 ships a native binary | Observed on the analysis box, 26 Oct 2026 (see EVIDENCE.md) |
| Python `brotli` 1.2.1 and `brotlicffi` 1.2.1.0 fixed | [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) |
| .NET fixed runtimes 8.0.33, 9.0.22, 10.0.14 | [dotnet/announcements#494](https://github.com/dotnet/announcements/issues/494) |
| ATT&CK techniques | [T1190](https://attack.mitre.org/techniques/T1190/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1499.004](https://attack.mitre.org/techniques/T1499/004/) |
| Parent/child web-shell pattern | [SigmaHQ Linux web shell detection](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml); our 2026-10-22 PHP hunt |
| Test data | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0); [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT) |
| Crash signals (segfault lines, exit codes 139/134, Windows event 1000), the one-minute correlation window, and the rarity of Brotli request bodies | Our own inference and general operating knowledge; not from a vendor |

## Not verified / not used

- No specific campaign or threat actor is claimed. No exploitation in the wild has been reported.
- No IOCs.
- No exploit or proof of concept was obtained or run.
