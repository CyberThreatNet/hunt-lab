# GitLab CI regex unauthenticated RCE hunt (CVE-2026-97229)

> **Status banner:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-10-30-gitlab-ci-regex-rce` |
| **Date** | 30 October 2026 |
| **Status** | Experimental |
| **Platforms** | Linux GitLab host telemetry / syslog; web access logs; Microsoft Defender XDR / Sentinel (KQL); Splunk |
| **ATT&CK** | T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter) |
| **CVEs** | CVE-2026-97229. KEV and EPSS are in [`cve-context.yaml`](cve-context.yaml) |
| **Files** | `query.kql` (MIT), `query.spl` (MIT), `rule-gitlab-spawns-shell.yml` + `rule-cilint-unauth.yml` + `rule-hostile-ci-regex.yml` (Sigma, DRL 1.1) |

## Hypothesis

An attacker probing or exploiting CVE-2026-97229 against a self-managed GitLab instance leaves at least one of: (1) access to CI Lint or GraphQL `ciLint` without a trusted session; (2) a shell or download tool spawned by a GitLab Ruby/Puma/Sidekiq/workhorse worker; (3) writes of `.gitlab-ci.yml` around the same window. Alpine Linux reported eight worker crashes from crafted CI configurations during an attempted exploit.

## Threat context

- GitLab (12 October 2026): CVE-2026-97229, integer overflow in CI/CD regex compiler allowing unauthenticated RCE via crafted regex. Fixed in 19.2.8, 19.3.5, 19.4.2 (CE/EE 19.2/19.3/19.4 lines). Root cause in Ruby Onigmo. https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/
- Ruby (23 October 2026): regexp engine fixes in 3.3.13, 3.4.12, 4.0.9. https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves
- CISA KEV dateAdded 2026-10-29, due 2026-11-01, forensic triage Yes. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Alpine Linux (28 October 2026): attempted exploit; eight worker crashes. https://alpinelinux.org/posts/GitLab-security-incident-CVE-2026-97229.html

**IOCs:** None published by the vendors above for this CVE. Prefer behavioural detections. Defang any indicators that appear later in tickets.

## Data sources and tables

| Query | Data source | Requirement |
|---|---|---|
| `query.kql` | DeviceProcessEvents / DeviceFileEvents / DeviceNetworkEvents | GitLab host process, file and (where available) URL telemetry |
| `rule-gitlab-spawns-shell.yml` | Sigma process_creation / linux | Parent under `/opt/gitlab/embedded/bin` or GitLab workhorse; child shell or download tool |
| `rule-cilint-unauth.yml` | Sigma webserver | Reverse-proxy or GitLab access logs covering `/ci/lint`, `/api/v4/ci/lint`, `/api/graphql` |
| `rule-hostile-ci-regex.yml` | Sigma file_event / linux | Creates or modifications of `.gitlab-ci.yml` (content review required) |
| `query.spl` | linux / gitlab / nginx / access sourcetypes | Splunk Add-on for Unix/Linux, GitLab or web access logs |

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1190 | Exploit Public-Facing Application |
| T1059 | Command and Scripting Interpreter |

## Tuning and false positives

- GitLab backup, upgrade or rake tasks that shell out — join to change windows.
- Custom GitLab hooks that intentionally invoke curl or a shell — baseline known hook paths and authors.
- Authenticated developers using CI Lint — join web hits to session or user ID; keep unauthenticated hits as high priority.
- Legitimate `.gitlab-ci.yml` edits — the file rule is low severity by design; always review content.
- Expected volume: near-zero unauthenticated CI Lint from the internet on locked-down instances; any shell spawn from a GitLab worker warrants patch verification and forensic collection (KEV triage flag).

## Validation notes

- Draft only. sigma-cli / conversion runs in CI on the PR.
- Test plan (isolated lab you own): (1) hit CI Lint while signed out and confirm the web rule fires; (2) never replay a CVE-2026-97229 exploit against production; (3) after upgrade to 19.2.8 / 19.3.5 / 19.4.2, re-baseline worker child-process noise.

## Rule IDs

- `rule-gitlab-spawns-shell.yml`: `7b9b1f6d-3079-4ddc-b6a9-14478f0e0626`
- `rule-cilint-unauth.yml`: `7f7a3a13-e2ba-4e2d-90ff-cf5847c88c87`
- `rule-hostile-ci-regex.yml`: `254ce2ec-7003-4187-8036-7116db318c8c`

## Credits and licence

- Author: Cyber-Threat.net Hunt Lab
- Sigma rules: [DRL 1.1](../../../../LICENSE-DRL). `query.kql`, `query.spl` and this README: [MIT](../../../../LICENSE).
