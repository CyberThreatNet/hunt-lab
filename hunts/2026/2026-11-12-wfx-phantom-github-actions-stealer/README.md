# wfx (wfx-loot, WFX Phantom): GitHub Actions secret stealer, hunt and rotation checklist

> **Status:** Draft for review: untested in a live estate

| | |
|---|---|
| **Hunt ID** | `2026-11-12-wfx-phantom-github-actions-stealer` |
| **Date** | 12 November 2026 |
| **Status** | Experimental |
| **Platforms** | GitHub (repositories, Actions, organisation or enterprise audit log); GitHub-hosted and self-hosted runners; AWS CloudTrail; Microsoft Entra ID audit logs; GCP audit logs; HashiCorp Vault; developer machines that ran `npm install` |
| **ATT&CK** | T1078 Valid Accounts, T1195.002 Compromise Software Supply Chain, T1552.001 Credentials In Files, T1552.005 Cloud Instance Metadata API, T1003.007 Proc Filesystem, T1550.001 Application Access Token, T1078.004 Cloud Accounts, T1098.001 Additional Cloud Credentials, T1098 Account Manipulation, T1070 Indicator Removal, T1041 Exfiltration Over C2 Channel, T1567 Exfiltration Over Web Service |
| **CVEs** | None. The attacker uses stolen tokens, not a GitHub flaw |
| **Files** | `rule-wfx-aws-sessions.yml`, `rule-wfx-aws-open-trust-policy.yml`, `rule-wfx-github-run-deleted.yml`, `rule-wfx-runner-egress.yml` (Sigma, DRL 1.1); `wfx.yar` (DRL 1.1); `query.kql`, `find-run-gaps.sh`, `find-wfx-indicators.sh` (MIT); `sources.md`; `ci-targets.txt` |

## Hypothesis

An attacker holding a stolen GitHub token for a developer or bot account first opens a probe pull request titled `docs: dependency audit notes` from a `wfx-docs` branch, which adds `docs/wfx-audit.md`. Where the token can write and CI will run, the attacker then pushes a stealer of about 1,500 lines of shell in one of four forms: commit `ci: refresh build cache` (steps added to an existing workflow, or the script appended to a shell script CI already runs, such as `update.sh`); commit `chore: add dependency audit workflow` (a new `.github/workflows/build-audit-<6 chars>.yml` on a `chore/<8 chars>` branch); or commit `chore: add ci helper` (a hidden `.ci-<6 chars>.sh` plus an npm `postinstall`, `build` or `test` hook). As soon as the run starts, the attacker pushes `ci: restore` and sometimes `ci: cleanup`, then deletes the run and its logs. **A missing run number straight after one of those commits means the stealer probably ran.** If it ran, every secret, variable and cloud role the job could reach is stolen, and the attacker may have left AWS or Azure persistence that survives rotation.

## Threat context (as of 12 November 2026)

- **Start:** about 12:45 UTC on 10 November 2026 (Aikido); SafeDep's first malicious commit is 12:46 UTC. Still active on 12 November: StepSecurity saw new probes minutes before 07:40 UTC, and The Hacker News found probes opened between 05:04 and 05:38 UTC.
- **Scale (sources differ, see `sources.md`):** Aikido counts 4,837 compromised accounts opening probe PRs in 61,764 repositories (61,839 PRs by search), at least 1,806 repositories where the payload ran (the same post also says 1,835), and 10,431 probes reaching repositories through collaborator or organisation access. SafeDep counts 61,879 probes in 61,734 repositories from 4,833 accounts, and 8,093 repositories with malicious commits on public default branches between 12:46 UTC on 10 November and 04:36 UTC on 12 November. StepSecurity counts more than 63,000 probes at 07:40 UTC on 12 November. About nine in ten probes are still open.
- **What it takes:** all Actions secrets and variables (`toJSON(secrets)`, `toJSON(vars)`), `GITHUB_TOKEN`, OIDC and Actions runtime tokens, and the memory of `Runner.Worker` and `Runner.Listener` (decrypted secrets the workflow never named). It also takes credential files for AWS, Azure, GCP, Docker, Kubernetes, npm, PyPI, SSH and Vault, AI provider and coding-agent keys, a repository snapshot with recent history and artefacts, and on self-hosted runners, instance metadata credentials, Docker state and systemd units.
- **Persistence:** AWS sessions named `wfx-*`, `iam:CreateAccessKey` for IAM users, and role trust policies rewritten to `"Principal": {"AWS": "*"}`. In Azure, federated identity credentials named `wfx-ci-*` on app registrations. The code can also post forged `success` statuses under required check names. Aikido describes this as part of the run; StepSecurity and SafeDep found it switched off in every copy they examined.
- **Exfiltration:** HTTP POST to TCP 8080 `/exfil` on the servers below. From 01:10 UTC on 12 November, Telegram appears as a backup, and from about 05:30 UTC some copies use Telegram only, with no collection IP. **IP blocklists alone no longer stop it.**
- **Packages:** `digitalelvis/neuronai-studio` 3.14.3 (Packagist; `composer install` does not run it, but `npm install` inside the vendor folder does; pin 3.14.2 or earlier). Go `github.com/onuragtas/docker-env` (also served as `github.com/onuragtas/redock`) v1.0.278 and v1.0.280, plus v1.0.282 per SafeDep. Go `github.com/vkuznet/gocurl` pseudo-version `v0.0.0-20261111095532-8d5aad0cb0da` per SafeDep and StepSecurity. The Go copies are in workflow files only, and Go builds do not run them.
- **Links:** Aikido and StepSecurity both see overlap with October's GhostAction victims (see `../2026-10-31-ghostaction-gheist/`). Aikido does not attribute the two waves to the same actor.

## Indicators (defanged)

| Type | Indicator |
|---|---|
| PR title | `docs: dependency audit notes` (body `Routine dependency audit notes`; file `docs/wfx-audit.md`) |
| Branches | `wfx-docs`, `chore/[a-z0-9]{8}`, `ci-check-[0-9]{4}` (SafeDep notes the last two come from an outside report and were not in its samples) |
| Commits | `ci: refresh build cache`, `chore: add ci helper`, `chore: add dependency audit workflow`, `chore: initial commit` (empty repositories), `ci: restore`, `ci: cleanup` |
| Files | `.ci-<6 chars>.sh`, `.github/workflows/build-audit-<6 chars>.yml` (workflow name `Dependency Audit <4 chars>`), injected steps `Pass runtime` and `Restore cache <4 chars>` |
| Collection servers | `194.150.166[.]244:8080/exfil`, `18.143.168[.]96:8080/exfil`, `153.75.82[.]159:8080/exfil` |
| Telegram | `api.telegram[.]org` `sendDocument`, chat `-1004340163187` (StepSecurity) |
| Callback token | `b42d70a7aab9140ca19e8249` (`WF_CTOKEN` in Aikido and SafeDep samples) |
| Stealer SHA-256 | `89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf` (Aikido; copies vary) |
| Cloud | AWS session names `wfx-*`; Entra federated credentials `wfx-ci-*`; artefacts `wfx-loot-*`, cache entries `wfx-*`, step summaries between `WFX-BEGIN` markers (these channels were switched off in the copies examined, so their absence proves nothing) |
| GitHub App | 173 probe PRs from 19 accounts were made through the Fly.io GitHub App (`fly-io`, app ID 34557) using user-to-server tokens (StepSecurity). There is no evidence of a breach at Fly.io |

## Hunts

| File | Data source | What it finds |
|---|---|---|
| `find-wfx-indicators.sh OWNER` | GitHub search and REST (read-only `gh`) | Probe PRs, payload and cleanup commits, leftover branches and the probe file across a user or organisation |
| `find-run-gaps.sh OWNER/REPO` | GitHub REST (read-only `gh`) | Missing run numbers per workflow since 10 November. Tested on two public repositories StepSecurity named: it reports run #1964 missing in one and run #63 in the other, as StepSecurity found |
| `rule-wfx-github-run-deleted.yml` | GitHub organisation or enterprise audit log | `workflows.delete_workflow_run`, to correlate with the commits above |
| `rule-wfx-aws-sessions.yml`, `query.kql` Q1 and Q2 | AWS CloudTrail | `wfx-*` STS sessions, then `CreateAccessKey` or `UpdateAssumeRolePolicy` from them |
| `rule-wfx-aws-open-trust-policy.yml`, `query.kql` Q2 | AWS CloudTrail | Any trust policy opened to `"AWS": "*"` |
| `query.kql` Q3 | Entra ID `AuditLogs` | Federated identity credentials named `wfx-ci-*` |
| `rule-wfx-runner-egress.yml`, `query.kql` Q4 | Runner network telemetry, firewall, DNS | The three collection servers and `api.telegram.org` from build hosts |
| `query.kql` Q5 | Self-hosted runner process telemetry | `python3` or `sudo` reading `/proc/<pid>/mem` of the runner processes |
| `wfx.yar` | Checkouts, git history, package tarballs, `vendor/` and `node_modules/` | Stealer config and markers, the hidden `.ci-*.sh` npm hook, and the injected workflow steps. Matched a live public payload sample (in memory, not saved) during testing |

Scan history, not just `HEAD`. The attacker reverts the commit, but the payload stays in git history. For example: `git rev-list --all | xargs -n1 -I{} git grep -l -e WF_CTOKEN -e wfx-loot {} -- .` or run `yara -r wfx.yar` over an export of each commit.

## Rotation checklist (if a gap or a payload commit is found)

1. **The account.** The commit author's token is stolen even if only the probe PR exists. Revoke that account's personal access tokens, OAuth and GitHub App user grants, SSH keys and sessions, and enforce 2FA. For bot accounts, remove any right to bypass branch protection.
2. **Repository secrets.** Rotate every repository, environment and organisation secret and variable the job could read, not just the ones the workflow names. The memory scan takes the rest.
3. **Publishing tokens.** Rotate npm, PyPI, Packagist, crates and container registry tokens. Pull and rebuild any version published between the malicious commit and its `ci: cleanup` from a clean commit.
4. **Cloud.** Rotate long-lived cloud keys held as secrets. Then remove persistence, because rotation alone does not: delete IAM access keys created since 10 November that you did not issue; restore trust policies opened to `"AWS": "*"`; delete Entra federated credentials named `wfx-ci-*`; review GCP `GenerateAccessToken` and `SignJwt` calls through your GitHub workload identity pool; and review Vault and Kubernetes logins from `token.actions.githubusercontent.com`.
5. **Self-hosted runners.** Treat the host as compromised. Rotate its own credentials and instance role, and rebuild it.
6. **Developer machines.** Anyone who ran `npm install` on an affected commit ran the stealer. Rotate that machine's credentials.
7. **Clean up GitHub.** Delete `wfx-docs` and `chore/*` branches, close probe PRs, and check that nothing merged on a forged check.
8. **Harden.** Use an egress allow-list on runners, because a bare IP and `api.telegram.org` don't belong in a normal build. Give workflows `permissions:` least privilege (no `statuses: write` unless needed). Narrow OIDC trust to specific repositories and branches. Require signed commits for bot accounts.

## Tuning and false positives

- Run deletions are routine in some organisations. Baseline first. The signal is a deletion within minutes of a push by the same developer or bot.
- Telegram egress is legitimate for some notification jobs. Allow-list known runners and bots.
- `rule-wfx-aws-open-trust-policy.yml` uses a regular expression so that the literal `*` principal is matched, not treated as a wildcard. Splunk renders it as `| regex`. Check that `requestParameters.policyDocument` is extracted in your CloudTrail sourcetype and URL-decoded.

## Validation notes

- Local `sigma check --fail-on-issues -x filename_length -x duplicate_filename`: see `sigma-check.txt`. Splunk conversion succeeds for all four rules. Microsoft XDR and Elastic are not targets, because the repository pipelines do not map aws or github log sources. Hand KQL ships in `query.kql`.
- `wfx.yar` compiles with yara-python 4.5. It matched one live public payload workflow (`vkuznet/gocurl` at `8d5aad0`, fetched in memory through the GitHub API and not stored) and did not match a benign `postinstall`.
- `find-run-gaps.sh` and `find-wfx-indicators.sh` were run read-only against public repositories named in the sources.
- KQL column names follow the standard Sentinel AWSCloudTrail, AuditLogs and Defender XDR schemas. They have not been run against a live workspace.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 12 November 2026. Facts and indicators from StepSecurity, Aikido Security and SafeDep; additional reporting from The Hacker News.
- Sigma rules and `wfx.yar`: Detection Rule License (DRL) 1.1. `query.kql` and the two scripts: MIT.
