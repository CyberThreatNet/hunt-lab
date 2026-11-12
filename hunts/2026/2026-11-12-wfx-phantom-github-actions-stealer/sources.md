# Sources for 2026-11-12-wfx-phantom-github-actions-stealer

Checked 12 November 2026, about 10:00 to 10:45 Europe/London (GMT).

## Primary (vendor research)

- Aikido Security, Oliver Smith, "wfx-loot campaign pushes CI secret stealer to tens of thousands of repositories", 12 November 2026 (modified 08:32 UTC): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories
  4,837 accounts; probes in 61,764 repositories; 61,839 PRs from 12:45 UTC on 10 November to 15:00 UTC on 11 November; "at least 1,835 repositories ran the payload" in the summary but "at least 1,806" in the body; 10,431 via collaborator or organisation access; 92% open; at least 50 compromised users publish packages; Packagist neuronai-studio 3.14.3; Go docker-env v1.0.278 and v1.0.280; IPs 194.150.166[.]244 and 18.143.168[.]96; SHA-256 89695abb...735cf; revert "within at most one minute".
- StepSecurity, Owais Shaikh, "WFX Phantom: The GitHub Actions Secret Stealer That Deletes Its Tracks", 12 November 2026: https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer
  More than 63,000 probes at 07:40 UTC on 12 November, about 90% open; fourth hiding place (appended to existing scripts such as update.sh); Telegram from 01:10 UTC and Telegram-only from about 05:30 UTC on 12 November; third server 153.75.82[.]159; chat -1004340163187; 101 copies examined; forged checks present but not switched on; run-gap examples (#1964, #63); Fly.io GitHub App on 173 probes from 19 accounts; persistence (AWS wfx- sessions, open trust policy, Azure wfx-ci-); packages including gocurl.
- SafeDep, "wfx: GitHub Actions Credential Stealer Hits 8,000 Repos", 12 November 2026: https://safedep.io/blog/github-actions-wfx-credential-stealer
  8,093 repositories with malicious commits from 12:46 UTC on 10 November to 04:36 UTC on 12 November (public default branches only); 61,879 probes in 61,734 repositories from 4,833 accounts, 91% open; method counts 7,309 / 771 / 16; three packages including redock v1.0.282 and gocurl; payload header (WF_* variables, callback token); 200-commit sample: about half to the first server, about a fifth Telegram only; forged checks never switched on.

## Secondary (attributed)

- The Hacker News, Swati Khandelwal, "Attacker Used 4,837 Hijacked GitHub Accounts to Run a CI Secret Stealer in 1,806+ Repositories", 12 November 2026, with correction: https://thehackernews.com/2026/11/4837-hijacked-github-accounts-ran-ci.html
  Summary of the above; probes seen 05:04 to 05:38 UTC on 12 November; 28 WebdriverIO repositories via wdio-bot; overlap with GhostAction.

## Where sources differ

- Repositories where the payload ran: Aikido gives both "at least 1,835" and "at least 1,806" in one post; The Hacker News uses 1,806+. SafeDep's 8,093 counts repositories that received malicious commits, not confirmed runs.
- Probe counts: 61,764 repositories / 61,839 PRs (Aikido, to 15:00 UTC on 11 Nov); 61,734 repositories / 61,879 PRs from 4,833 accounts (SafeDep); more than 63,000 PRs (StepSecurity, 07:40 UTC on 12 Nov). The counts differ by cut-off time.
- Accounts: 4,837 (Aikido) versus 4,833 (SafeDep).
- Start: 12:45 UTC (Aikido) versus 12:46 UTC (SafeDep's first commit).
- Exfiltration: Aikido says HTTP POST only, to two IPs. StepSecurity and SafeDep add a third server and Telegram. The Hacker News corrected its article on this.
- Forged required checks: Aikido describes them as part of the run. StepSecurity (101 copies) and SafeDep (all samples) found the feature switched off.
- Revert timing: Aikido "within at most one minute"; StepSecurity "usually within a minute"; The Hacker News corrected "within a minute" to say some changes stayed for longer.
- Packages: Aikido lists one Packagist and one Go module (two versions). SafeDep and StepSecurity add gocurl, and SafeDep adds docker-env/redock v1.0.282.
- Branch patterns `chore/[a-z0-9]{8}` and `ci-check-[0-9]{4}`: listed by Aikido. SafeDep says they come from an outside report and were not in its samples.
