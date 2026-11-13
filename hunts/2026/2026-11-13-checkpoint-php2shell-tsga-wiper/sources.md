# Sources for 2026-11-13-checkpoint-php2shell-tsga-wiper

Checked 13 November 2026, about 10:00 to 10:45 Europe/London (GMT).

## Primary

- Check Point Research, "PHP2Shell Exploitation on Check Point Gateway", published 12 November 2026 13:56 UTC: https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/
  Waves (30 Oct Israel, destructive against some; 2 Nov worldwide, none destructive); 130.94.19[.]204 and [.]168; `/opt/CPcvpn-R81.20/tmp/` session files with `upload_progress_pwn`; hundreds of portal segfaults; `zz*.tpl` webshells in the login-page template directory (path not printed); key `zz2026`; `/tmp/.up.tpl`; `challenge_render.tpl`; TSGA launch line; `slot_CPconfigdaemon`; `/lib/libcpfwcommon.so`; TCP 11072; `/tmp/.p_sock`; gogo; SSH to ESXi as `vpxuser`; `destroy_v6` at `/tmp/des`; `DREAM_ANNEXATION.txt`; PhiliKit links; attribution caveats; eight SHA256 values.
- Check Point blog, "Security Advisory: Active Exploitation of PHP2Shell and Local Privilege Escalation", 12 November 2026 13:58 UTC: https://blog.checkpoint.com/security/security-advisory-active-exploitation-of-php2shell-and-local-privilege-escalation/
  Activity 30 Oct to 4 Nov; PHP2Shell hotfix since 23 Oct; additional behavioural indicators; November Jumbo Hotfix advice; CVE table (CVE-2026-123039 lists R82.20, R82.10, R82, R81.20).
- Check Point sk1000362, CVE-2026-123039: https://support.checkpoint.com/results/sk/sk1000362
  Root `dynamic_server`, `/tmp/dynamic_socket` 0777; CVSS 7.8; affected products and versions including end-of-support R81 and R81.10; fixed Jumbo takes; interim mitigation; `dynamicCli.log` check; 0660 check; "a couple of dozen customers".
- Check Point sk1000302, PHP2Shell: https://support.checkpoint.com/results/sk/sk1000302 (last modified 12 November 2026)
  Affected features and versions; CVSS 9.2; hotfix 23 Oct 18:30 GMT; Jumbo takes and Spark builds; Management and Log Servers not affected.
- CISA KEV catalogue 2026.11.10 (JSON feed): CVE-2026-109618 and CVE-2026-109619 added 26 October 2026, due 29 October, forensic triage required. CVE-2026-123039 not listed.
- ESET APT Activity Report Q4 2025 to Q1 2026: https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026/
  PhiliKit found on VirusTotal (sample `philistine`, uploaded 25 February 2026), assessed as part of UNC5221's SPAWN toolset for Ivanti VPN appliances.

## Secondary (attributed)

- SecurityWeek, Ionut Arghire, 13 November 2026: https://www.securityweek.com/php2shell-exploited-in-destructive-check-point-gateway-attacks/
- The Hacker News, Ravie Lakshmanan, 13 November 2026: https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html

## Where sources differ or were not used

- The Hacker News names the group "Armory Castle (formerly UNC5221)" and says ESET first documented PhiliKit in June 2026. Neither Check Point nor the ESET report page we read uses that name, so the pack does not.
- Affected versions for CVE-2026-123039: the blog table lists R82.20 to R81.20; sk1000362 adds end-of-support R81 and R81.10. We give the sk list.
- The Hacker News gives scanning hours as "between 12 and 9 a.m. UTC"; Check Point Research says 00:00 to 09:00 UTC. We use Check Point's wording.
