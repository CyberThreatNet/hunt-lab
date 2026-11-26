# Hunt: Dokploy 0.31.1 security release and CVE-2026-129433 (member to root)

Full write-up: [Dokploy fixes 74 flaws: update self-hosted panels now](https://cyber-threat.net/dokploy-0-31-1-74-security-flaws-update/) on Cyber-Threat.net.
> **Status:** Experimental; Sigma checked; KQL and script untested on a live Dokploy host.

| | |
|---|---|
| **Hunt ID** | 2026-11-18-dokploy-0-31-1-member-to-root |
| **Date** | 18 November 2026 |
| **Status** | Experimental |
| **Platforms** | Linux Docker hosts running Dokploy; Microsoft Defender for Endpoint |
| **ATT&CK** | T1078 Valid Accounts, T1059.004 Unix Shell, T1053.003 Cron, T1611 Escape to Host |
| **CVEs** | CVE-2026-129433, CVE-2026-129316, CVE-2026-129315 |
| **Files** | rule-dokploy-compose-service-label-injection.yml, query.kql, dokploy-check.sh, sources.md |

## Hypothesis
An authenticated organisation member in a Dokploy instance prior to version 0.31.1 may have injected shell commands via the serviceName parameter in backup definitions. These commands execute when scheduled backups run, potentially granting root access to the host via the mounted Docker socket.

## Threat context
Dokploy 0.31.1 released on 12 November 2026 to address multiple critical vulnerabilities, including OS command injection in backups. CVE-2026-129433 allows command execution via the serviceName parameter. As of 17 November 2026, this vulnerability is not listed in CISA's Known Exploited Vulnerabilities catalogue, and no exploitation in the wild has been reported.

## How to use this pack
1. Update Dokploy to version 0.31.1 or later immediately using the panel's update function.
2. Run `dokploy-check.sh` on the host to identify existing backup and schedule entries containing shell metacharacters.
3. Run the Sigma rule and KQL queries over process logs from the Docker host to detect execution of malicious commands.
4. Review organisation members and API keys in the Dokploy panel; remove unauthorised users and revoke their keys.
5. Rotate any secrets that were sent to notification channels (Slack, Discord, etc.) due to the leak in failed builds/backups.
6. Review containers and bind mounts for any you did not create, indicating potential compromise.

## Caveats
- Process logging on the Docker host is required for the Sigma and KQL detections to function.
- This pack relies on behaviour hunts; no published indicators of compromise (IOCs) are included.

## Credits and licence
- Sigma rule: DRL 1.1
- KQL query, Bash script, README, and sources: MIT Licence

## Sources
See sources.md.
