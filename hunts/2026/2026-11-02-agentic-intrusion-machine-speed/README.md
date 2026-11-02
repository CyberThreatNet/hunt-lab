# Agent-driven intrusion: machine-speed discovery and bulk collection

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-02-agentic-intrusion-machine-speed | 2026-11-02 | Experimental | Linux, Windows; Splunk; Microsoft Defender XDR / Sentinel | T1595.002, T1190, T1059.006, T1082, T1033, T1016, T1083, T1087.004, T1213, T1119, T1078 | None | rule.yml, rule-correlation.yml, query.kql, ci-targets.txt, sources.md |

## Hypothesis

An intruder using an AI agent to drive the attack leaves a different shape in the logs from a human operator: many tools run in seconds from one parent process, systematic probing with very even timing, and bulk reads of directory-type data.

## Threat context

On 30 October 2026 Chainalysis disclosed that "this month" an external actor used "offensive agentic techniques" to gain unauthorised access to its systems and internal tools. Chainalysis says user IDs, full names, email addresses and organisation role labels were accessed. It says it has no indication that investigation content, transaction or query results, clear-text passwords, MFA secrets or session tokens were accessed. It has not published the vulnerabilities, tools, timeline or indicators. Nothing in this hunt is an indicator from that incident. It is general guidance for spotting agent-driven activity.

## Hunts

1. **Machine-speed discovery** (`rule.yml` base + `rule-correlation.yml`, `query.kql` Q1). One interpreter process (Python, Node.js, Bun, Deno, PowerShell) spawns six or more distinct discovery or staging tools within two minutes.
2. **Bulk directory reads** (`query.kql` Q2). One app or user reads hundreds of user, group or role objects through Microsoft Graph in ten minutes.
3. **Even-timed probing** (`query.kql` Q3). One client hits more than 100 distinct paths in 15 minutes, mostly 4xx, with some successes. Look at the gap spread: very low variance points to automation.
4. **Unexpected password resets** (`query.kql` Q4). Clusters of resets, the follow-on Chainalysis tells customers to watch for.

## Data sources

| Source | Used by |
|---|---|
| Linux or Windows process creation (Sysmon, auditd, Defender `DeviceProcessEvents`) | rule.yml, rule-correlation.yml, Q1 |
| Microsoft Graph activity logs | Q2 |
| Web server, WAF or API gateway logs | Q3 |
| Entra ID audit logs | Q4 |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1595.002 Vulnerability Scanning | Systematic probing of exposed services |
| T1190 Exploit Public-Facing Application | Probing that ends in success responses |
| T1078 Valid Accounts | Follow-on use of found credentials or tokens |
| T1059.006 Python | Agent tools commonly run through an interpreter |
| T1082, T1033, T1016, T1083 Discovery | System, owner, network and file discovery in a burst |
| T1087.004 Cloud Account Discovery | Bulk reads of users and roles |
| T1213 Data from Information Repositories | Reading internal tools and directories |
| T1119 Automated Collection | Scripted, high-rate collection |

The mapping is ours, for the hunts above. Chainalysis has not published ATT&CK techniques for its incident.

## Tuning

- Allow-list known automation parents (configuration management, CI runners, monitoring agents) by command line.
- Thresholds (six tools, 500 Graph calls, 100 paths) are starting points. Baseline a week first.
