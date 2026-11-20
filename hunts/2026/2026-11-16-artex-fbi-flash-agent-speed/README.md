# Hunt: FBI FLASH on ARTEX and agent-speed intrusions

Full write-up: [Hunt Lab: Detecting ARTEX agent-speed intrusions](https://cyber-threat.net/hunt-lab-detecting-artex-agent-speed-intrusions/) on Cyber-Threat.net.

> **Status:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-11-16-artex-fbi-flash-agent-speed` |
| **Date** | 16 November 2026 |
| **Status** | Experimental |
| **Platforms** | Firewall and DNS logs; Microsoft Entra ID, Microsoft Sentinel, Microsoft Graph activity logs, Azure Application Gateway |
| **ATT&CK** | T1190 Exploit Public-Facing Application. T1078 Valid Accounts. T1528 Steal Application Access Token. T1110 Brute Force. T1195 Supply Chain Compromise. |
| **CVEs** | n/a |
| **Files** | `rule-fbi-flash-artex-ips.yml` (Sigma, DRL 1.1, experimental); `rule-artex-xcai-pro-dns.yml` (Sigma, DRL 1.1, experimental); `query.kql` (MIT); `sources.md`; `ci-targets.txt`; `sigma-check.txt` |

## Hypothesis

If an attacker is using the ARTEX agentic framework, defenders may see compressed bursts of automated requests, sequential lookups on partner or employee portals, unusual application or service-principal sign-ins, and rapid privilege or credential changes. Some of that activity may involve infrastructure published in FBI FLASH-20261113-001, but those addresses are historical and can be reassigned.

## Threat context

- **Source.** FBI FLASH-20261113-001, 13 November 2026, TLP:CLEAR, with additional reporting from BleepingComputer, Amazon Threat Intelligence and MalwareMustDie.
- **Speed.** The FLASH says some intrusions progressed from initial targeting to privileged access in under three hours.
- **Campaigns named in the FLASH.** South Korean financial institutions, personal information from approximately 67,000 people; ConnectWise Cloud Backup, access to more than 2,250 downstream tenants. Other actor names and figures in the article come from BleepingComputer or Amazon, not from the FLASH body.
- **IOCs.** 24 IPv4 addresses and the domain xcai[.]pro from the FLASH. Behavioural indicators include high-frequency automated requests and sequential enumeration. Outbound calls to public LLM APIs are not standalone indicators.

## How to use this pack

1. Load the Sigma rules on firewall and DNS tooling, or convert them for your SIEM.
2. Run the KQL in a Microsoft Sentinel workspace. Tune the burst thresholds in queries 4 and 5.
3. For ConnectWise, the FLASH asks organisations to review activity from at least 1 October 2026, search by application ID, and keep affected connections disabled until ConnectWise gives formal restoration instructions.
4. Prefer the MalwareMustDie TLP:CLEAR pack if you want additional formats (Suricata, Snort, YARA, STIX). This pack does not copy that work.

## Caveats

- Untested against a customer tenant or live firewall feed.
- FLASH IPs may already belong to benign services. The companion spreadsheet says artefacts should not be treated as standalone indicators.
- Do not alert on api.anthropic.com, api.deepseek.com, open.bigmodel.cn or api.x.ai alone.
- Amazon's IOC list is separate and is not in these rules.

## Validation notes

- Draft for review: untested. See `sigma-check.txt`.
- Local `sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename` to be recorded in `sigma-check.txt`.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 16 November 2026. Indicators from FBI FLASH-20261113-001.
- Sigma rules: Detection Rule License (DRL) 1.1. All other files in this pack: MIT.

## Sources

See `sources.md`.
