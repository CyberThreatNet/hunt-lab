# CRAFTY FALCON / CERT-In CIAD-2026-0058: BFSI API abuse and AI pentest artefacts

Full write-up: [Hunt: CRAFTY FALCON Rs.1 tests, staging pivots and ARTEX](https://cyber-threat.net/hunt-crafty-falcon-rs1-staging-artex/) on Cyber-Threat.net.

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-05-crafty-falcon-bfsi | 2026-11-05 | Experimental | Payment logs; AWS CloudTrail; Windows/Linux endpoints; Docker hosts; Splunk; Microsoft Sentinel / Defender | T1588.007, T1190, T1078, T1552, T1059, T1505.003, T1651, T1105, T1059.004 | None (campaign advisory) | rule.yml, rule-aws-ssm-lambda.yml, rule-artex-login-captcha.yml, query.kql, host-checks.sh, ci-targets.txt, sources.md |

## Hypothesis

Operators tracked by CERT-In as CRAFTY FALCON abuse payment and disbursement APIs after entering through internet-facing non-production environments or cloud management channels. They validate fund flows with micro-value transfers (for example Rs. 1) before large transfers, and use publicly available AI offensive tools (ARTEX, PentAGI, Cairn, CyberStrikeAI). Separately, hosts that pulled the trojanised `tomicdd/artex` Docker image may expose an unauthenticated root shell on the login path.

## Threat context

CERT-In advisory CIAD-2026-0058 (4 November 2026, Critical) updates CIAD-2026-0046 (9 October 2026). CSIRT-Fin designates the actor CRAFTY FALCON. Targets include NBFCs, digital lending platforms, fintech entities, payment aggregators and service providers, and cryptocurrency / virtual digital asset service providers. The campaign is active and ongoing; entities have been re-targeted after incomplete remediation, including over holidays and weekends. Full infrastructure fingerprints and detection rules remain in restricted (TLP:AMBER) advisories shared with BFSI entities. This pack covers behaviours CERT-In published openly, plus Docker image checks from BadByte's 4 November 2026 write-up. It does not claim CRAFTY FALCON authored the Docker backdoor.

Prior ARTEX coverage on Cyber-Threat.net (VAPOR PANDA / BLOODALCHEMY, 31 October 2026) is linked for tool context only. CERT-In does not attribute CRAFTY FALCON to VAPOR PANDA.

## Hunts

1. **Micro-value then high-value transfers** (`query.kql` Q1). Same beneficiary or payout path: tiny credit then large credit in a short window.
2. **Staging / UAT to production** (`query.kql` Q2). Hosts or identities named for non-production reaching production payment APIs, secrets or networks.
3. **Cloud management abuse** (`rule-aws-ssm-lambda.yml`, `query.kql` Q3). SSM `SendCommand` / `StartSession`, Lambda code updates, and creation of users, roles or access keys outside approved automation.
4. **AI pentest tool artefacts** (`rule.yml`, `query.kql` Q4). Process, path or command-line matches for ARTEX, PentAGI, Cairn or CyberStrikeAI.
5. **Trojanised ARTEX Docker image** (`rule-artex-login-captcha.yml`, `host-checks.sh`, `query.kql` Q5). Image digests, binary hash, UI build ID, and login POSTs whose JSON body includes a `captcha` key.

## Data sources

| Source | Used by |
|---|---|
| Core banking / aggregator / wallet transfer logs | Q1 |
| Device / identity / proxy logs with environment naming | Q2 |
| AWS CloudTrail (or multi-cloud audit) | rule-aws-ssm-lambda.yml, Q3 |
| Endpoint process creation | rule.yml, Q4 |
| Docker / compose inventory; reverse-proxy or WAF HTTP logs | rule-artex-login-captcha.yml, host-checks.sh, Q5 |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1588.007 Obtain Capabilities: Artificial Intelligence | Public AI pentest frameworks named by CERT-In |
| T1190 Exploit Public-Facing Application | Staging entry; new PHP/Node.js upload and deserialization chains |
| T1078 Valid Accounts | Shared staging-to-production credentials and tokens |
| T1552 Unsecured Credentials | Hard-coded tokens; stolen wallet keys |
| T1059 Command and Scripting Interpreter | AI-refined script bursts; SSM/Lambda execution |
| T1505.003 Web Shell | PHP and Node.js webshells after exploit |
| T1651 Cloud Administration Command | AWS Systems Manager and Lambda abuse |
| T1105 Ingress Tool Transfer | Pull of trojanised ARTEX images |
| T1059.004 Unix Shell | Captcha-field `sh -c` backdoor as root |

## Notes

- CERT-In's public text does not list IP addresses or domains. Do not invent them. Ask CSIRT-Fin for the restricted pack if you are a covered entity.
- Payment-log field names differ by vendor. Q1 is a template; map amount, beneficiary and timestamp columns before production use.
- Tool-name matches fire on authorised red teams. Require a change ticket or written scope before treating a hit as hostile.
- BadByte withholds the captcha marker string. The HTTP rule alerts on any login body that contains a captcha key, which official ARTEX clients do not send.
- pySigma has no first-class AWS CloudTrail product for every backend; Splunk conversion of `rule-aws-ssm-lambda.yml` is best-effort. Hand-written KQL is in `query.kql`.
