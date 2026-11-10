# Qubole vendor-account AssumeRole and stale third-party trust

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-10-qubole-sts-assumerole-vendor-trust | 2026-11-10 | Experimental | AWS CloudTrail (Athena, Microsoft Sentinel AWSCloudTrail, Splunk AWS add-on); IAM Access Analyzer; AWS CLI | T1199, T1078.004, T1550.001, T1526, T1552, T1530 | n/a | rule-assume-role-actor-iam-user.yml, rule-assume-role-qubole-account.yml, query.kql, query.spl, query-athena.sql, audit-trust-policies.md, ci-targets.txt, sources.md |

## Hypothesis

Wiz reports that a threat actor with credentials from Qubole's AWS account (805246085872) calls sts:AssumeRole against customer integration roles, including unused roles whose trust policies were left in place, then uses the resulting session to enumerate the account, read secrets and download S3 objects.

## Threat context

Wiz, working with Sentra and Mandiant, published this activity on 9 November 2026. Observed role assumption ran from 14 to 26 October 2026. Wiz asks customers to review CloudTrail from 1 October 2026. The Register reported the same incident and should be credited; all identifiers in this pack come from the Wiz post.

**Reported for this threat (Wiz):**

- AssumeRole from account 805246085872. Legitimate Qubole platform traffic also uses this account and, Wiz says, came from AWS infrastructure in the environments observed.
- IAM user AIDA3W7DIFLYOLTK63SFS, observed only in threat actor activity in those environments.
- IAM user AIDAJYRRH5Y3A7AAJM2HW from 18 October, which also carries legitimate platform traffic from AWS infrastructure. Filter on source address.
- Source addresses (defanged as published): 45.83.220[.]211 (Mullvad, 14-15 Oct), 57.129.54[.]120 (OVH, 15-26 Oct), 185.209.199[.]73 (Mullvad, 18-21 Oct), 89.37.63[.]175 (Datacamp / Mullvad, 25 Oct), 2001:41d0:70d[:]7800:: (OVH IPv6, 16-24 Oct). Mullvad exits are shared VPN nodes; an address match alone is not conclusive.
- Role session names with prefix quiam-, including quiam-enum and quiam-scope-full.
- Follow-on ListBuckets, ListObjects, HeadObject, GetObject, GetFunctionConfiguration, ListSecrets, GetSecretValue, DescribeParameters, GetParameter, and GetCallerIdentity with a TruffleHog user agent.
- A related ISO (sso_agent.iso, SHA-256 65f061281c9a712e9502793dc4c5035cae490b84da05f7d4223cefa65ad396e4) was hosted on 57.129.54[.]120. Wiz has not identified deployments and cannot confirm use. Not used as a detection rule here.

Wiz also describes a separate 8-11 October abuse of customer-owned keys thought to have been created for Qubole integrations, not linked to the role-assumption campaign. That is out of scope for these rules.

## Hunts

1. **Actor-only IAM user** (`rule-assume-role-actor-iam-user.yml`, `query.kql` Q1): any CloudTrail event, especially AssumeRole, where userIdentity.principalId is AIDA3W7DIFLYOLTK63SFS. High signal in Wiz's dataset.
2. **Vendor-account AssumeRole** (`rule-assume-role-qubole-account.yml`, `query.kql` Q2, `query.spl`, `query-athena.sql`): AssumeRole where userIdentity.accountId is 805246085872. This also matches legitimate Qubole traffic. Tune by excluding source addresses in AWS IP ranges, and investigate non-AWS sources and quiam- session names first.
3. **Follow-on session activity** (`query.kql` Q3, `query.spl` Q3, `query-athena.sql` Q3): secret, parameter, Lambda and S3 calls from matching role sessions. After a successful AssumeRole, follow-on calls in the customer account often carry the assumed-role identity (a `quiam-` match in the ARN), not the vendor account ID. The `quiam-` match is a starting filter, not a complete session join; still join follow-on events to the Q1/Q2 sessions in your own workspace.
4. **Stale trust audit** (`audit-trust-policies.md`): IAM Access Analyzer and an aws cli query for roles that still trust 805246085872.

## Data sources

| Query | Data source | Requirement |
|---|---|---|
| query.kql | Microsoft Sentinel `AWSCloudTrail` (or an equivalent CloudTrail table) | AWS CloudTrail connector, management events from 1 October 2026 in every relevant account |
| rule.yml | Sigma `product: aws`, `service: cloudtrail` | CloudTrail management events |
| query.spl | Splunk sourcetype `aws:cloudtrail` (AWS add-on) | Same coverage |
| query-athena.sql | Athena or a CloudTrail Lake query | Organisation trail covering all accounts and regions |
| audit-trust-policies.md | IAM API and IAM Access Analyzer | IAM read in each account; an analyser is optional but useful |

Field names in `query.kql` follow the Sentinel `AWSCloudTrail` table as documented by Microsoft (UserIdentityAccountId, UserIdentityPrincipalid, SourceIpAddress, SessionIssuerUserName, UserIdentitySessionContextSessionIssuerUserName where present). Confirm the exact column names in your workspace before you enable a detection. CloudTrail management events do not record S3 GetObject; enable S3 data events or server access logs to see object reads.

## ATT&CK mapping

| ID | Technique | Why |
|---|---|---|
| T1199 | Trusted Relationship | Vendor AWS account is trusted by customer integration roles |
| T1078.004 | Valid Accounts: Cloud Accounts | Actor used IAM users in the trusted vendor account |
| T1550.001 | Application Access Token | Pack context only: later use of stolen Entra and Okta tokens, as Wiz describes. Not mapped on the two AssumeRole Sigma rules, because sts:AssumeRole itself is a stretch for this technique. |
| T1526 | Cloud Service Discovery | Broad enumeration of roles, buckets, functions, keys and databases |
| T1552 | Unsecured Credentials | Secrets Manager, SSM parameters and Lambda environment variables |
| T1530 | Data from Cloud Storage Object | S3 GetObject after ListBuckets / ListObjects / HeadObject |

## Tuning and false positives

- Account 805246085872 is also used for legitimate Qubole platform activity. Do not page on every AssumeRole from that account. Wiz says legitimate traffic it observed came from AWS infrastructure.
- AIDAJYRRH5Y3A7AAJM2HW is used by both the actor (from non-AWS addresses) and the platform (from AWS infrastructure).
- Mullvad addresses are shared exits.
- User agents in Wiz's table (Boto3, aws-cli, TruffleHog) are common. Treat them as suspicious only with another indicator from the Wiz post.
- Expected volume is low in accounts that no longer use Qubole, and may be steady in accounts with an active integration.

## Validation notes

- Draft for review: untested against live CloudTrail. Identifiers were copied from the Wiz post and checked against that page on 10 November 2026.
- sigma check: no rule or condition errors and no issues. The vendor-account rule uses an anchored regex for 805246085872 so the value stays a string under sigma-cli 3.1.0. See sigma-check.txt.
- Splunk conversion (`-t splunk --without-pipeline`) succeeded for both rules. KQL is hand-written for Sentinel's AWSCloudTrail table, not a Sigma conversion.

## Credits and licence

- Cyber-Threat.net Hunt Lab, from Wiz's 9 November 2026 blog (Zack Morrow, Sean Johnstone, Benjamin Read). The Register reported the same incident.
- `rule-*.yml`: [DRL 1.1](../../LICENSE-DRL). `query.kql`, `query.spl`, `query-athena.sql`, `audit-trust-policies.md` and this README: [MIT](../../LICENSE).
