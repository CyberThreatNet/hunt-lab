# Sources (verified 10 November 2026, Europe/London)

All identifiers in the pack were copied from the Wiz blog and checked against that page the same day.

| Claim | Source | Status |
|---|---|---|
| Activity 14-26 Oct 2026; review CloudTrail from 1 Oct 2026 | Wiz, 9 Nov 2026 | Verified primary |
| Account 805246085872 used by Qubole platform and by the actor | Wiz | Verified primary |
| IAM user AIDA3W7DIFLYOLTK63SFS observed only in actor activity | Wiz | Verified primary |
| IAM user AIDAJYRRH5Y3A7AAJM2HW used by actor from 18 Oct and by legitimate platform traffic from AWS infrastructure | Wiz | Verified primary |
| IPs, IPv6, session names, API sequence, TruffleHog, ISO hash | Wiz IOC tables and narrative | Verified primary |
| Every attributed AssumeRole included an External ID and succeeded; many roles otherwise unused | Wiz | Verified primary |
| S3 object reads need data events or server access logs | Wiz | Verified primary |
| Separate 8-11 Oct customer-owned key activity, not linked | Wiz | Verified; out of scope for these rules |
| ISO hosted on the OVH address; no deployments identified | Wiz | Verified; not used as a detection rule |
| The Register report of the same incident | https://www.theregister.com/security/2026/11/09/attackers-backdoor-trusted-aws-integrations-to-steal-secrets/5308553 | Secondary, credited |

Sentinel AWSCloudTrail column names follow Microsoft's table documentation. Confirm locally. Pack untested against live CloudTrail.
