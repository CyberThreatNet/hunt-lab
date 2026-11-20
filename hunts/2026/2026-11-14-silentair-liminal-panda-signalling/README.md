# SilentAir and LIMINAL PANDA: signalling interception and GTPDoor on the IPX

Full write-up: [SilentAir: hijacked mobile nodes used to intercept SMS codes](https://cyber-threat.net/silentair-hijacked-mobile-nodes-sms-codes/) on Cyber-Threat.net. Confirm the slug at publish if it changes; the URL will 404 until the article is live.

> **Status:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-11-14-silentair-liminal-panda-signalling` |
| **Date** | 14 November 2026 |
| **Status** | Experimental |
| **Platforms** | Mobile operator SS7, Diameter and GTP firewalls or interconnect captures; Linux hosts on the IPX edge; enterprise Microsoft Entra ID, Microsoft Sentinel and Microsoft Defender XDR |
| **ATT&CK** | T1111 Multi-Factor Authentication Interception. T1449 Exploit SS7 to Redirect Phone Calls/SMS is a close match but is deprecated. T1430.002 covers location tracking by impersonating SS7 nodes, not call or SMS diversion. |
| **FiGHT** | FGT5012.008 Locate UE via SS7 or Diameter; FGS5012 GTPDOOR; FGT1572.502 C2 Over GTP-U; FGT5042 Bypass Telecom Signaling Firewall. There is no exact current FiGHT ID for UpdateLocation SMS or call diversion. |
| **CVEs** | n/a |
| **Files** | `operator-hunt-notes.md` (pseudo-logic for operators, MIT); `rule-gtpdoor-v3-sctpe-md5.yml` (Sigma, DRL 1.1, experimental); `query.kql` (enterprise Entra and Defender, MIT); `query-sigma.kql` (hand-corrected Defender hash query, MIT); `query.spl` (Sigma to Splunk conversion, MIT); `sources.md`; `ci-targets.txt`; `sigma-check.txt` |

## Hypothesis

If an attacker has taken over a signalling node inside a roaming partner, or inside your own network, they can send a malicious SS7 UpdateLocation or Diameter Update-Location-Request so that your network treats that node as the one serving a target phone. Incoming SMS, including one-time codes, and calls may then be diverted. A separate, possibly related actor can hide command and control in GTP-C or, in a newer variant, in GTP-U.

Enterprises will not see those signalling messages in Microsoft 365 logs. They can still find accounts that use SMS for sign-in, phone-method changes, and risky sign-ins that follow.

## Threat context

- **Source.** Enea, "The Enemy Within. Tracking LIMINAL PANDA and SilentAir through Mobile Networks", 11 November 2026, key takeaways added 12 November 2026.
- **SilentAir.** Enea assesses with high confidence that this is a new state-level signalling actor, and with low confidence that its activity aligns with China-nexus operations. Sources in at least six Asian countries have targeted a dozen further countries and territories, with Taiwan the primary focus. Enea has told the operators and believes the activity has been disrupted for now; it does not say the equipment has been cleaned, and it names no operators.
- **LIMINAL PANDA.** Enea detected GTPDoor activity from the first quarter of 2026 and blocked several hundred covert sessions. It has seen infections, or strong signs of them, at 5 to 10 operators, and believes the total may reach several dozen, mainly in Asia, Africa and Latin America. A new GTPDoor version 3 uses GTP-U. A link between SilentAir and LIMINAL PANDA is possible but unconfirmed.
- **IOCs.** MD5 samples published by Enea: GTPDoor v3 `35f0d4d0c5519a2957338e448fce53bc`, SCTPE `da35d98c9a22e8ede93595d21fe7e63e`. SCTPE is not confirmed as a SilentAir implant.

## How to use this pack

1. Operators: work through `operator-hunt-notes.md` on your signalling and GTP tools. The notes are questions, not a vendor schema.
2. If you collect file hashes on IPX-facing Linux hosts, deploy the Sigma rule or the hash list, and run `query.kql` query 5 or `query-sigma.kql` where Defender file events are available.
3. Enterprises: run the KQL in `query.kql`. Queries 2 to 4 are for Microsoft Sentinel. Query 1 is for Defender XDR and cannot filter on SMS.

## Data sources and tables

| Query | Data source | What it finds |
|---|---|---|
| `operator-hunt-notes.md` | Operator SS7, Diameter and GTP firewalls or interconnect packet captures | Diversion, silent SMS, GTP-C/U covert sessions and host anomalies. No standard field names are assumed. |
| `rule-gtpdoor-v3-sctpe-md5.yml`, `query.spl` | Linux `file_event` (Sigma); Splunk conversion of the same hash list | The two MD5 values Enea published |
| `query.kql` Q5, `query-sigma.kql` | Defender XDR `DeviceFileEvents` | Exact MD5 match for those two samples |
| `query.kql` Q1 | Defender XDR `EntraIdSignInEvents` (preview, Entra ID P2) | Risky sign-ins. This table has no authentication-method column, so it cannot filter on SMS. |
| `query.kql` Q2 | Microsoft Sentinel `SigninLogs` | Sign-ins whose `AuthenticationMethodsUsed` includes SMS |
| `query.kql` Q3 | Microsoft Sentinel `AuditLogs` | Security-information registration, deletion or default-method changes |
| `query.kql` Q4 | Sentinel `AuditLogs` joined to `SigninLogs` | A security-information change followed within 24 hours by a risky sign-in for the same account |
| Host review | Process list, netstat or lsof versus a libpcap listener on IPX-facing Linux | A listener that does not show in netstat or lsof, the gap Enea noted for GTPDoor v3 |

## Caveats

- Untested against live operator traffic or a customer tenant.
- A hash miss does not clear a host. Enea could not analyse a SilentAir binary.
- Entra does not record a carrier SIM-swap or number-port event.

## Tuning and false positives

- The MD5 rule will also fire on security-research samples and sandbox detonations stored on a lab host.
- Query 2 depends on `AuthenticationMethodsUsed` being populated in your Sentinel workspace; confirm the column before treating a blank result as "no SMS sign-ins".
- Query 3 is not a SIM-swap or number-port detector. It only sees Entra security-information changes.
- Operator notes are questions, not vendor field names. A silent SMS burst or an unexpected UpdateLocation is a lead, not proof of SilentAir.

## Validation notes

- Draft for review: untested against live operator traffic or a customer tenant. No sample was run.
- Local `sigma check --fail-on-error --fail-on-issues -x filename_length -x duplicate_filename` on 14 November 2026: 0 errors, 0 issues. See `sigma-check.txt`. Tooling: sigma-cli 3.1.0, pySigma 1.5.1.
- `sigma convert -t splunk --without-pipeline` succeeds and is saved in `query.spl`.
- `sigma convert -t kusto -p microsoft_xdr` is omitted from `ci-targets.txt` because the pipeline emits `MD5 startswith` for `Hashes|contains`. A hand-corrected exact-hash query is in `query-sigma.kql` and in `query.kql` query 5.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 14 November 2026. Facts and MD5 samples from Enea, 11 November 2026, with additional reporting from SecurityWeek and The Hacker News.
- `rule-gtpdoor-v3-sctpe-md5.yml`: Detection Rule License (DRL) 1.1. All other files in this pack: MIT.

## Sources

See `sources.md`.
