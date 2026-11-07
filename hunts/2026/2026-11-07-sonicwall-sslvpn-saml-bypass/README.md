# SonicWall SSL-VPN logins that skipped SAML/MFA (CVE-2026-19868)

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-07-sonicwall-sslvpn-saml-bypass | 2026-11-07 | Experimental | SonicWall SonicOS syslog; SAML IdP sign-in logs (Entra ID, Okta, others); Microsoft Sentinel; Splunk | T1133, T1078, T1556 | CVE-2026-19868 | rule-sslvpn-login-allowed.yml, query.kql, ci-targets.txt, sources.md; templates/ (not deployable) |

## Hypothesis

On SonicOS firewalls with SAML enabled for SSL-VPN, an attacker with valid credentials for an alternate authentication method (for example a local or directory password) logs in to SSL-VPN without passing through the SAML identity provider, and so without SAML-enforced MFA. Each such session leaves a VPN login with no matching IdP sign-in.

## Threat context

SonicWall advisory SNWLID-2026-0014 (6 November 2026). CISA KEV added 6 November 2026, due 20 November 2026. Affected Gen7 7.3.3-7015 and older, Gen8 8.2.2-8015 and older; fixed 7.3.4-7013 and 8.2.3-8015; no workaround. No public attack details or IOCs.

## Hunts

1. **VPN login with no IdP sign-in** (`rule-sslvpn-login-allowed.yml` as input, `query.kql` Q1): join SonicOS event 1080 logins to SAML sign-ins for the same user within five minutes. Unmatched VPN logins are leads.
2. **Non-SAML auth method** (`templates/`, TEMPLATE, NOT DEPLOYABLE): needs a field we could not validate. See templates/README.md.
3. **New source for the account** (`query.kql` Q3): first-seen source IP for a user's SSL-VPN logins in the last 7 days.

## Data sources

| Source | Used by |
|---|---|
| SonicOS syslog / CEF (SSL-VPN user login events) | all |
| IdP SAML sign-in logs (e.g. Entra `SigninLogs`, Okta System Log) | Q1 |

## Field mapping (validated)

| Item | Value | Source |
|---|---|---|
| SSL-VPN successful login | SonicOS log event ID 1080, msg "SSL VPN zone remote user login allowed" | Rapid7 SonicWALL event code table; Arctic Wolf SonicOS log samples (2025) |
| Raw syslog keys | `m` (event ID), `msg`, `usr`, `src`, `sess`, `note` | Arctic Wolf and Rapid7 samples |
| Sentinel CEF | `CommonSecurityLog`, `DeviceVendor == "SonicWall"`, event ID in `DeviceEventClassID`, user in `SourceUserName` or `susr` | Microsoft Sentinel SonicWall connector doc; Azure-Sentinel ASIM parser ASimNetworkSessionSonicWallFirewall.yaml |

Not validated: SonicWall's own Log Events Reference Guide PDF did not download from this environment (blocked by the SonicWall site). Nothing documents an auth-method field, so that check lives in `templates/`.

No accounts are excluded by default. Any break-glass exclusion should be a reviewed, local change.

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1133 External Remote Services | SSL-VPN is the access path |
| T1078 Valid Accounts | Valid credentials for an alternate method are required |
| T1556 Modify Authentication Process | Effect is SAML/MFA enforcement skipped (no evidence of attacker modifying config) |

## Notes

- Patching closes the flaw but does not undo past sessions. Hunt back to at least October.
- Break-glass local accounts will show in Q1. Review them; do not allow-list them silently.
