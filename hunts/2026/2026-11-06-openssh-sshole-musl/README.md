# OpenSSH *sshole (CVE-2026-123158): musl / Alpine password bypass

| Hunt ID | Date | Status | Platforms | ATT&CK | CVEs | Files |
|---|---|---|---|---|---|---|
| 2026-11-06-openssh-sshole-musl | 2026-11-06 | Experimental | Linux auth logs; host inventory; Microsoft Sentinel / Defender; Splunk | T1078, T1110, T1548 | CVE-2026-123158 | rule-sshd-star-password-accept.yml, rule-alpine-doas-after-ssh.yml, query.kql, host-checks.sh, ci-targets.txt, sources.md |

## Hypothesis

On musl-based Linux with OpenSSH built or run without PAM, an attacker who can reach sshd can authenticate as any account whose `/etc/shadow` password field is exactly `*` by sending a password between 257 and 1024 bytes. Alpine tiny-cloud images that ship the `alpine` user with passwordless `doas` can escalate to root after that login. Fixed in Portable OpenSSH 10.6p2 and in Alpine backports listed in the companion Alert.

## Threat context

Disclosed 5 November 2026. Researcher: Özgün Kültekin (Wakefield). Primary sources: OpenSSH 10.6p2 release notes, Alpine advisory, oss-security 2026/11/05/3, sshhole.com. OpenSSH and Alpine do not assign a CVE in those advisories (Alpine: none at time of writing). GHSA-4fcc-vm97-gx3x / NVD list CVE-2026-123158 with CVSS 3.1 8.1. Password length: Alpine and sshhole.com use 257-1024 bytes; GHSA text says 256–1024  -  pack follows Alpine. As of 6 November 2026 Europe/London: public PoC available; no in-the-wild exploitation reported in the primaries; not listed in CISA KEV catalogVersion 2026.11.04. EPSS has no score yet.

## Hunts

1. **Successful password auth for common `*` accounts** (`rule-sshd-star-password-accept.yml`, `query.kql` Q1).
2. **Exposure config** (`host-checks.sh`, `query.kql` Q2): PasswordAuthentication yes with UsePAM no on Alpine/musl inventory.
3. **Alpine `alpine` user + doas** (`rule-alpine-doas-after-ssh.yml`, `host-checks.sh`, `query.kql` Q3).

## Data sources

| Source | Used by |
|---|---|
| sshd auth logs (syslog/journal) | rule-sshd-star-password-accept.yml, Q1 |
| Host config / package inventory | host-checks.sh, Q2 |
| doas / sudo audit or process logs | rule-alpine-doas-after-ssh.yml, Q3 |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1078 Valid Accounts | Bypass yields a real interactive session as the target user |
| T1110 Brute Force | Oversized password attempt against a `*` account |
| T1548 Abuse Elevation Control Mechanism | Passwordless doas on Alpine cloud `alpine` user |

## Notes

- Do not claim confirmed exploitation. Re-check KEV and vendor advisories before treating a hit as an incident without corroboration.
- Tune the username list. Many sites use different key-only account names.
- `PermitRootLogin prohibit-password` blocks direct root password login by default; still hunt root if that setting was relaxed.
- Containers that do not run sshd are out of scope for runtime exposure.
