# Sources — 2026-10-28-php2shell-fragnesia-chain

Primary (fetched / verified 28 October 2026):

- Dream Research — [Chained PHP2Shell Exploit Roots 25 Servers](https://dreamgroup.com/blog/chained-php2shell-exploit-roots-25-servers) (26 October 2026). Custom PHP2Shell + Fragnesia; 19k FOFA → 240 → 24 firewalls + 1 management server; US / Japan / Taiwan / South Korea; `/etc/pam.d/su` → `pam_permit.so`; Chinese-nexus assessment, no named actor.
- CISA KEV JSON — [known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) catalogueVersion **2026.10.28**: CVE-2026-109618 / 109619 `dateAdded` 2026-10-26 `dueDate` 2026-10-29; CVE-2026-46300 `dateAdded` 2026-10-28 `dueDate` 2026-10-31; ransomware Unknown; forensic triage Yes.
- PHP.net — security releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (21 October 2026).
- Ubuntu Security — [CVE-2026-46300](https://ubuntu.com/security/CVE-2026-46300) (Fragnesia; XFRM ESP-in-TCP shared-frag; High / CVSS 7.8).
- NVD — [CVE-2026-46300](https://nvd.nist.gov/vuln/detail/CVE-2026-46300), [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619).
- FIRST EPSS (model date 2026-10-28): PHP CVEs ≈ 0.99999; CVE-2026-46300 ≈ 0.10192 (~95.7th percentile).

Secondary:

- SecurityWeek — [China-Linked Hackers Exploit PHP2Shell to Root Firewalls](https://www.securityweek.com/china-linked-hackers-exploit-php2shell-to-root-firewalls/) (28 October 2026). Summarises Dream; “25 firewalls” wording is looser than Dream’s 24 firewalls + 1 management server.
- BleepingComputer — CISA confirms PHP2Shell now exploited (covers KEV add for the PHP CVEs; not the Fragnesia chain itself).
- Cyber-Threat.net — existing Alert [PHP2Shell: patch PHP now, then go hunting](https://cyber-threat.net/php2shell-patch-php-now-then-go-hunting/) (post 6); Hunt Lab `2026-10-22-php-web-server-spawning-shell`.
