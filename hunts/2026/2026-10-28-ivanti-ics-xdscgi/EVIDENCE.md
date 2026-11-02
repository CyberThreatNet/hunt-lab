# Evidence

- KEV catalogVersion 2026.10.30: CVE-2026-104935 (added 2026-10-13, due 2026-10-16), CVE-2026-111357 (added 2026-10-30, due 2026-11-02), CVE-2026-118527 (added 2026-10-30, due 2026-11-13); ransomware Unknown for all three.
- EPSS 2026-11-01: CVE-2026-104935 0.86766 / 0.99742; CVE-2026-111357 0.00533 / 0.45024; CVE-2026-118527 not yet scored by FIRST.
- Volexity 13 Oct 2026 (updated noting CVE-2026-111357 patch 29 Oct): X-DSCGI-PATH mismatch, wu.cgi /runtime/tmp MD5 race, dsinvoked/DSCache local root, ICT miss.
- CISA 13 Oct alert updated 30 Oct; CCB Belgium and NHS England confirm chain and CVSS/CWE labels.
- Coverage: existing proxy queries apply to CVE-2026-104935 and the network race of CVE-2026-118527; CVE-2026-111357 is context-only (no new host rule without primary-source SIEM artefacts).
- Rules not run against live or lab data in this pack.
