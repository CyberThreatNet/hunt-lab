# Evidence

- KEV catalogVersion 2026.10.30: CVE-2026-104935 (added 2026-10-13, due 2026-10-16), CVE-2026-111357 (added 2026-10-30, due 2026-11-02), CVE-2026-118527 (added 2026-10-30, due 2026-11-13); ransomware Unknown for all three.
- EPSS 2026-11-01: CVE-2026-104935 0.86766 / 0.99742; CVE-2026-111357 0.00533 / 0.45024; CVE-2026-118527 not yet scored by FIRST.
- Volexity 13 Oct 2026 (updated noting CVE-2026-111357 patch 29 Oct): X-DSCGI-PATH mismatch, wu.cgi /runtime/tmp MD5 race, dsinvoked/DSCache local root, ICT miss. Volexity does not name CVE-2026-118527; the race-to-CVE mapping is from the KEV short description (predictable identifiers / upload to a known location) plus that race write-up.
- CISA 13 Oct alert updated 30 Oct. CCB Belgium (read 2 Nov 2026) and NHS England CC-4866 (read 2 Nov 2026) confirm the three-CVE chain and publish CVSS scores for CVE-2026-111357 and CVE-2026-118527; neither page lists CWE IDs.
- Coverage: existing proxy queries apply to CVE-2026-104935 and the network race mapped to CVE-2026-118527 (KEV description + Volexity race); CVE-2026-111357 is context-only (no new host rule without primary-source SIEM artefacts).
- Rules not run against live or lab data in this pack.
