# Evidence notes (review pack)

Captured under `../../../../../evidence/` relative to this hunt folder
(`/workspace/ct-plan/adobe-magento-polyshell-2026-10-27/evidence/`).

| File | What |
|------|------|
| `kev-cve-2026-48356.json` | KEV row for CVE-2026-48356 (dateAdded, dueDate, vendorProject) |
| `nvd-cve-2026-48356.json` | NVD API JSON (CVSS, CWE, descriptions) |
| `epss-cve-2026-48356.json` | FIRST EPSS score at capture time |
| `adobe-apsb26-73.html` / markdown extract | Adobe bulletin (severity, CVSS, versions) |
| `sansec-polyshell.html` / extract | Sansec public research (paths, accesson.php, loader domains) |
| `sigma-check.txt` | `sigma check` on both rules (0 errors; FilenameLengthIssue only) |
| `convert-*.txt` | Local sigma-cli conversions used to seed kql / esql / splunk files |

Do not invent IOCs. Defang any domain or URL if pasted into the Alert body
(e.g. `hxxps://`).
