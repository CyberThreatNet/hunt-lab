# Evidence

- Talos VOLTA post fetched 2 November 2026: documents OpenRouter endpoint, model chain (claude-opus-4.6 → kimi-k2 → gemini-2.5-flash), temperature 0.2, Identity_Report.txt / AI_Analysis.txt / volta_dox.zip / volta_log.zip / volta_doxnet.zip / volta_debug.txt, SHA256 57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279, filenames 9BY0tjwOc3ut.exe / yLP9m5J3i2Aw.exe, PE timestamp 2026-08-17 20:35, first seen 2026-10-11 12:46 UTC, Chrome --headless ABE note, builder six-slot template.
- THN 2 November 2026 summarises the same Talos research; adds Telegram as exfil channel in its staging list (aligned with Talos builder Telegram slot).
- No YARA strings in either source sufficient to author a durable content rule; hash-only.
- Sigma/KQL not run against live or lab data in this pack.
