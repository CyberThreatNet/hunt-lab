# VOLTA-AUTODOXER (VOLTA) - OpenRouter triage and artefacts

Companion write-up: Cyber-Threat.net VOLTA explainer (publishing with this hunt).

> **Draft for review: untested.** Behavioural starting points from Cisco Talos (31 October 2026). No sample detonated. No YARA body: Talos published SHA256 and filenames only.

| | |
|---|---|
| **Hunt ID** | `2026-11-02-volta-autodoxer` |
| **Date** | 2 November 2026 |
| **Status** | experimental (untested) |
| **Platforms** | network_connection; file_event; process_creation (headless Chrome cue) |
| **ATT&CK** | T1555.003, T1539, T1555, T1552.001, T1113, T1589, T1071.001, T1041, T1070.004 |
| **Files** | `rule.yml`, `rule-artefacts.yml`, `rule-chrome-headless.yml`, `kql-microsoft-xdr.txt`, `ci-targets.txt`, `sources.md`, `EVIDENCE.md` |

## Hypothesis

If VOLTA has completed (or attempted) its AI triage stage on a Windows host, defenders should see a non-browser process POST to `openrouter.ai/api/v1/chat/completions`, and/or file creates for `Identity_Report.txt`, `AI_Analysis.txt`, `volta_dox.zip` (plus `volta_log.zip` / `volta_doxnet.zip`) or `%APPDATA%\volta_debug.txt`. Chrome launched with `--headless` by an unexpected parent is a related ABE-bypass cue from Talos, not VOLTA-specific alone.

## Rules

| File | What it catches |
|------|-----------------|
| `rule.yml` | Network to `openrouter.ai` (OpenRouter chat-completions host) |
| `rule-artefacts.yml` | Named VOLTA report/zip/debug artefacts |
| `rule-chrome-headless.yml` | Chrome/Chromium started with `--headless` |

## Scope and limits

- OpenRouter allowlist caveat: developer tools, IDE extensions and scripts call OpenRouter legitimately. Allowlist sanctioned AI clients (and known browsers), require the `/api/v1/chat/completions` path where URL telemetry exists, and expect false positives.
- Artefact names are as published by Talos; rename variants will miss.
- Hash for the analysed sample: `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279`. Prefer hash blocklists alongside behaviour.
- No exploit or builder instructions are reproduced here.

## Sources

See `sources.md`. Primary: Cisco Talos VOLTA post, 31 October 2026.
