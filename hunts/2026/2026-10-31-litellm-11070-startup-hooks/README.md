# LiteLLM 1.107.0: cook.pth / sitecustomize credential theft

Companion: [LiteLLM 1.107.0 was poisoned](https://cyber-threat.net/litellm-1-107-0-poisoned-rotate-secrets/).

> **Status:** Sigma `check` clean; YARA not sample-tested.

| | |
|---|---|
| **Hunt ID** | `2026-10-31-litellm-11070-startup-hooks` |
| **Date** | 31 October 2026 |
| **Status** | Experimental |
| **Platforms** | Hosts that ran Python/Docker with LiteLLM 1.107.0 |
| **ATT&CK** | T1195.001, T1195.002, T1059.006, T1546.018, T1552.001 |
| **CVEs** | None (MDE TVM-2026-0003) |
| **Files** | `rule-startup-files.yml`, `rule-exfil-domain.yml`; `query.kql`; `cook-pth.yar`; `sources.md`; `ci-targets.txt` |

## Hypothesis

Hosts that installed 1.107.0 (PyPI ~11:39–13:23 UTC or Docker tags to ~14:20 UTC, 21 Oct 2026) leave `cook.pth` / `cook.py` / `sitecustomize.py` under site-packages, `/tmp/remote_code_loader.lock`, `/tmp/.pc_once_72129118c59f5636c0bb`, `/tmp/.pc_e_*` staging, and egress to `www[.]litellm[.]dev`. **Do not start Python or pip to check.**

## Threat context

LiteLLM: release redirected to lookalike `Berri-AI/litellm`. Microsoft: `cook.pth` runs PRIVCOLLECT; `sitecustomize.py` is a Unix loader (second stage not confirmed). Private enterprise registry unaffected. Rebuild on `1.106.2`; rotate every reachable secret.

## Hunts

1. Startup files — `rule-startup-files.yml`
2. Exfil domain — `rule-exfil-domain.yml`
3. XDR — `query.kql` (Microsoft public hashes/domain/OpenSSL staging)
4. YARA — `cook-pth.yar`

## Tuning

Benign `sitecustomize.py` is common — require hash or sibling `cook.pth`. Rebuild beats uninstall.

## Validation

Untested on live infections. No wheel executed.
