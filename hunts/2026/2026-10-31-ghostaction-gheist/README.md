# GhostAction and Gheist: malicious GitHub Actions stealing secrets

> **Status:** Sigma `check` clean; not engine-tested.

| | |
|---|---|
| **Hunt ID** | `2026-10-31-ghostaction-gheist` |
| **Date** | 31 October 2026 |
| **Status** | Experimental |
| **Platforms** | GitHub org/Enterprise audit; self-hosted Actions runners; egress telemetry |
| **ATT&CK** | T1195.002, T1552.001, T1078, T1070 |
| **CVEs** | None |
| **Files** | `rule-ghostaction-exfil.yml`, `rule-gheist-selfhosted.yml` (Sigma, DRL 1.1); `query.kql`; `sources.md`; `ci-targets.txt` |

## Hypothesis

Stolen GitHub tokens used in GhostAction or Gheist leave: HTTP to `193.32.204[.]199` from a runner (GhostAction); or a `ci-sync-*` branch adding only `sync-check.yml`, audit UA `gheist`, and on self-hosted runners `.gdmp_pat` / `.gdmp_patg` / `.gdmp_sweep` or log marker `gdmp-pivot` (Gheist). Wiz states the campaigns are distinct.

## Threat context

**GhostAction** (GitGuardian): injects `security-audit.yml` / `github_actions_security.yml`; posts secrets to `193.32.204[.]199`. Oct wave hit tens of thousands of repos.

**Gheist** (Wiz, from 15 Sep 2026): plants `sync-check.yml` on `ci-sync-` + six chars; base32-dumps `toJSON(secrets)` into logs then deletes the run — no external C2. Public runs largely held; private/Enterprise can complete. Self-hosted pivot writes `.gdmp_*`.

## Hunts

1. GhostAction IP — `rule-ghostaction-exfil.yml`
2. Gheist helpers — `rule-gheist-selfhosted.yml`
3. Combined XDR — `query.kql`; also audit for UA `gheist` and deleted `ci-sync-*` runs

## Tuning

Lab IP replays match. Rotate every secret the repo could reach; revoke the injecting token.

## Validation

Untested on live infections. No sample executed.
