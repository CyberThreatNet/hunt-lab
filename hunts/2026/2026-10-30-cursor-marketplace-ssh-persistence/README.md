# Cursor Marketplace SSH persistence (Anthropic.claude-code 2.1.313)

Full write-up: companion Alert draft on Cyber-Threat.net (slug `cursor-marketplace-trojanised-extension-ssh-backdoor`).

> **Draft for review: untested.** Sigma check expected clean; conversions and host script not engine-tested against live infections.

| | |
|---|---|
| **Hunt ID** | `2026-10-30-cursor-marketplace-ssh-persistence` |
| **Date** | 30 October 2026 |
| **Status** | Experimental |
| **Platforms** | Developer workstations (macOS, Linux, Windows) that installed Cursor Marketplace extensions; Microsoft Defender XDR / Sentinel; Splunk |
| **ATT&CK** | T1195.002, T1098.004, T1543.001, T1053.003, T1053.005, T1572, T1071.001, T1071.002 |
| **CVEs** | None |
| **Files** | `rule-authorized-keys.yml`, `rule-persistence.yml`, `rule-reverse-tunnel.yml`, `rule-c2-network.yml` (Sigma, DRL 1.1); `query.kql`, `query.spl` (MIT); `host-check.sh` (MIT); `sources.md` |

## Hypothesis

If a host installed the trojanised `Anthropic.claude-code` **2.1.313** VSIX from the Cursor Marketplace between about 09:27 and 20:35 UTC on 29 October 2026, then we expect one or more of: an `authorized_keys` entry with comment `svc-telemetry`; LaunchAgent `com.apple.sysmond` / helper `~/.config/.smt`; Linux `@reboot` cron for `.smt`; Windows `SysMon` task or Startup `sysmon.cmd`; `ssh`/`autossh` reverse-tunnel command lines; and egress to `134.209.82.225` on TCP 22 or 8099. **Uninstalling the extension does not remove these artefacts.**

## Threat context

What is **reported** (see [`sources.md`](sources.md)):

- Cursor: malicious build available in its VS Code extension Marketplace for that window; at most 5,000 users; payload plants SSH key, persistence, reverse tunnel and HTTP beacon; enabling local SSH often failed without admin rights; attacker server taken offline; uninstall alone insufficient.
- OpenSourceMalware / Phorion: loader prepended to `extension.js`; key comment `svc-telemetry`; LaunchAgent / cron / SysMon details; beacon `http://134.209.82.225:8099/beacon`.

Indicators below are used **only** where those sources published them.

## Hunts

1. **Authorized keys** — `rule-authorized-keys.yml` (file_event).
2. **Persistence paths** — `rule-persistence.yml` (file_event).
3. **Reverse SSH tunnel** — `rule-reverse-tunnel.yml` (process_creation).
4. **C2 IP** — `rule-c2-network.yml` (network_connection).
5. **Combined XDR** — `query.kql`.
6. **Host script** — `./host-check.sh` (read-only; exit 1 on hit).

## ATT&CK mapping

| ID | Technique |
|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain |
| T1098.004 | Account Manipulation: SSH Authorized Keys |
| T1543.001 | Create or Modify System Process: Launch Agent |
| T1053.003 | Scheduled Task/Job: Cron |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1572 | Protocol Tunneling |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1071.002 | Application Layer Protocol: File Transfer Protocols |

## Tuning and false positives

- Legitimate autossh reverse tunnels — baseline known jump hosts.
- Software named SysMon unrelated to this implant — require path under Startup or task name correlation.
- Responders grepping `svc-telemetry` during cleanup — expect hits.

## Validation notes

Untested against live infections. No malware sample executed in Hunt Lab. Synthetic validation pending.
