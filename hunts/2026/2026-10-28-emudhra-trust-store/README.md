# eMudhra trust-store follow-up

Full write-up: [eMudhra intermediate keys: Windows and Edge trust purge](https://cyber-threat.net/emudhra-intermediate-keys-windows-edge-trust-purge/) on Cyber-Threat.net.

> **Draft: untested.** Looks for local CA/root imports that could undo Microsoft's October 2026 eMudhra purge. Pair with inventory of certs still chaining to removed roots.

| **Hunt ID** | `2026-10-28-emudhra-trust-store` |
| **CVEs** | CVE-2026-108014, CVE-2026-108015 (HCL) — context only |
