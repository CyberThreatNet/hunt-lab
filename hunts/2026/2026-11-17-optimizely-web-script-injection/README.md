# Hunt: Optimizely Web script injection (16 November 2026)

Full write-up: [Optimizely supply-chain attack: check your scripts and your visitors](https://cyber-threat.net/optimizely-supply-chain-attack-check-scripts/) on Cyber-Threat.net.

> **Status:** Draft for review: Sigma checked, YARA tested on synthetic samples only, KQL untested against a live tenant.

| | |
|---|---|
| **Hunt ID** | `2026-11-17-optimizely-web-script-injection` |
| **Date** | 17 November 2026 |
| **Status** | Experimental |
| **Platforms** | Web proxy and DNS logs; Microsoft Defender for Endpoint; Microsoft Sentinel; file scanning (YARA) of saved snippets, proxy cache or page archives |
| **ATT&CK** | T1195.002 Compromise Software Supply Chain. T1189 Drive-by Compromise. T1059.007 JavaScript. T1027 Obfuscated Files or Information. T1056 Input Capture. T1539 Steal Web Session Cookie. T1113 Screen Capture. T1565.003 Runtime Data Manipulation. T1041 Exfiltration Over C2 Channel. T1203 Exploitation for Client Execution. |
| **CVEs** | None assigned |
| **Files** | `rule-optimizely-injection-proxy.yml` and `rule-optimizely-injection-dns.yml` (Sigma, DRL 1.1, experimental); `query.kql` (MIT); `optimizely_injection.yar` (MIT); `optimizely-snippet-check.sh` (MIT); `sources.md`; `sigma-check.txt` |

## Hypothesis

If a user in your organisation visited a site whose Optimizely Web snippet was infected on 16 November 2026, their browser will have fetched `track.js` from the attacker host and may have posted card data, cookies or screenshots back to it. iPhones and iPads will also have reached the `.icu` exploit-kit routers. If your own site uses Optimizely Web, your snippet's Project JavaScript may have carried the loader, and anyone with write access to your Optimizely account is in scope.

## Threat context

- **Vendor.** Optimizely says an unauthorised party exploited a vulnerability in the Experimentation account signup flow to add JavaScript to customer projects. It has fixed the flaw, removed the code, revoked tokens and reset access (BleepingComputer; status page 17 November 2026 01:02 UTC).
- **Scale.** Report URI found 188 infected snippets for 178 organisations out of 1,611 checked. First injection 04:21 UTC, all clean by 23:11 UTC on 16 November.
- **Payload.** Crypto address swapping, card skimming to `card.php`, cookie and screenshot theft to `hit.php`, Coruna and DarkSword iOS exploit kits.
- **Earlier wave.** `webshell.lol/get.js` through Kissmetrics, StorifyMe and Minute Media scripts from 13 November. The KQL window starts on 13 November to catch it.

## How to use this pack

1. **Visitors (your users).** Run the Sigma rules or KQL queries 1 to 4 over 13 to 17 November 2026. Any device that reached `card.php` or `hit.php` sent data out: treat card details and non-HttpOnly session cookies used on that device as exposed. Any iPhone or iPad that reached the `.icu` hosts should be updated to iOS 18.7.3 or later, or 26.3 or later, and reviewed.
2. **Site owners.** Run `optimizely-snippet-check.sh <project_id>` for every Optimizely project, then open Project JavaScript and every experiment's custom code by hand. A clean result today does not prove you were clean on 16 November.
3. **Archives.** Run `optimizely_injection.yar` over any saved copies of your snippet, CDN or proxy cache, or script-monitoring archives.
4. **Access.** Review Optimizely users, API tokens and integrations with write access, and rotate them. Check Optimizely's change history for 16 November.
5. **Controls.** Build an inventory of third-party scripts and who can change each one. Tighten CSP: restrict `connect-src`, avoid `'unsafe-eval'` and `'strict-dynamic'` where you can, and turn on reporting. Query 5 is a template for CSP report data.

## Caveats

- Indicators are historical. `1688360.cc` and `webshell.lol` were placed on clientHold on 17 November 2026; some IPs may be reassigned.
- Sandboxes, URL scanners and threat-intel tools will fetch these hosts. Exclude them.
- The YARA rules were tested only on synthetic samples built from published strings.
- Wallet addresses are in `sources.md` references, not in rules: they are for finance teams checking outgoing crypto transfers, not network detection.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 17 November 2026. Indicators from Report URI (Scott Helme) and BleepingComputer.
- Sigma rules: Detection Rule License (DRL) 1.1. All other files in this pack: MIT.

## Sources

See `sources.md`.
