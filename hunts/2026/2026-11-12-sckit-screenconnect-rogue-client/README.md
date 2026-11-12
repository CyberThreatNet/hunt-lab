# SCKit worm: rogue ScreenConnect clients pushed through cloud Run Command

> **Status:** Draft for review: untested

| | |
|---|---|
| **Hunt ID** | `2026-11-12-sckit-screenconnect-rogue-client` |
| **Date** | 12 November 2026 |
| **Status** | Experimental |
| **Platforms** | Windows endpoints managed through ScreenConnect (cloud or on-premises); MSP technician workstations; ScreenConnect instance audit, Run Command and Toolbox history; EDR and network telemetry |
| **ATT&CK** | T1199 Trusted Relationship, T1072 Software Deployment Tools, T1219 Remote Access Software, T1105 Ingress Tool Transfer, T1053.005 Scheduled Task, T1547.001 Registry Run Keys, T1543.003 Windows Service, T1562.001 Disable or Modify Tools, T1539 Steal Web Session Cookie, T1550.004 Web Session Cookie |
| **CVEs** | CVE-2026-127063 (third-party RMM+ extension, ConnectWise 12 November 2026 disclosures) |
| **Files** | `rule-sckit-temp-dropper.yml`, `rule-sckit-trapwatch-persistence.yml`, `rule-sckit-rogue-screenconnect-client.yml`, `rule-sckit-network.yml` (Sigma, DRL 1.1); `query.kql` (MIT); `sckit.yar` (DRL 1.1); `sources.md`; `ci-targets.txt` |

## Do this first: do not triage over ScreenConnect

Huntress and ConnectWise both say it: do not open an interactive ScreenConnect session to a host you suspect. The kit is built to hand its dropper to the technician who connects, then to every endpoint that technician's panel can reach. Use EDR live response, WinRM or another out-of-band tool. If a technician has already connected to a suspect host, treat that workstation as exposed and investigate it from a clean device.

## Hypothesis

If your ScreenConnect panel was used against you, an operator sent Run Command jobs, running as SYSTEM, to many endpoints within minutes. Each job checked for an existing ScreenConnect client, downloaded an attacker-controlled installer to `C:\Windows\Temp\sc.msi`, wrote a dropper to `C:\Windows\Temp\sckit-run.bat` and fetched `C:\Windows\Temp\sckit-decoder.ps1`. The kit then unpacked to `C:\ProgramData\RelayTrap`, added Defender exclusions, installed a second attacker-controlled ScreenConnect client, and created a `TrapWatch` scheduled task that runs `TrapWatch.ps1` as SYSTEM to stop the legitimate client and take its place. A host with two ScreenConnect client services, one of which you do not own, is the lead.

## Threat context

- **When and how big.** Huntress saw the activity start at about 17:47 UTC on 11 November 2026 and counted at least 288 endpoints across 48 organisations within 90 minutes, about a third of them in the first 10 minutes. Earlier reporting by BleepingComputer, quoting Huntress on Reddit, gave "6 compromised MSPs and 286+ endpoints" across 47 organisations. The blog figure is the later one.
- **Likely entry.** Huntress's 11 November update (23:34 ET) ties the activity to RMM+, a third-party ScreenConnect extension. In versions 1.0.31 and 1.0.32, if an administrator never set the extension's access key, RMM+ accepted a blank one. RMM+ authenticates with that shared key and so bypasses ScreenConnect user accounts, roles and MFA. Huntress saw commands with no matching login, linked to RMM+ in the logs. ConnectWise has not confirmed the initial access method and says it is assessing Huntress's findings.
- **ConnectWise response.** The ConnectWise Trust Center was updated at 18:45 UTC on 12 November. In its 12 November disclosures, ConnectWise assigned CVE-2026-127063 to the third-party RMM+ extension. It found about 400 partner environments with one or more of five extensions (Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link). It disabled them where it could. On-premises partners must disable them themselves and not re-enable or reinstall them. Disabling an extension does not remove access already set up on endpoints. ConnectWise's disclosure says no fixed RMM+ version has been announced, and that disabling the extension is the current mitigation.
- **Technician clients.** Partners should put every ScreenConnect technician client on version 26.6.5 or later. ConnectWise has verified that the fix for CVE-2026-84869, released in the 26.6.5 client on 8 September 2026, blocks the toolkit's attempted endpoint-to-technician spread. Updating a cloud console does not automatically update technician clients. Huntress says the current ScreenConnect releases, 26.6.6.9747 and 26.7.6.9783, are affected, because the RMM+ issue sits in the extension.
- **Spread.** The code is built to steal a technician's `.aspxauth` session cookie, replay it against the panel and broadcast a payload through the Shared Toolbox. Huntress has not seen that step succeed: the console takeover attempt failed in every recovered host log it checked.

## Indicators (defanged; Huntress block list, 11 November 2026)

| Indicator | Role |
|---|---|
| `185.99.255[.]28` (hostname `screen`) | Attacker ScreenConnect server; serves the client installer |
| `newnewnew.gotdns[.]org` | Attacker relay, resolves to the address above |
| `soxnewwork.homedns[.]org` | Attacker relay, resolves to the address above; relay on port 81 for client `ed630cc2c873b091` |
| `sc.payproofkit[.]com` (`155.94.150[.]39`, hostname `WIN-FB5CKHMU4E1`) | Attacker ScreenConnect panel (BleepingComputer lists it as secondary C2) |
| `cdn007-digitaldownloads[.]com` | Possible C2, first flagged by Blackpoint |
| `hxxps://ns.mo7sen[.]dev/EadF.php?p=4` | Stager (`?p=5` delivers sqlite3; `?p=1` the stage 0 payload; `?p=6` the cleaner) |
| `2588ef5c15954b10`, `ed630cc2c873b091` | Rogue ScreenConnect client IDs |
| `Addmin` | Attacker participant name |
| `/Bin/ScreenConnect.ClientSetup.msi?...&c=Exploited...` | Installer pattern (Huntress: `&c=Exploited Actor Name: Addmin`; BleepingComputer: `&c=Exploited<N>`) |

Huntress publishes SHA256 values for 16 kit files; they are in `sckit.yar`. Huntress warns that hashes are weak here because scripts are rebuilt with different values and `RelayTrap.exe` is compiled on each host. Prefer the names, paths and behaviours.

## Data sources and tables

| Query | Data source | What it finds |
|---|---|---|
| `rule-sckit-temp-dropper.yml`, `query.kql` Q1 | `file_event` / `DeviceFileEvents` | `sc.msi`, `sckit-run.bat`, `sckit-decoder.ps1` in `C:\Windows\Temp`, and kit files or `C:\ProgramData\RelayTrap` |
| `query.kql` Q2 | `DeviceProcessEvents` | Run Command children of `ScreenConnect.ClientService.exe` that fetch an MSI or decode a script |
| `query.kql` Q3 | `DeviceProcessEvents` | More than one ScreenConnect client ID on one device, or a known rogue ID |
| `rule-sckit-trapwatch-persistence.yml`, `query.kql` Q4 | `process_creation`, `DeviceEvents`, `DeviceRegistryEvents` | `TrapWatch` task, `RelayTrapLiteAlert` Run value, Defender exclusions set during install |
| `rule-sckit-rogue-screenconnect-client.yml`, `query.kql` Q6 | `process_creation` | Client or installer command lines naming the rogue IDs, relays or installer pattern |
| `rule-sckit-network.yml`, `query.kql` Q5 | `network_connection` / `DeviceNetworkEvents`, firewall, DNS | The block list above |
| `query.kql` Q7 | `DeviceProcessEvents` on technician workstations | `sqlite3.exe` reading browser cookie stores |
| `sckit.yar` | Files on disk, EDR file collection | Kit scripts, config and known hashes |
| ScreenConnect panel | Instance audit log, Run Command history, Toolbox history, extension list | Jobs and Toolbox items you did not start, RMM+ or the other four extensions |

## First-hour checklist for MSPs and their customers

1. **Panel, from a clean device.** Open Administration, Extensions. If RMM+ or any of the other four extensions is present, disable it (on-premises) or confirm ConnectWise disabled it (cloud). If you must keep RMM+ for now, set a long random access key. Do not reinstall.
2. **Technician clients.** Put every ScreenConnect technician client, cloud or on-premises, on version 26.6.5 or later, so the CVE-2026-84869 fix can block endpoint-to-technician spread. Check the installed client on each technician workstation; do not rely on the console version alone.
3. **Run Command and Toolbox history.** Look for mass Run Command jobs you did not start, especially from about 17:00 UTC on 11 November, and any Shared Toolbox item that appeared and vanished. Huntress warns earlier victims are likely, so check back as far as the logs go.
4. **Endpoints.** Run Q1, Q3 and Q4 across every managed estate. Two ScreenConnect client services on one host, `C:\ProgramData\RelayTrap`, or a `TrapWatch` task means the host is compromised.
5. **Block.** Add the indicators above to DNS and egress block lists, and run Q5 back to the start of your logs.
6. **Isolate and clean.** Isolate affected hosts and keep them isolated until cleanup is done. Huntress has seen reinfection soon after isolation was lifted. Remove the rogue client service, the `TrapWatch` task, `C:\ProgramData\RelayTrap\`, the `%TEMP%` kit files (`sckit-*`, `Panel-Lateral.ps1`, `runnew.cmd`, `ToolboxRelayUploader.exe`, `sqlite3.exe`) and the `RelayTrapLiteAlert` Run value. Verify the legitimate client separately before removing anything.
7. **Revoke.** From a trusted device, end active ScreenConnect web sessions, rotate ScreenConnect credentials, and revoke browser and identity-provider sessions for technicians who may have connected to an affected host.
8. **Technicians.** Run Q7 and the YARA rule on any workstation that connected to a suspect host after 11 November.

## Tuning and false positives

- `sc.msi` is a generic name. On its own in `C:\Windows\Temp` it is a lead. Together with `sckit-run.bat` or a new client ID it is a finding.
- Q3 will list devices that legitimately have two clients, for example when two MSPs share a customer or during a migration. Confirm each client ID and relay host against your own panels.
- Dynamic DNS names (`gotdns`, `homedns`) can be re-pointed. Match on time as well as name.

## Validation notes

- Draft for review: untested in a live estate. No sample was run.
- Local `sigma check --fail-on-issues -x filename_length -x duplicate_filename`: see `sigma-check.txt`. Microsoft XDR and Splunk conversions succeed for all four rules.
- `sckit.yar` compiles with yara-python 4.5 and was smoke-tested against synthetic strings only.
- The ScreenConnect client folder and query-string format used in Q3 follow the standard client install layout (`ScreenConnect Client (<id>)`, `h=` relay host). Check it against one of your own hosts before relying on it.

## Credits and licence

- Cyber-Threat.net Hunt Lab, 12 November 2026. Facts and indicators from Huntress and ConnectWise; additional reporting from BleepingComputer.
- Sigma rules and `sckit.yar`: Detection Rule License (DRL) 1.1. `query.kql`: MIT.
