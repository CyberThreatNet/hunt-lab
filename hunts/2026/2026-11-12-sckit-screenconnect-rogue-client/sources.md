# Sources for 2026-11-12-sckit-screenconnect-rogue-client

Checked 12 November 2026, about 10:00 to 10:30 Europe/London (GMT).

## Primary

- Huntress, Ben Nahorney and Susannah Matt, "SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays Across Hundreds of Endpoints", 11 November 2026, updated 11 November 23:34 ET: https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
  At least 288 endpoints across 48 organisations; activity from about 17:47 UTC on 11 November; all 288 within 90 minutes, about a third in the first 10 minutes. Run Command as SYSTEM; `C:\Windows\TEMP\sc.msi`, `C:\Windows\Temp\sckit-run.bat`, `C:\Windows\Temp\sckit-decoder.ps1`; `C:\ProgramData\RelayTrap`; `TrapWatch` task; second attacker-controlled client; RMM+ 1.0.31 and 1.0.32 accept a blank access key; ScreenConnect 26.6.6.9747 and 26.7.6.9783 affected; console takeover failed in every recovered host log; IOC table and 16 SHA256 values. ConnectWise advisory time given as 22:45 UTC on 11 November.
- ConnectWise, "ScreenConnect security update: Guidance for partners", 11 November 2026: https://www.connectwise.com/blog/screenconnect-security-update-guidance-for-partners
  About 400 partner environments with one or more of Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link; presence alone does not establish compromise; disabled where ConnectWise can act; on-premises partners must disable; initial access and full scope under investigation; avoid interactive ScreenConnect connections to suspected devices.

## Secondary (attributed)

- BleepingComputer, "Active ScreenConnect attacks breach MSPs, impact dozens of organizations", updated 11 November 2026: https://www.bleepingcomputer.com/news/security/active-screenconnect-attacks-breach-msps-impact-dozens-of-organizations/
  Earlier Huntress count of six compromised MSPs, 286 endpoints across 47 organisations; Huntress quote that the activity looked like abuse of legitimate functionality (before the RMM+ update); installer pattern given as `&c=Exploited<N>`; earlier July 2026 batch script referencing rogue ID `ed630cc2c873b091`.

## Where sources differ

- Victim count: Huntress blog 288 endpoints and 48 organisations; BleepingComputer (earlier Huntress figures) 286 and 47, plus six MSPs.
- Environments: ConnectWise says "approximately 400"; Huntress's key takeaways say "more than 400" and its body says "across 400".
- `sc.payproofkit[.]com`: Huntress calls it the attacker-controlled panel; BleepingComputer lists it as secondary C2.
- Installer pattern: Huntress `&c=Exploited Actor Name: Addmin`; BleepingComputer `&c=Exploited<N>`. The rules match the common prefix `&c=Exploited`.
- Cause: BleepingComputer quotes Huntress saying the activity looked like abuse of legitimate functionality. Huntress's later update points to the RMM+ blank-key flaw. ConnectWise has not confirmed the initial access method.
