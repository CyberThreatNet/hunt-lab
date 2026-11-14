# Sources for 2026-11-14-sckit-screenconnect-partner-access

Checked 14 November 2026, about 12:30 to 13:00 Europe/London (GMT). Updated from the 12 November draft with the 13 November Huntress wave and the ConnectWise Trust Center update at 21:15 UTC on 13 November. See also the Alert pack sources.md.

## Primary

- Huntress, Ben Nahorney and Susannah Matt, "SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays Across Hundreds of Endpoints", 11 November 2026, updated 11 November 23:34 ET: https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
  At least 288 endpoints across 48 organisations; activity from about 17:47 UTC on 11 November; all 288 within 90 minutes, about a third in the first 10 minutes. Run Command as SYSTEM; `C:\Windows\TEMP\sc.msi`, `C:\Windows\Temp\sckit-run.bat`, `C:\Windows\Temp\sckit-decoder.ps1`; `C:\ProgramData\RelayTrap`; `TrapWatch` task; second attacker-controlled client; RMM+ 1.0.31 and 1.0.32 accept a blank access key; ScreenConnect 26.6.6.9747 and 26.7.6.9783 affected; console takeover failed in every recovered host log; IOC table and 16 SHA256 values. ConnectWise advisory time given as 22:45 UTC on 11 November.
- ConnectWise, "ScreenConnect security update: Guidance for partners", 11 November 2026: https://www.connectwise.com/blog/screenconnect-security-update-guidance-for-partners
  About 400 partner environments with one or more of Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, RMM+ Password Link; presence alone does not establish compromise; disabled where ConnectWise can act; on-premises partners must disable; initial access and full scope under investigation; avoid interactive ScreenConnect connections to suspected devices.
- ConnectWise Trust Center, "ScreenConnect Security Investigation Update", last updated 12 November 2026, 18:45 UTC: https://www.connectwise.com/company/trust/advisories
  Investigation ongoing. No evidence of a compromise of ConnectWise infrastructure, or that initial access involved a ScreenConnect vulnerability. A CVE has been assigned to the issue in the independently developed third-party RMM+ family extension (the page does not print the CVE ID). About 400 partner environments had at least one of the five listed extensions. ConnectWise is assessing the researcher report that RMM+ 1.0.31 and 1.0.32 could accept an empty access key when none had been configured. The toolkit's attempted endpoint-to-technician spread is blocked by the fix for CVE-2026-84869 in ScreenConnect client 26.6.5 (8 September 2026). All partners should verify technician clients are on 26.6.5 or later; updating a cloud console does not automatically update technician clients.
- ConnectWise Advisories, "CVE-2026-127063, Third-Party RMM+ Extension for ScreenConnect Security Advisory", 12 November 2026: https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-127063
  Assigns CVE-2026-127063. Describes a static API secret used by default (CWE-1392, Use of Default Credentials). CVSS 4.0 9.3. ScreenConnect server and client are not impacted. No fixed RMM+ version has been announced; disabling the extension is the current mitigation. Affected product named as the DataComm RMM+ extension for ConnectWise ScreenConnect.
- ConnectWise, "ScreenConnect 26.6.5 Security Patch" (CVE-2026-84869), 8 September 2026: https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin
  Client-side unauthorised file transfer and execution during an active remote session; fixed in 26.6.5. The 12 November Trust Center update says 26.6.5 and later block this toolkit's endpoint-to-technician spread technique.

## Secondary (attributed)

- BleepingComputer, "Active ScreenConnect attacks breach MSPs, impact dozens of organizations", updated 11 November 2026: https://www.bleepingcomputer.com/news/security/active-screenconnect-attacks-breach-msps-impact-dozens-of-organizations/
  Earlier Huntress count of six compromised MSPs, 286 endpoints across 47 organisations; Huntress quote that the activity looked like abuse of legitimate functionality (before the RMM+ update); installer pattern given as `&c=Exploited<N>`; earlier July 2026 batch script referencing rogue ID `ed630cc2c873b091`.

## Where sources differ

- Victim count: Huntress blog 288 endpoints and 48 organisations; BleepingComputer (earlier Huntress figures) 286 and 47, plus six MSPs.
- Environments: ConnectWise says "approximately 400"; Huntress's key takeaways say "more than 400" and its body says "across 400".
- `sc.payproofkit[.]com`: Huntress calls it the attacker-controlled panel; BleepingComputer lists it as secondary C2.
- Installer pattern: Huntress `&c=Exploited Actor Name: Addmin`; BleepingComputer `&c=Exploited<N>`. The rules match the common prefix `&c=Exploited`.
- Cause: BleepingComputer quotes Huntress saying the activity looked like abuse of legitimate functionality. Huntress's later update points to the RMM+ blank-key flaw. ConnectWise has not confirmed the initial access method and is assessing Huntress's findings.
- RMM+ flaw wording: Huntress (and the Trust Center's summary of researcher findings) describes an empty access key accepted when none had been configured, in RMM+ 1.0.31 and 1.0.32. ConnectWise's CVE-2026-127063 advisory describes a static API secret used by default (CWE-1392) and does not itself use the "blank key" wording. The Alert and this pack keep the blank-key account as Huntress's finding.
