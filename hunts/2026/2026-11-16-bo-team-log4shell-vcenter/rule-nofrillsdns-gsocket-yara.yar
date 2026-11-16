rule HuntLab_BOTeam_pgcache_nofrillsdns
{
    meta:
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-16"
        description = "Strings from the pgcache and GSocket downloader activity documented by Kaspersky ICS CERT on 5 November 2026. Untested."
        reference = "https://ics-cert.kaspersky.com/publications/reports/2026/11/05/supply-chain-attack-bo-team-in-a-software-developers-infrastructure/"
        licence = "MIT"
    strings:
        $p1 = "/etc/cron.hourly/pgcache" ascii
        $p2 = "lo1yaizaeghaevarooD1ahtaichootae.nofrillsdns.com" ascii
        $p3 = "lo1yaizaeghaevarood1ahtaichootaz.nofrillsdns.com" ascii
        $p4 = "vmware-timecheck-api.nofrillsdns.com" ascii
        $p5 = "gsocket.io/y" ascii
        $p6 = "/etc/cron.hourly/1vmware-timesync" ascii
    condition:
        2 of them
}
