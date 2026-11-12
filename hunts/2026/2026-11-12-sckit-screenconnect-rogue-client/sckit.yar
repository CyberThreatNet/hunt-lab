import "hash"

rule SCKit_ScreenConnect_Worm_Scripts
{
    meta:
        description = "SCKit ScreenConnect worm scripts and config (names and markers published by Huntress, 11 Nov 2026)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        severity = "high"
        tlp = "CLEAR"
        note = "Huntress says hashes are weak indicators because scripts are rebuilt per host. This rule keys on names and markers instead."
    strings:
        $n1 = "sckit-decoder.ps1" ascii wide nocase
        $n2 = "sckit-loader.ps1" ascii wide nocase
        $n3 = "sckit-run.bat" ascii wide nocase
        $n4 = "Panel-Lateral" ascii wide
        $n5 = "ToolboxRelayUploader" ascii wide
        $n6 = "Run-Lateral-Full.bat" ascii wide
        $n7 = "RelayTrapLiteAlert" ascii wide
        $n8 = "TrapWatch" ascii wide
        $n9 = "RelayTrap" ascii wide
        $n10 = "Stop-LabTrap" ascii wide
        $i1 = "EadF.php" ascii wide
        $i2 = "mo7sen" ascii wide
        $i3 = "newnewnew.gotdns" ascii wide
        $i4 = "soxnewwork.homedns" ascii wide
        $i5 = "payproofkit" ascii wide
        $i6 = "2588ef5c15954b10" ascii wide
        $i7 = "ed630cc2c873b091" ascii wide
        $a1 = "AddToToolbox" ascii wide
        $a2 = ".aspxauth" ascii wide nocase
    condition:
        filesize < 5MB and
        (
            1 of ($i*) or
            3 of ($n*) or
            (1 of ($n*) and 1 of ($a*))
        )
}

rule SCKit_Known_SHA256
{
    meta:
        description = "SCKit component SHA256 values published by Huntress (weak: kit is rebuilt per host)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/sckit-worm-rogue-screenconnect"
        severity = "medium"
        tlp = "CLEAR"
    condition:
        filesize < 20MB and
        (
            hash.sha256(0, filesize) == "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11" or
            hash.sha256(0, filesize) == "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec" or
            hash.sha256(0, filesize) == "b93f10f30ee453d1e1c046fec9d141c41d7680be5cd46c3aeb3febe0f4953b4d" or
            hash.sha256(0, filesize) == "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4" or
            hash.sha256(0, filesize) == "d2ed7a7bf4f8ac9c7969e9b3a07ebd4dda0d858f372c876ac0a041611698de9a" or
            hash.sha256(0, filesize) == "4a1dd3cd2ea14368afadf7e9dfdd63b104e3981ef8c85bbb6510919b810af04b" or
            hash.sha256(0, filesize) == "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af" or
            hash.sha256(0, filesize) == "cf50d73fa8117a758093b1344de41cd6a6ccddc645cdda1fa91a9264efe93956" or
            hash.sha256(0, filesize) == "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781" or
            hash.sha256(0, filesize) == "c31e6f075cd77e01839aebce32ed35659a9ee962d102aca53040bb5e297410a9" or
            hash.sha256(0, filesize) == "deda7c30d798a19b6699a45fbcba503cf778594df9163c61c2f96bb2d2b9fb45" or
            hash.sha256(0, filesize) == "0bd84c776dc01f784a617e73fc77b269f847fc4a062ffd489e4692869724bf08" or
            hash.sha256(0, filesize) == "454c43d296b1276bde9a4f6ff1da2221cb35ccdb2fc7991bdd572e45bce12a8a" or
            hash.sha256(0, filesize) == "5dd3a6ba806ac472663e243cfc1c034c534d5d9a42ec362c3dbf0f8d950148d0" or
            hash.sha256(0, filesize) == "43b7a5e56f9e6c7b74e1ce2b7b5af63f383084625fcc2d3a5985fa1059e2db95" or
            hash.sha256(0, filesize) == "50659748723e906c8b3d3c0386bd4cf692f693a3e23639398c1a14d0c31fed61"
        )
}
