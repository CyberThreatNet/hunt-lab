import "hash"

rule CP_PHP2Shell_Portal_Template_Webshell
{
    meta:
        description = "PHP webshell planted as a .tpl file in the Check Point Mobile Access portal template directory (Check Point Research, 12 Nov 2026)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        severity = "critical"
        tlp = "CLEAR"
        note = "Strings come from the published key and upload path, not from a sample. The small first-stage shell may carry neither; the hash covers the one sample Check Point listed."
    strings:
        $php = "<?php" ascii nocase
        $key = "zz2026" ascii
        $up = "/tmp/.up.tpl" ascii
        $tpl = "challenge_render.tpl" ascii
    condition:
        filesize < 200KB and
        (
            hash.sha256(0, filesize) == "edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3" or
            ($php and ($key or $up or $tpl)) or
            ($key and $up)
        )
}

rule CP_TSGA_TSProxy_PhiliKit_ELF
{
    meta:
        description = "TSGA backdoor and TSProxy library (PhiliKit variants) on Check Point gateways, and related PhiliKit files (Check Point Research, 12 Nov 2026)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        severity = "critical"
        tlp = "CLEAR"
        note = "Path strings are those Check Point says the implant uses or writes. They may be encoded in some builds, so a miss is not evidence of absence."
    strings:
        $p1 = "slot_CPconfigdaemon" ascii
        $p2 = "libcpfwcommon.so" ascii
        $p3 = "/tmp/.p_sock" ascii
        $p4 = "/tmp/.bd.log" ascii
        $p5 = "CPconfigdaemon" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 20MB and
        (
            hash.sha256(0, filesize) == "4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8" or
            hash.sha256(0, filesize) == "d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63" or
            hash.sha256(0, filesize) == "ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7" or
            hash.sha256(0, filesize) == "fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da" or
            ($p3 and 1 of ($p1, $p2, $p4, $p5)) or
            ($p1 and $p2)
        )
}

rule CP_Campaign_destroy_v6_Wiper
{
    meta:
        description = "destroy_v6 Linux ELF wiper and its DREAM_ANNEXATION.txt note, used on VMware ESXi in the PHP2Shell Check Point campaign (Check Point Research, 12 Nov 2026)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        severity = "critical"
        tlp = "CLEAR"
    strings:
        $note = "DREAM_ANNEXATION" ascii wide
    condition:
        filesize < 20MB and
        (
            hash.sha256(0, filesize) == "c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237" or
            hash.sha256(0, filesize) == "0522937c0c0337be54fe25493539e5f5f8ceb9742c980aaff1cfc9515f3a96f7" or
            (uint32(0) == 0x464c457f and $note)
        )
}

rule CP_Campaign_gogo_Scanner_Hash
{
    meta:
        description = "gogo scanner build Check Point Research saw on a compromised Check Point gateway (12 Nov 2026). gogo is a public scanner; only the published hash is matched."
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        severity = "high"
        tlp = "CLEAR"
    condition:
        hash.sha256(0, filesize) == "3b51080a909023f7d484e2443740b572307ce0054eb9e32d98f0a06bfcd2db90"
}
