import "hash"

rule CWPdoor_Ngx_Integrity_Strings
{
    meta:
        description = "CWPdoor trojanised cwpsrv: X-Ngx-Integrity header strings (XLab)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/"
        severity = "critical"
        tlp = "CLEAR"
    strings:
        $h1 = "X-Ngx-Integrity-Time" ascii
        $h2 = "X-Ngx-Integrity-Data" ascii
        $h3 = "X-Ngx-Integrity-Sig" ascii
        $sock = "ngx_http_integrity_helper" ascii
        $fn1 = "ngx_http_integrity_init" ascii
        $fn2 = "ngx_http_integrity_check" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 20MB and
        (
            2 of ($h*) or $sock or 1 of ($fn*)
        )
}

rule CWPdoor_Known_MD5
{
    meta:
        description = "CWPdoor known sample MD5s from XLab IOC list"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-06"
        reference = "https://blog.xlab.qianxin.com/cwpdoor-the-invisible-backdoor-living-inside-control-web-panel/"
        severity = "critical"
        tlp = "CLEAR"
    condition:
        hash.md5(0, filesize) == "e505d4ffa21cf494a5dc2d7c8f4f1236" or
        hash.md5(0, filesize) == "965aea67fb40de1bab5169ada993349f" or
        hash.md5(0, filesize) == "d3f4e95113d49ab3991b45e457bda75b"
}
