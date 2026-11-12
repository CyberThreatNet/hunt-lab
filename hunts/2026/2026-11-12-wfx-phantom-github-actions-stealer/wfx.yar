rule WFX_CI_Secret_Stealer_Script
{
    meta:
        description = "wfx (wfx-loot, WFX Phantom) GitHub Actions secret stealer: config variables and self-reported markers"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-12"
        reference = "https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer"
        reference2 = "https://safedep.io/blog/github-actions-wfx-credential-stealer"
        severity = "critical"
        tlp = "CLEAR"
        usage = "Scan checkouts, git history (for example git rev-list --all piped to git show), package tarballs and vendor folders. The attacker reverts the commit, so scan history, not only HEAD."
    strings:
        $cfg1 = "WF_CALLBACK" ascii
        $cfg2 = "WF_CTOKEN" ascii
        $cfg3 = "WF_MEMSCAN" ascii
        $cfg4 = "WF_EXFIL_CACHE" ascii
        $cfg5 = "WF_EXFIL_SUM" ascii
        $cfg6 = "WF_EXFIL_ART" ascii
        $cfg7 = "WF_PRIVATE" ascii
        $cfg8 = "WF_SECRETS" ascii
        $cfg9 = "WF_TARBALL" ascii
        $m1 = "wfx-loot" ascii
        $m2 = "WFX-BEGIN" ascii
        $m3 = "exfil_no_runtime_vars" ascii
        $m4 = "selfhosted_collected" ascii
        $m5 = "memscan_files" ascii
        $m6 = "oidc_discovery" ascii
        $m7 = "deliver_retry" ascii
        $tok = "b42d70a7aab9140ca19e8249" ascii
        $ip1 = "194.150.166.244" ascii
        $ip2 = "18.143.168.96" ascii
        $ip3 = "153.75.82.159" ascii
    condition:
        filesize < 2MB and
        (
            $tok or
            4 of ($cfg*) or
            2 of ($m*) or
            (1 of ($ip*) and 1 of ($cfg*))
        )
}

rule WFX_Npm_Hidden_CI_Helper_Hook
{
    meta:
        description = "package.json script that runs a hidden .ci-<6 chars>.sh file, the wfx chore: add ci helper form"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-12"
        reference = "https://safedep.io/blog/github-actions-wfx-credential-stealer"
        severity = "high"
        tlp = "CLEAR"
    strings:
        $hook = /"(postinstall|preinstall|install|build|test|prepare)"\s*:\s*"[^"]{0,40}sh \.\/\.ci-[a-z0-9]{6}\.sh/ ascii
        $exit42 = "-eq 42 ]; then exit 42" ascii
    condition:
        filesize < 1MB and ($hook or $exit42)
}

rule WFX_Injected_Workflow_Steps
{
    meta:
        description = "wfx injected workflow: Pass runtime step exporting Actions runtime tokens plus toJSON(secrets), or the Dependency Audit workflow name"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-11-12"
        reference = "https://safedep.io/blog/github-actions-wfx-credential-stealer"
        severity = "high"
        tlp = "CLEAR"
    strings:
        $s1 = "name: Pass runtime" ascii
        $s2 = "ACTIONS_RUNTIME_TOKEN" ascii
        $s3 = "toJSON(secrets)" ascii
        $s4 = /name: Restore cache [a-z0-9]{4}\b/ ascii
        $s5 = /name: Dependency Audit [a-z0-9]{4}\b/ ascii
    condition:
        filesize < 2MB and $s1 and $s2 and ($s3 or $s4 or $s5)
}
