import "hash"

rule LiteLLM_11070_cook_pth
{
    meta:
        description = "LiteLLM 1.107.0 malicious cook.pth startup hook"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"
        tlp = "CLEAR"
    strings:
        $import_cook = "import cook" ascii
    condition:
        filesize < 64 and $import_cook
        or hash.sha256(0, filesize) == "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        or hash.sha256(0, filesize) == "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"
}

rule LiteLLM_11070_cook_py
{
    meta:
        description = "LiteLLM 1.107.0 cook.py collector wrapper (Microsoft SHA-256)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"
        tlp = "CLEAR"
    condition:
        hash.sha256(0, filesize) == "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        or hash.sha256(0, filesize) == "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"
}

rule LiteLLM_11070_sitecustomize
{
    meta:
        description = "LiteLLM 1.107.0 malicious sitecustomize.py (Microsoft SHA-256)"
        author = "Cyber-Threat.net Hunt Lab"
        date = "2026-10-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "high"
        tlp = "CLEAR"
    condition:
        hash.sha256(0, filesize) == "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        or hash.sha256(0, filesize) == "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"
}
