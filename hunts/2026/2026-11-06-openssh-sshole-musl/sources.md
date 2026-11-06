# Sources

| Claim | Source |
|---|---|
| Bypass via musl crypt() returning * for passwords over 256 bytes; accounts with * field; PasswordAuthentication no mitigates; fix in OpenSSH 10.6p2 | https://www.openwall.com/lists/oss-security/2026/11/05/3 ; https://www.openssh.org/releasenotes.html#10.6p2 |
| Alpine affected conditions; fixed package table; alpine user + doas; cloud image range 3.18.11-3.24.3; detection via Accepted password | https://www.alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/ |
| Password length 257-1024; researcher narrative and self-check | https://sshhole.com/ ; https://github.com/oz9un/sshole |
| CVE-2026-123158; CVSS 3.1 8.1 High | https://github.com/advisories/GHSA-4fcc-vm97-gx3x |
