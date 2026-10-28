# Mandiant / GTIG YARA — obtain from primary source

Do **not** treat this file as a licensed copy of Mandiant rules. Google Threat Intelligence Group published two hunting rules in the ARMORY CASTLE post; reproduce them from the primary source under your organisation’s acceptable-use review, or consume them via Google SecOps / Mandiant rule packs.

**Primary URL:** https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust/

| Rule name | Purpose |
| --- | --- |
| `G_Hunting_Webshell_SAWFLY_1` | SAWFLY PHP webshell (filesize &lt; 20KB; Base32 alphabet, `range(0,255)`, `pack('H*',`, `@eval(`, `http_response_code(404)`) |
| `G_Hunting_Backdoor_BARECLAW_1` | BARECLAW ELF tunneler (CLI strings + xorshift bytes; ELF magic) |

**Defanged file hashes (full values only in Mandiant post):**

- SAWFLY `mangoapi.php` SHA-256 starts `dc14e215…` ends `…ae95fb`
- BARECLAW `ingredi_ws` SHA-256 starts `1f19b9a2…` ends `…3aa462`

Our Sigma/KQL in this pack cover path and process behaviour for estates that cannot run YARA on appliance disks. Prefer the Mandiant rules when you can scan recovered images or exported web roots.
