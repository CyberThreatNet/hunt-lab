#!/bin/sh
# Read-only triage for a VMware ESXi host that a Check Point gateway can reach over SSH.
# Destructive stage of the PHP2Shell Check Point campaign, Check Point Research 12 Nov 2026:
# SSH from the gateway as vpxuser, destroy_v6 wiper staged at /tmp/des, DREAM_ANNEXATION.txt notes.
# Run from the ESXi shell (busybox sh). It changes nothing. Save the output off-box.
# Licence: MIT. Cyber-Threat.net Hunt Lab, 13 Nov 2026.
GW="${1:-}"   # optional: gateway internal address(es), as an egrep pattern, e.g. '10\.0\.0\.1|10\.0\.0\.2'

echo "== host"; hostname; date -u; vmware -vl 2>/dev/null

echo "== SSH service state"
vim-cmd hostsvc/get_ssh_status 2>/dev/null

echo "== vpxuser SSH logins (vpxuser is the vCenter agent account; interactive SSH as vpxuser is unusual)"
grep -h -i 'vpxuser' /var/log/auth.log* 2>/dev/null | grep -i 'sshd\|accepted\|session' | tail -50
[ -n "$GW" ] && { echo "== SSH from gateway address(es)"; grep -h -E "$GW" /var/log/auth.log* 2>/dev/null | tail -50; }

echo "== shell commands mentioning the wiper or its note"
grep -h -i '/tmp/des\|destroy_v6\|DREAM_ANNEXATION' /var/log/shell.log* 2>/dev/null | tail -50

echo "== wiper binary and notes"
ls -la /tmp/des 2>/dev/null && sha256sum /tmp/des 2>/dev/null
find / -xdev -name 'DREAM_ANNEXATION.txt' 2>/dev/null | head -50
echo "== notes on datastores (top three levels; slow on large datastores)"
find /vmfs/volumes/ -maxdepth 3 -name 'DREAM_ANNEXATION.txt' 2>/dev/null | head -50

echo "== done"
