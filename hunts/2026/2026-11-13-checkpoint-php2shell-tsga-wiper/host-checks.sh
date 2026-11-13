#!/bin/bash
# Read-only triage for a Check Point Security Gateway (Gaia, Expert mode, as admin).
# PHP2Shell (CVE-2026-109618, CVE-2026-109619) + CVE-2026-123039 campaign, Check Point Research 12 Nov 2026.
# It changes nothing. Save the output off-box. A hit means: treat the gateway as compromised,
# preserve evidence, contact Check Point, and rebuild rather than clean.
# Licence: MIT. Cyber-Threat.net Hunt Lab, 13 Nov 2026.

echo "== host, version and Jumbo take"
hostname; date -u
cat /etc/cp-release 2>/dev/null
cpinfo -y all 2>/dev/null | grep -i -A1 'HOTFIX\|JUMBO' | head -20

echo "== CVE-2026-123039: socket mode (fixed: srw-rw---- root config; vulnerable: srwxrwxrwx)"
ls -l /tmp/dynamic_socket 2>/dev/null || echo "no /tmp/dynamic_socket (dynamic_server stopped?)"

echo "== CVE-2026-123039: blocked attempts after the fix (non-zero or unexpected uid = attempt)"
grep "Rejected connection from unauthorized uid" /var/log/dynamicCli.log* 2>/dev/null | tail -50

echo "== TSGA / TSProxy / webshell upload artefacts"
for f in /tmp/CPconfigdaemon /tmp/.bd.log /tmp/.up.tpl /tmp/.p_sock /lib/libcpfwcommon.so /tmp/des; do
  [ -e "$f" ] && { echo "FOUND $f"; ls -la --time-style=full-iso "$f"; sha256sum "$f" 2>/dev/null; }
done
find / -xdev \( -name 'slot_CPconfigdaemon' -o -name 'CPconfigdaemon' -o -name 'gogo' -o -name 'DREAM_ANNEXATION.txt' \) 2>/dev/null \
  | while read -r f; do echo "FOUND $f"; ls -la --time-style=full-iso "$f"; sha256sum "$f" 2>/dev/null; done

echo "== processes named like the implant"
ps -eo pid,ppid,user,lstart,args | grep -i 'CPconfigdaemon\|gogo\|/tmp/des' | grep -v grep

echo "== TSGA/PhiliKit TCP 11072 listener and /tmp/.p_sock"
netstat -anp 2>/dev/null | grep -E ':11072\b|\.p_sock'

echo "== processes that have libcpfwcommon.so mapped (TSProxy injection)"
grep -l 'libcpfwcommon.so' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3 | while read -r p; do ps -o pid,user,args -p "$p" | tail -1; done

echo "== Mobile Access portal: .tpl files named zz* or challenge_render.tpl, and .tpl files containing PHP"
for d in /opt/CPcvpn-*; do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \( -name 'zz*.tpl' -o -name 'challenge_render.tpl' \) 2>/dev/null \
    | while read -r f; do echo "CHECK $f"; ls -la --time-style=full-iso "$f"; sha256sum "$f"; done
  find "$d" -xdev -type f -name '*.tpl' -newermt '2026-10-20' 2>/dev/null -exec grep -l -i '<?php\|zz2026\|base64_decode' {} + 2>/dev/null \
    | sed 's/^/PHP-IN-TPL /'
done
# Check Point does not print the template path. challenge_render.tpl may be a genuine file name:
# compare content, size and time with a known-clean gateway on the same version and Jumbo take.

echo "== PHP session files with the exploitation marker (Check Point saw them under /opt/CPcvpn-R81.20/tmp/)"
grep -rl 'upload_progress_pwn' /opt/CPcvpn-*/tmp/ 2>/dev/null | head -50

echo "== portal Apache/PHP segmentation faults (hundreds were logged during exploitation)"
grep -h -i 'segmentation fault\|segfault' /opt/CPcvpn-*/log/* /var/log/messages* 2>/dev/null | tail -30

echo "== logins and shells from the two published scanning addresses"
grep -h -E '130\.94\.19\.(204|168)' /var/log/messages* /var/log/secure* /opt/CPcvpn-*/log/* 2>/dev/null | tail -30

echo "== done"
