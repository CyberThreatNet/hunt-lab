#!/usr/bin/env bash
# OpenSSH *sshole (CVE-2026-123158) host checks (Cyber-Threat.net Hunt Lab, 6 November 2026)
# Run only on hosts you own. Does not attempt the bypass.
set -euo pipefail

echo "== Effective sshd settings =="
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -iE 'passwordauthentication|usepam|permitrootlogin' || echo "(sshd -T failed)"
else
  echo "(no sshd binary)"
fi

echo
echo "== Accounts with password field exactly * =="
if [[ -r /etc/shadow ]]; then
  awk -F: '$2=="*" {print $1}' /etc/shadow || true
else
  echo "(cannot read /etc/shadow; run as root)"
fi

echo
echo "== alpine user and doas =="
grep -E '^alpine:' /etc/passwd /etc/shadow 2>/dev/null || echo "(no alpine user)"
if [[ -f /etc/doas.conf ]]; then
  grep -nE 'alpine|permit' /etc/doas.conf || true
fi
if [[ -d /etc/doas.d ]]; then
  grep -RIn --include='*' 'alpine\|permit' /etc/doas.d 2>/dev/null || true
fi

echo
echo "== openssh package (Alpine apk) =="
if command -v apk >/dev/null 2>&1; then
  apk info -v openssh openssh-server openssh-server-pam 2>/dev/null || true
else
  echo "(not Alpine apk)"
  command -v rpm >/dev/null 2>&1 && rpm -q openssh-server 2>/dev/null || true
  command -v dpkg >/dev/null 2>&1 && dpkg -l 'openssh*' 2>/dev/null | awk '/^ii/ {print}' || true
fi

echo
echo "== Recent Accepted password lines (last 200 matching) =="
if [[ -f /var/log/messages ]]; then
  grep -E 'Accepted password for' /var/log/messages | tail -n 200 || true
elif command -v journalctl >/dev/null 2>&1; then
  journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep -E 'Accepted password for' | tail -n 200 || true
else
  echo "(no /var/log/messages or journalctl)"
fi

echo
echo "Done. If a * account shows Accepted password, treat the host as suspect."
