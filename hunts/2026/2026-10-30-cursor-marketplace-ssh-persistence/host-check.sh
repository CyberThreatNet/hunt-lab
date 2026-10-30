#!/usr/bin/env bash
# Read-only host checks for Cursor Marketplace implant artefacts (macOS/Linux).
# Defensive only. Does not modify the system. Exit 1 if any high signal found.
set -euo pipefail
found=0
check() {
  local label="$1"; shift
  if "$@"; then
    echo "HIT: $label"
    found=1
  else
    echo "ok: $label"
  fi
}
check "svc-telemetry in ~/.ssh/authorized_keys"   grep -qs 'svc-telemetry' "${HOME}/.ssh/authorized_keys" 2>/dev/null
check "LaunchAgent com.apple.sysmond.plist"   test -f "${HOME}/Library/LaunchAgents/com.apple.sysmond.plist"
check "helper ~/.config/.smt"   test -f "${HOME}/.config/.smt"
check "helper ~/.config/.smtk"   test -f "${HOME}/.config/.smtk"
if command -v crontab >/dev/null 2>&1; then
  if crontab -l 2>/dev/null | grep -qs '\.smt'; then
    echo "HIT: crontab references .smt"
    found=1
  else
    echo "ok: crontab .smt"
  fi
fi
if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP@134.209.82.225 2>/dev/null | grep -qs .; then
    echo "HIT: live connection toward 134.209.82.225"
    found=1
  else
    echo "ok: no live socket to C2 IP"
  fi
fi
exit "$found"
