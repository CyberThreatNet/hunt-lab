#!/usr/bin/env bash
# CWPdoor host checks (Cyber-Threat.net Hunt Lab, 6 November 2026)
# Run only on hosts you own. Does not trigger the backdoor.
set -euo pipefail

CWP_BIN="${CWP_BIN:-/usr/local/cwpsrv/bin/cwpsrv}"
BAD_MD5_SCRIPT="e505d4ffa21cf494a5dc2d7c8f4f1236"
BAD_MD5_115="965aea67fb40de1bab5169ada993349f"
BAD_MD5_124="d3f4e95113d49ab3991b45e457bda75b"

echo "== Unix socket ngx_http_integrity_helper =="
if command -v ss >/dev/null 2>&1; then
  ss -axp 2>/dev/null | grep -i integrity || echo "(no integrity socket match)"
else
  echo "(ss not available)"
fi

echo
echo "== cwpsrv processes =="
ps aux 2>/dev/null | grep -E '[c]wpsrv' || echo "(no cwpsrv process)"

echo
echo "== strings X-Ngx-Integrity in ${CWP_BIN} =="
if [[ -f "$CWP_BIN" ]]; then
  if command -v strings >/dev/null 2>&1; then
    strings "$CWP_BIN" | grep -E 'X-Ngx-Integrity|ngx_http_integrity' || echo "(no integrity strings)"
  else
    echo "(strings not available)"
  fi
  echo
  echo "== md5sum =="
  if command -v md5sum >/dev/null 2>&1; then
    sum=$(md5sum "$CWP_BIN" | awk '{print $1}')
    echo "$sum  $CWP_BIN"
    case "$sum" in
      "$BAD_MD5_115"|"$BAD_MD5_124"|"$BAD_MD5_SCRIPT") echo "MATCHES XLab bad MD5" ;;
      *) echo "(does not match published bad MD5s; still check strings/socket)" ;;
    esac
  fi
  echo
  echo "== possible installer backups =="
  ls -la /usr/local/cwpsrv/bin/cwpsrv.prev-* 2>/dev/null || echo "(no cwpsrv.prev-* found)"
else
  echo "(binary not found at $CWP_BIN)"
fi

echo
echo "Done. Socket or X-Ngx-Integrity strings => treat as infected per XLab."
