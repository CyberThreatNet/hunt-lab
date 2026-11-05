#!/bin/sh
# Synology DSM C3RB3R readiness checks. Read-only where possible. Run on the NAS (SSH) or from an admin session.
# Fixed builds per Synology-SA-24:20: 7.2.2-72806-1, 7.2.1-69057-6, 7.2-64570-4, 7.1.1-42962-7, 6.2.4-25556-8 (or above).

echo "== DSM version (compare with Synology-SA-24:20 fixed builds)"
cat /etc.defaults/VERSION 2>/dev/null || cat /etc/VERSION 2>/dev/null || syno_uname -a 2>/dev/null

echo "== Listening management ports (default 5000/5001)"
ss -ltnp 2>/dev/null | grep -E ':(5000|5001|5005|5006)\b' || netstat -ltnp 2>/dev/null | grep -E ':(5000|5001|5005|5006)\b' || echo "ss/netstat unavailable"

echo "== Quick artefact search on common share roots (may take time on large volumes)"
for root in /volume1 /volume2 /volume3; do
  [ -d "$root" ] || continue
  echo "-- $root"
  find "$root" -xdev -name '*.L0CK3D' 2>/dev/null | head -20
  find "$root" -xdev -name 'read-me3.txt' 2>/dev/null | head -20
done

echo "== Snapshot / shared-folder snapshot status (DSM 7 names vary by package)"
synoshare --get-snapshots 2>/dev/null || echo "synoshare snapshots helper unavailable; check Control Panel > Shared Folder > Snapshot"

echo "== From an untrusted network you own, only test hosts you are authorised to assess:"
echo "   curl -skI https://NAS_HOST:5001/  (a DSM login page means the admin UI is reachable from there)"
