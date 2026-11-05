#!/usr/bin/env bash
# CRAFTY FALCON / ARTEX Docker host checks (Cyber-Threat.net Hunt Lab, 5 November 2026)
# Run only on hosts you own. Does not exploit the backdoor.
set -euo pipefail

BACKDOOR_SHA="d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573"
BUILD_ID="3aC1db3gGU08O4UHbAt4J"

echo "== Docker images matching known backdoored names =="
docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Digest}}' 2>/dev/null \
  | grep -E '^(tomicdd|congdonglinux)/artex' || echo "(none listed)"

echo
echo "== Compose / config references =="
if command -v docker >/dev/null 2>&1; then
  docker compose config 2>/dev/null | grep -nE 'image: *(tomicdd|congdonglinux)/artex' || echo "(no compose match or no compose file)"
fi

echo
echo "== Running containers: binary hash of /app/artex =="
for cid in $(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | awk '/artex/ {print $1}'); do
  echo "-- container $cid"
  docker exec "$cid" sha256sum /app/artex 2>/dev/null || echo "  (no /app/artex)"
done

echo
echo "== Local console UI build ID (127.0.0.1:8787 only) =="
if command -v curl >/dev/null 2>&1; then
  hits=$(curl -fsS --max-time 3 http://127.0.0.1:8787/ 2>/dev/null | grep -c "$BUILD_ID" || true)
  echo "build id hits: ${hits:-0} (1+ suggests backdoored UI build per BadByte)"
else
  echo "curl not available"
fi

echo
echo "== Expected backdoored binary SHA-256 (BadByte) =="
echo "$BACKDOOR_SHA"
