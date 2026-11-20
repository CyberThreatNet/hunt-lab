#!/usr/bin/env bash
# Cyber-Threat.net Hunt Lab, 17 November 2026. MIT licence.
# Fetch your Optimizely Web snippet(s) and look for the 16 November 2026 injection.
# Usage: ./optimizely-snippet-check.sh <project_id_or_snippet_url> [...]
# A clean result today does not prove you were clean on 16 November: Optimizely
# removed the code. Check Optimizely change history and any script-monitoring
# archive (for example urlscan.io history) for 16 November as well.
set -euo pipefail
pat='1688360\.cc|webshell\.lol|MTY4ODM2MC5jYy|aHR0cHM6Ly8xNjg4MzYwLmNj|window\._k7|__k7b|02111110|5vobauua3ojpklx|eil786npto9u5bq'
for arg in "$@"; do
  case "$arg" in
    http*) url="$arg" ;;
    *) url="https://cdn.optimizely.com/js/${arg}.js" ;;
  esac
  body=$(curl -fsSL --max-time 30 "$url") || { echo "FETCH FAILED $url"; continue; }
  sha=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  if printf '%s' "$body" | grep -Eq "$pat"; then
    echo "SUSPICIOUS $url sha256=$sha"
    printf '%s' "$body" | grep -Eo ".{0,80}($pat).{0,80}" | head -5
  else
    echo "no known indicator $url sha256=$sha"
  fi
  # Show whether the snippet carries Project JavaScript at all, for manual review.
  if printf '%s' "$body" | grep -q '"projectJS"'; then
    echo "  note: snippet has projectJS; review it against what your team wrote"
  fi
done
