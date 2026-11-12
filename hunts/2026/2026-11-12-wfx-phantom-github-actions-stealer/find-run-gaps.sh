#!/usr/bin/env bash
# find-run-gaps.sh: list missing GitHub Actions run numbers per workflow since a date.
# A deleted run leaves a gap in run_number. wfx deletes the run that carried its payload,
# so a gap right after a wfx commit is the strongest sign the stealer ran.
# Read-only: uses `gh api` GET calls only. Needs gh logged in with read access to Actions.
# Cyber-Threat.net Hunt Lab, 12 November 2026. MIT licence.
#
# Usage: ./find-run-gaps.sh OWNER/REPO [SINCE_DATE]
#   SINCE_DATE defaults to 2026-11-10 (campaign start, Aikido: 12:45 UTC on 10 November 2026).
# Output: workflow name, the run numbers either side of each gap, and how many are missing.
# Run numbers are counted per workflow, so gaps are reported per workflow file.
set -euo pipefail
repo="${1:?usage: $0 OWNER/REPO [SINCE_DATE]}"
since="${2:-2026-11-10}"
gh api --paginate "repos/${repo}/actions/runs?per_page=100&created=>=${since}" \
  --jq '.workflow_runs[] | [.workflow_id, .name, .run_number] | @tsv' |
sort -t$'\t' -k1,1n -k3,3n -u |
awk -F'\t' '
  $1 == wf && $3 > prev + 1 { printf "%s\tgap after run #%d, next is #%d (%d missing)\n", name, prev, $3, $3 - prev - 1 }
  { wf = $1; name = $2; prev = $3 }'
