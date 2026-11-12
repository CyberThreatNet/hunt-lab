#!/usr/bin/env bash
# find-wfx-indicators.sh: search one GitHub user or organisation for wfx (wfx-loot, WFX Phantom) traces.
# Read-only: GitHub search and GET calls through `gh`. Needs gh logged in.
# Search covers what your token can see. Commit search covers default branches only, so
# also run find-run-gaps.sh per repository and check reflogs or audit logs for deleted branches.
# Cyber-Threat.net Hunt Lab, 12 November 2026. MIT licence.
#
# Usage: ./find-wfx-indicators.sh OWNER
set -uo pipefail
owner="${1:?usage: $0 OWNER}"
since="2026-11-10"

echo "== Probe pull requests: 'docs: dependency audit notes' (any state)"
gh search prs --owner "$owner" --match title "docs: dependency audit notes" \
  --created ">=${since}" --limit 200 --json repository,number,state,author,createdAt \
  --jq '.[] | "\(.repository.nameWithOwner)#\(.number)\t\(.state)\t\(.author.login)\t\(.createdAt)"' || true

echo "== Payload and cleanup commits"
for msg in "ci: refresh build cache" "chore: add ci helper" "chore: add dependency audit workflow" "ci: restore" "ci: cleanup"; do
  gh search commits --owner "$owner" "\"${msg}\"" --committer-date ">=${since}" --limit 200 \
    --json repository,sha,commit \
    --jq ".[] | select(.commit.message | startswith(\"${msg}\")) | \"\(.repository.fullName)\t\(.sha[0:7])\t${msg}\t\(.commit.author.name) <\(.commit.author.email)>\t\(.commit.committer.date)\"" || true
done

echo "== Leftover branches: wfx-docs, chore/<8 chars>, ci-check-<4 digits>"
gh repo list "$owner" --limit 1000 --json nameWithOwner --jq '.[].nameWithOwner' |
while read -r repo; do
  gh api --paginate "repos/${repo}/branches?per_page=100" --jq '.[].name' 2>/dev/null |
    grep -E '^(wfx-docs|chore/[a-z0-9]{8}|ci-check-[0-9]{4})$' |
    sed "s|^|${repo}\t|" || true
done

echo "== Probe file docs/wfx-audit.md on default branches (code search)"
gh search code --owner "$owner" --filename wfx-audit.md --json repository,path \
  --jq '.[] | "\(.repository.nameWithOwner)\t\(.path)"' 2>/dev/null || true

echo "Done. For every repository listed, run find-run-gaps.sh and treat a gap after a wfx commit as a completed theft."
