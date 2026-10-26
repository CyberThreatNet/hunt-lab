#!/usr/bin/env bash
# Broken-case tests for scripts/refresh_kev_epss.py.
#
# Offline: the live feeds are replaced with simulated data, so no network is used.
# Every test runs on a throwaway copy of the repository in a temporary directory;
# the checkout you run it from is never changed. Needs bash, python3 (3.9+),
# GNU coreutils and GNU sed (as on the GitHub ubuntu runners).
#
#   bash scripts/tests/test_refresh_kev_epss.sh
#
# Exit code: the number of failed tests (0 = all passed).
# Licence: MIT (see LICENSE).
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
W="${TMP}/repo"
OUT="${TMP}/out"
pass=0
fail=0

ok()  { echo "PASS  $1"; pass=$((pass + 1)); }
bad() { echo "FAIL  $1"; sed 's/^/      /' "${OUT}"; fail=$((fail + 1)); }

reset() {
  rm -rf "${W}"
  mkdir -p "${W}"
  tar -C "${REPO}" --exclude=.git -cf - . | tar -C "${W}" -xf -
}

# Fingerprint of everything a refresh may write.
tree() { (cd "${W}" && find hunts README.md -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum); }

# Pick test subjects from the repository rather than hard-coding hunt names.
# SCORED: a cve-context.yaml with at least one EPSS score. RULELESS: one in a hunt with no rule.yml.
SCORED=""
RULELESS=""
while IFS= read -r f; do
  rel="${f#"${REPO}"/}"
  if [[ -z "${SCORED}" ]] && grep -Eq '^      epss: [0-9]' "${f}"; then SCORED="${rel}"; fi
  if [[ -z "${RULELESS}" && ! -f "$(dirname "${f}")/rule.yml" ]]; then RULELESS="${rel}"; fi
done < <(find "${REPO}/hunts" -name cve-context.yaml | sort)
if [[ -z "${SCORED}" ]]; then echo "no cve-context.yaml with an EPSS score; nothing to test"; exit 1; fi

# --- Offline --check cases -------------------------------------------------------------

chk() { (cd "${W}" && python3 scripts/refresh_kev_epss.py --check > "${OUT}" 2>&1); }
expect_check_fail() {
  if chk; then bad "$1 (--check passed)"; else ok "$1"; fi
}

reset; if chk; then ok "unchanged repository passes --check"; else bad "unchanged repository fails --check"; fi
reset; sed -i '0,/^      epss: [0-9].*/s//      epss: 1.5/' "${W}/${SCORED}";   expect_check_fail "--check: EPSS out of range"
reset; sed -i '0,/^      kev_listed: false/s//      kev_listed: true/' "${W}/${SCORED}"
if grep -q 'kev_listed: true' "${W}/${SCORED}"; then expect_check_fail "--check: listed in KEV but no KEV dates"; fi
reset; sed -i '0,/^      epss_note:.*/{//d}' "${W}/${SCORED}";               expect_check_fail "--check: missing field"
reset; rm "${W}/${SCORED}";                                                      expect_check_fail "--check: cve-context.yaml deleted"
if [[ -n "${RULELESS}" ]]; then
  reset; rm "${W}/${RULELESS}";                                                  expect_check_fail "--check: cve-context.yaml deleted from a hunt with no rule.yml"
else
  echo "SKIP  --check: no hunt without a rule.yml has a cve-context.yaml"
fi
reset; sed -i 's/^<!-- kev-epss:end -->$/| stale | row |\n&/' "${W}/README.md";    expect_check_fail "--check: README table out of date"

# --- Refresh cases with simulated feeds ------------------------------------------------
# PATCH is Python run after the script is imported as module r, to replace the feeds.

run() {
  (cd "${W}" && PATCH="${PATCH}" python3 - "$@" > "${OUT}" 2>&1 <<'PY'
import http.client, io, os, sys, urllib.request
sys.argv = ["refresh_kev_epss.py", "--date", "2026-01-02"] + sys.argv[1:]
sys.path.insert(0, "scripts")
import refresh_kev_epss as r

class Resp(io.BytesIO):
    def __init__(self, url, body=b"{}"):
        super().__init__(body)
        self._url = url
    def geturl(self):
        return self._url
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False

def kev_none():
    return ("2026.01.01", {})

exec(os.environ["PATCH"])
sys.exit(r.main())
PY
  )
}

# Expect exit code $2, no file changed, and one "error: ... Nothing changed" line.
expect_nochange() {
  local name="$1" want="$2" before after rc
  before="$(tree)"; run "${@:3}"; rc=$?; after="$(tree)"
  if [[ ${rc} -eq ${want} && "${before}" == "${after}" ]] && grep -q '^error: .*Nothing changed' "${OUT}"; then
    ok "${name} (exit ${rc}, nothing written)"
  else
    bad "${name} (exit ${rc}, wanted ${want}; files changed: $([[ "${before}" != "${after}" ]] && echo yes || echo no))"
  fi
}

old_epss() { grep -m1 '^      epss: ' "${W}/${SCORED}"; }

reset; before_epss="$(old_epss)"
# One CVE empty, the rest answered: a gap. Keep the old score and warn.
PATCH='r.fetch_kev = kev_none
target = r.context_cves(r.ROOT / os.path.dirname(os.environ["SCORED"]))[0]
def fake(cves):
    return {c: {"cve": c, "epss": "0.5", "percentile": "0.5", "date": "2026-01-02"} for c in cves if c != target}
r.fetch_epss = fake'
export SCORED
run; rc=$?
if [[ ${rc} -eq 0 && "$(old_epss)" == "${before_epss}" ]] && grep -q "^warning: .*FIRST EPSS returned no score; kept" "${OUT}" && chk; then
  ok "one CVE empty from FIRST: old score kept, warning printed, --check passes"
else
  bad "one CVE empty from FIRST (exit ${rc})"
fi

reset
PATCH='r.fetch_kev = kev_none
target = r.context_cves(r.ROOT / os.path.dirname(os.environ["SCORED"]))[0]
def fake(cves):
    return {c: {"cve": c, "epss": "0.5", "percentile": "0.5", "date": "2026-01-02"} for c in cves if c != target}
r.fetch_epss = fake'
run --allow-null; rc=$?
if [[ ${rc} -eq 0 ]] && grep -q '^      epss: null' "${W}/${SCORED}" && grep -q 'Not yet scored' "${W}/${SCORED}" && chk; then
  ok "--allow-null: one empty CVE recorded as null with a note"
else
  bad "--allow-null (exit ${rc})"
fi

# Every CVE empty, some scored before: an outage. Exit 3, nothing written, also with --allow-null.
reset; PATCH='r.fetch_kev = kev_none
r.fetch_epss = lambda cves: {}'
expect_nochange "every CVE empty from FIRST: outage" 3
reset; expect_nochange "every CVE empty from FIRST with --allow-null: still an outage" 3 --allow-null
if ! grep -q '^error: FIRST EPSS returned no score for any of the' "${OUT}"; then bad "outage message wording"; fi

# Every CVE empty, none scored before (e.g. a repository whose CVEs are all new): a gap, not an outage.
reset; PATCH='r.fetch_kev = kev_none
r.fetch_epss = lambda cves: {}
r.existing_entries = lambda hunt: {}'
run; rc=$?
if [[ ${rc} -eq 0 ]] && grep -q '^      epss: null' "${W}/${SCORED}" && chk; then
  ok "every CVE empty but none scored before: treated as a gap (exit 0, null with note)"
else
  bad "all empty, none scored before (exit ${rc})"
fi

reset; PATCH='r.fetch_kev = kev_none
r.fetch_epss = lambda cves: {}'
before="$(tree)"; run --date 26-10-2026; rc=$?
if [[ ${rc} -eq 2 && "$(tree)" == "${before}" ]]; then ok "bad --date: usage error (exit 2, nothing written)"; else bad "bad --date (exit ${rc})"; fi

reset; PATCH='urllib.request.urlopen = lambda req, timeout=0: Resp("http://example.invalid/feed.json")'
expect_nochange "redirect to a non-HTTPS URL" 1
reset; PATCH='def boom(*a, **k):
    raise http.client.IncompleteRead(b"")
urllib.request.urlopen = boom'
expect_nochange "connection dropped mid-read" 1
reset; PATCH='def boom(*a, **k):
    raise OSError("connection reset")
urllib.request.urlopen = boom'
expect_nochange "network error" 1
reset; PATCH='urllib.request.urlopen = lambda req, timeout=0: Resp(req.full_url, b"{\"vulns\": []}")'
expect_nochange "KEV feed format changed" 1
reset; PATCH='r.fetch_kev = kev_none
r.fetch_epss = lambda cves: {c: {"cve": c, "epss": "abc", "percentile": "0.5", "date": "2026-01-02"} for c in cves}'
expect_nochange "EPSS value not a number" 1
reset; sed -i 's/^<!-- kev-epss:end -->$//' "${W}/README.md"
PATCH='r.fetch_kev = kev_none
r.fetch_epss = lambda cves: {c: {"cve": c, "epss": "0.5", "percentile": "0.5", "date": "2026-01-02"} for c in cves}'
expect_nochange "README table markers broken: no hunt file written either" 1

echo
echo "${pass} passed, ${fail} failed"
exit "${fail}"
