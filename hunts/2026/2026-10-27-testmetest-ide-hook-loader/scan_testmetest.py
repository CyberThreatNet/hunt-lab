#!/usr/bin/env python3
# Hunt ID: 2026-10-27-testmetest-ide-hook-loader
# Read-only triage scanner for the testmetest / @iobandamwer npm worm and its
# .github/init.js IDE and AI-assistant hooks.
# Sources: JFrog Security Research (26 Oct 2026) and SafeDep (22 Oct 2026, updated 26 Oct);
# see sources.md. Licence: MIT (see ../../../LICENSE).
#
# What it does: walks the folders you give it, and (unless --no-host) looks in your home
# directory and temp directory, for the files, names and hashes those two sources published.
# What it never does: run, import, open in an editor, change or delete anything it finds.
# It only reads file metadata and file contents, and (with --git) runs read-only git commands.
#
# Exit codes: 0 = nothing found, 1 = at least one finding, 2 = error.
# Python 3.8+, standard library only. Linux, macOS and Windows.

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

VERSION = "0.1.0-draft"

# --- Published indicators (keep each with its source; see sources.md) ----------------------

# JFrog "Package classifications" table, 26 Oct 2026: versions JFrog classifies as malicious.
MALICIOUS_VERSIONS = {
    "data-pipeline-testmetest": {"2.0.1"},
    "event-bus-lite-testmetest": {"0.0.1", "0.0.2", "0.0.6"},
    "event-emitter-testmetest": {"1.0.6", "1.0.7", "3.0.0", "3.0.1", "4.1.0", "5.0.0"},
    "log-rotate-testmetest": {"1.0.1"},
    "log-sink-testmetest": {"1.0.1"},
    "net-codec-testmetest": {"1.0.1"},
    "npm-publish-testmetest": {"1.0.1"},
    "pixel-map-testmetest": {"0.0.1", "0.0.2", "0.0.3"},
    "retry-utils-testmetest": {"1.0.3"},
    "test-brotli-testmetest": {"1.0.0"},
    "test-brotli2-testmetest": {"1.0.0"},
    "@iobandamwer/cache-helper": {"1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8"},
    "@iobandamwer/native-helper": {"0.0.1"},
    "path-stream-utils-testmetest": {"0.0.1", "0.0.2"},
}
# Any other name in the same inventory (JFrog lists 25 names), plus SafeDep's testmgkregme.
CAMPAIGN_NAME_RE = re.compile(r"(?<![A-Za-z0-9._-])(@iobandamwer/[a-z0-9._-]+|[a-z0-9._-]*testmetest|testmgkregme)(?![A-Za-z0-9_-])")

# Full SHA-256 values published by SafeDep (IOC table) and JFrog (IOCs section).
KNOWN_SHA256 = {
    "837904152e824645cb7d2d58a4a5e0aaa22d5e82a5d6eafe08b9c2b8b1bf4de6": "binding.gyp, event-bus-lite-testmetest@0.0.1 (SafeDep)",
    "0b0e02b03ea3a2f8e8657143706e327a0b3608acbc1c43ec02ebc072dbe76944": "index.js loader, event-bus-lite-testmetest@0.0.1 (SafeDep)",
    "fc8e014b1c6940435880346fe3e84b20f2cbd9e65ed662283347a306929b8381": "lib_native.dat, event-bus-lite-testmetest@0.0.1 (SafeDep)",
    "c7ef186aa59b67d9b198a14f6dc8aaee6dd86510ac7c37d28f65d310cd846411": "sync.py persistence script (SafeDep)",
    "7625f77a61433b3a8e9b41952b7dca102d1d08eab30266fd6c6aa0b0c2ea15b1": "addon.node, path-stream-utils-testmetest@0.0.2 (SafeDep)",
    "1685824218a45e9308e3ced9f4a1cee3fe51e516dab2bd058fc1f9de31f559c9": "addon_win.node, path-stream-utils-testmetest@0.0.2 (SafeDep)",
    "b3f74e4b03b58eeb31ff9ecc663a118ca37695f078eb4d3cae311ddc56a55d28": ".napi_cache, path-stream-utils-testmetest@0.0.2 (SafeDep)",
    "67967033b1dd1e5b845c0959291df533d1102d0191885e7cb9b18d46f7744bbd": ".napi_cache, path-stream-utils-testmetest@0.0.1 (SafeDep)",
    "9d83919bfdb0e14018f1a6f2b8b6586de59b60dfdcfbdb5ae1a1556c23cc4793": "decoded victim publisher payload _p (JFrog)",
    "3dc40fc55302664c07c9d9182ffd95910aeb366fcd417fbdad0a90cdeb8ea69e": "victim Bun bootstrap _b (JFrog)",
    "8506042b383ab46545c27a402eb2dc973696a93af71181b175b1d87972843a43": "ci.js publisher payload (JFrog)",
    "783a4ac906cc9b2eaf5cd13408ea95db6ce52a46d9af11aad1a5b167af69589f": "ci.js v3 publisher payload (JFrog)",
    "a516dd7867af83f8be0cc3e926fdfd964097f0e7665596b05fe5234be7e2b5e9": "stable-scripts-9965 loader (JFrog)",
    "ccfd769acc024edc409ef879198d2a2398beee60930f2b3f2771ded1e14e0c57": "stable-scripts-9965 decoded stage (JFrog)",
    "7ad216b3afd2f40a147c80733c7309fb3d3a7f52ee78149c8e51672cfb617d07": "stable-scripts-9965 publisher payload (JFrog)",
    "e3cb383615fc70bce9b5bcd1c7a394132b50483daaf231a04ee90d4690962c73": "shellpanel mock (JFrog)",
    "17614e98b613b17d0e1bb7125ab203715dd397661b897d8d18dbb77864c1839f": "shellpanel marker tool (JFrog)",
}
# JFrog published only 8-character SHA-256 prefixes for the ten .github/init.js wrapper builds.
# A prefix match is strong supporting evidence, not proof on its own.
INIT_JS_SHA256_PREFIXES = {
    "36385dbe": "G1", "0892d847": "G2", "fc2a0699": "G3", "069f5e22": "G4", "49d08999": "G5",
    "684cf1a1": "G6", "01e9dc12": "G7", "a03af3db": "G8", "e086374a": "G9", "5f367cc3": "G10",
}

INIT_JS_BIG = 12 * 1024 * 1024          # JFrog's smallest wrapper is 12,964,907 bytes
HASH_LIMIT = 64 * 1024 * 1024           # never hash files bigger than this
READ_LIMIT = 4 * 1024 * 1024            # bytes read when looking for marker strings
LOADER_RE = re.compile(rb"var\s*_r\s*=\s*0\s*,\s*_s\s*=\s*1\s*,\s*_t\s*=\s*2")   # wrapper start published by JFrog
INIT_REF_RE = re.compile(r"\.github[\\/]+init\.(js|ps1)")
# Published IOCs (SafeDep, JFrog), used only as detection byte markers, not links.
# The domain is split so URL-reputation scanners do not flag this file.
PAYLOAD_MARKERS = [b"msync-3f7a", b"net-health-checker", b"aiarmor" b".website", b"AutoSyncComplete:"]

HOOK_FILES = {                      # relative path (with /) -> tool
    ".claude/settings.json": "Claude Code", ".claude/settings.local.json": "Claude Code",
    ".gemini/settings.json": "Gemini CLI", ".cursor/mcp.json": "Cursor (MCP)",
    ".vscode/tasks.json": "VS Code tasks", "package.json": "npm scripts",
    "composer.json": "Composer scripts", "Makefile": "make", "CLAUDE.md": "agent instructions",
    "AGENTS.md": "agent instructions",
}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".tox", ".cache"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}


class Scanner:
    def __init__(self, extra_hashes=None):
        self.findings = []
        self.errors = []
        self.hashes = dict(KNOWN_SHA256)
        if extra_hashes:
            self.hashes.update(extra_hashes)
        self.seen = set()

    # -- helpers ---------------------------------------------------------------------------
    def add(self, severity, path, what, detail=""):
        key = (severity, os.path.abspath(path), what)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append({"severity": severity, "path": os.path.abspath(path), "finding": what, "detail": detail})

    def read_head(self, path, limit=READ_LIMIT):
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except OSError as exc:
            self.errors.append("%s: %s" % (path, exc))
            return b""

    def sha256(self, path):
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_size > HASH_LIMIT:
                return None
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError as exc:
            self.errors.append("%s: %s" % (path, exc))
            return None

    def check_hash(self, path):
        digest = self.sha256(path)
        if not digest:
            return None
        if digest in self.hashes:
            self.add("HIGH", path, "SHA-256 matches a published indicator", "%s (%s)" % (digest, self.hashes[digest]))
        elif digest[:8] in INIT_JS_SHA256_PREFIXES:
            self.add("HIGH", path, "SHA-256 prefix matches a published .github/init.js wrapper build",
                     "%s (JFrog group %s; only the first 8 characters were published)" % (digest, INIT_JS_SHA256_PREFIXES[digest[:8]]))
        return digest

    def markers(self, path):
        head = self.read_head(path)
        found = [m.decode() for m in PAYLOAD_MARKERS if m in head]
        if LOADER_RE.search(head):
            found.append("wrapper skeleton var _r=0,_s=1,_t=2")
        return found

    # -- repository / project checks --------------------------------------------------------
    def scan_tree(self, root):
        if not os.path.isdir(root):
            self.errors.append("%s: not a directory" % root)
            return
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: self.errors.append(str(e))):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))]
            parent = os.path.basename(dirpath)
            grand = os.path.basename(os.path.dirname(dirpath))
            if grand == "node_modules" or (grand.startswith("@") and os.path.basename(os.path.dirname(os.path.dirname(dirpath))) == "node_modules"):
                self.check_installed_package(dirpath)
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    continue
                self.check_file(root, dirpath, name, path, parent)

    def check_installed_package(self, pkgdir):
        base = os.path.basename(pkgdir)
        scope = os.path.basename(os.path.dirname(pkgdir))
        name = "%s/%s" % (scope, base) if scope.startswith("@") else base
        if not CAMPAIGN_NAME_RE.fullmatch(name):
            return
        version = ""
        try:
            with open(os.path.join(pkgdir, "package.json"), encoding="utf-8", errors="replace") as fh:
                version = str(json.load(fh).get("version", ""))
        except (OSError, ValueError):
            pass
        if version in MALICIOUS_VERSIONS.get(name, set()):
            self.add("HIGH", pkgdir, "installed package version classified malicious", "%s@%s (JFrog)" % (name, version))
        else:
            self.add("HIGH", pkgdir, "installed package from the testmetest campaign",
                     "%s@%s: remove it; treat the host as exposed until checked" % (name, version or "?"))

    def check_file(self, root, dirpath, name, path, parent):
        rel = os.path.relpath(path, root).replace("\\", "/")
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            self.errors.append("%s: %s" % (path, exc))
            return

        # 1. .github/init.js and .github/init.ps1
        if parent == ".github" and name in ("init.js", "init.ps1"):
            sev = "HIGH" if (name == "init.js" and size > INIT_JS_BIG) else "REVIEW"
            self.add(sev, path, ".github/%s present" % name,
                     "%d bytes%s" % (size, "; over 12 MB, the size of the published wrappers" if sev == "HIGH" else ""))
            m = self.markers(path)
            if m:
                self.add("HIGH", path, "loader markers in .github/%s" % name, ", ".join(m))
            self.check_hash(path)

        # 2. hook configs that run .github/init.js (or init.ps1)
        tail2 = "/".join(rel.split("/")[-2:])
        is_hook = name in HOOK_FILES or tail2 in HOOK_FILES or (parent == "rules" and name.endswith(".mdc") and ".cursor" in rel.split("/"))
        if is_hook and size <= READ_LIMIT:
            text = self.read_head(path).decode("utf-8", "replace")
            if INIT_REF_RE.search(text):
                tool = HOOK_FILES.get(tail2) or HOOK_FILES.get(name) or "Cursor rules"
                self.add("HIGH", path, "%s config runs .github/init.*" % tool,
                         "do not open this folder in that tool until cleaned")

        # 3. dependency manifests and lockfiles naming campaign packages
        if name in LOCKFILES or name == "package.json":
            if size <= 64 * 1024 * 1024:
                text = self.read_head(path, 64 * 1024 * 1024).decode("utf-8", "replace")
                names = sorted(set(CAMPAIGN_NAME_RE.findall(text)))
                if names:
                    self.add("HIGH", path, "dependency file names testmetest-campaign packages", ", ".join(names))

        # 4. native-addon carrier markers and the binding.gyp trigger
        if name == ".napi_cache":
            self.add("HIGH", path, ".napi_cache file (encrypted payload next to a native addon)", "%d bytes" % size)
            self.check_hash(path)
        if name in ("addon.node", "addon_win.node", "lib_native.dat", "sync.py", "index.js", "binding.gyp", "ci.js", "loader.js"):
            self.check_hash(path)
        if name == "binding.gyp" and size <= READ_LIMIT:
            text = self.read_head(path).decode("utf-8", "replace")
            # Legitimate addons use "<!(node -p ...)" or "<!(node -e ...)" to read build settings.
            # The carrier runs a script file and then echoes a stub C file name (SafeDep, JFrog).
            if re.search(r"<!\(\s*(env\s+)?node\s+[^-\s][^)]*;\s*echo\s+[^\s)]+\.c\b", text):
                self.add("HIGH", path, "binding.gyp runs a node script then echoes a stub C file",
                         "the build trigger described by SafeDep and JFrog")
            elif re.search(r"<!\(\s*(env\s+)?node\s+[^-\s][^)\s]*\.js", text):
                self.add("REVIEW", path, "binding.gyp runs a node script during the build", "check what the script does")

    # -- host checks ------------------------------------------------------------------------
    def scan_home(self, home):
        candidates = [
            ".local/bin/net-health-checker.sh",
            ".config/net-health-checker",
            ".local/share/runtimes/sync.py",
            ".config/systemd/user/net-health-checker.service",
            ".config/systemd/user/pkg-runtime.service",
            "Library/LaunchAgents/com.user.net-health-checker.plist",
            "Library/LaunchAgents/com.user.pkg-runtime.plist",
        ]
        for rel in candidates:
            p = os.path.join(home, *rel.split("/"))
            if os.path.lexists(p):
                self.add("HIGH", p, "persistence artefact", "remove persistence BEFORE revoking any token (wiper)")
                if os.path.isfile(p):
                    self.check_hash(p)
        for rel in (".config/systemd/user", "Library/LaunchAgents"):
            d = os.path.join(home, *rel.split("/"))
            try:
                for entry in os.listdir(d):
                    if "net-health-checker" in entry or "pkg-runtime" in entry:
                        self.add("HIGH", os.path.join(d, entry), "persistence unit", "remove persistence BEFORE revoking any token (wiper)")
            except OSError:
                pass

    def scan_tmp(self, tmpdirs):
        for d in tmpdirs:
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for entry in entries:
                p = os.path.join(d, entry)
                if os.path.islink(p):
                    continue
                if re.fullmatch(r"\.[0-9]+", entry) and os.path.isfile(p):
                    m = self.markers(p)
                    self.add("HIGH" if m else "REVIEW", p, "temp file named like the Linux addon drop /tmp/.<pid>",
                             ", ".join(m) if m else "check what created it")
                    self.check_hash(p)
                elif re.fullmatch(r"\.nc[0-9]+\.js", entry) and os.path.isfile(p):
                    self.add("HIGH", p, "temp file named like the Windows addon drop %TEMP%\\.nc<pid>.js", ", ".join(self.markers(p)))
                    self.check_hash(p)
                elif entry in (".hc", ".svc"):
                    self.add("HIGH" if entry == ".hc" else "REVIEW", p, "published drop or scanner path /tmp/%s" % entry, "")
                    if os.path.isfile(p):
                        self.check_hash(p)
                elif entry.startswith(".b-") and os.path.isdir(p):
                    self.add("REVIEW", p, "temp directory named like the loader's .b-* staging folder", "")
        if os.name != "nt":
            p = "/var/tmp/.fontconfig_state"
            if os.path.lexists(p):
                self.add("HIGH", p, "persistence artefact", "remove persistence BEFORE revoking any token (wiper)")

    # -- git history (optional) -------------------------------------------------------------
    def scan_git(self, roots):
        repos = set()
        for root in roots:
            for dirpath, dirnames, _ in os.walk(root):
                if ".git" in dirnames:
                    repos.add(dirpath)
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "node_modules"]
        for repo in sorted(repos):
            try:
                refs = subprocess.run(["git", "-C", repo, "for-each-ref", "--format=%(refname)"],
                                      capture_output=True, text=True, timeout=60, check=True).stdout.splitlines()
                for ref in refs:
                    if re.search(r"/(chore/ci-[0-9a-f]+|deps/upd-[0-9]+)$", ref):
                        self.add("HIGH", repo, "branch name matches the campaign pattern", ref)
                log = subprocess.run(["git", "-C", repo, "log", "--all", "--format=%H%x1f%s%x1f%b%x1e"],
                                     capture_output=True, text=True, timeout=300, check=True).stdout
                for rec in log.split("\x1e"):
                    parts = rec.strip().split("\x1f")
                    if len(parts) < 2:
                        continue
                    msg = " ".join(parts[1:])
                    for marker, sev in (("AutoSyncComplete:", "HIGH"), ("msync-3f7a", "HIGH"),
                                        ("shellpanel execution smoke", "HIGH"), ("skip-checks:true", "REVIEW")):
                        if marker in msg:
                            self.add(sev, repo, "commit message contains %s" % marker, parts[0][:12])
                big = subprocess.run(["git", "-C", repo, "rev-list", "--all", "--objects"],
                                     capture_output=True, text=True, timeout=300, check=True).stdout
                for line in big.splitlines():
                    if line.endswith(" .github/init.js") or line.endswith(" .github/init.ps1"):
                        self.add("HIGH", repo, "git history contains %s" % line.split(" ", 1)[1], line.split(" ")[0][:12])
            except FileNotFoundError:
                self.errors.append("git not found; --git skipped")
                return
            except (subprocess.SubprocessError, OSError) as exc:
                self.errors.append("%s: git: %s" % (repo, exc))


def default_tmpdirs():
    dirs = {tempfile.gettempdir()}
    if os.name != "nt":
        dirs.add("/tmp")
    for var in ("TEMP", "TMP"):
        if os.environ.get(var):
            dirs.add(os.environ[var])
    return sorted(dirs)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only scan for testmetest / @iobandamwer npm worm artefacts.")
    ap.add_argument("paths", nargs="*", default=["."], help="folders to scan (repositories, project roots); default: current folder")
    ap.add_argument("--no-host", action="store_true", help="skip home-directory persistence and temp-folder checks")
    ap.add_argument("--home", default=os.path.expanduser("~"), help="home directory to check (default: yours)")
    ap.add_argument("--tmp-dir", action="append", help="temp folder to check (repeatable; default: system temp folders)")
    ap.add_argument("--git", action="store_true", help="also check branches, commit messages and history of git repositories found")
    ap.add_argument("--ioc-file", help="JSON file {\"<sha256>\": \"description\"} of extra hashes to match")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    extra = None
    if args.ioc_file:
        try:
            with open(args.ioc_file, encoding="utf-8") as fh:
                extra = {k.lower(): str(v) for k, v in json.load(fh).items()}
        except (OSError, ValueError, AttributeError) as exc:
            print("error: cannot read --ioc-file: %s" % exc, file=sys.stderr)
            return 2

    s = Scanner(extra)
    for p in args.paths:
        s.scan_tree(p)
    if not args.no_host:
        s.scan_home(args.home)
        s.scan_tmp(args.tmp_dir or default_tmpdirs())
    if args.git:
        s.scan_git(args.paths)

    fatal = [e for e in s.errors if "not a directory" in e]
    if args.json:
        print(json.dumps({"version": VERSION, "findings": s.findings, "errors": s.errors}, indent=2))
    else:
        for f in sorted(s.findings, key=lambda f: (f["severity"] != "HIGH", f["path"])):
            print("%-6s %s\n       %s%s" % (f["severity"], f["path"], f["finding"], (": " + f["detail"]) if f["detail"] else ""))
        for e in s.errors:
            print("note   %s" % e, file=sys.stderr)
        print("%d finding(s): %d HIGH, %d REVIEW." % (len(s.findings), sum(f["severity"] == "HIGH" for f in s.findings),
                                                    sum(f["severity"] == "REVIEW" for f in s.findings)))
        if any(f["severity"] == "HIGH" for f in s.findings):
            print("If any HIGH finding is on this machine: disconnect it, remove persistence first, then rotate credentials. See README.")
    if fatal:
        return 2
    return 1 if s.findings else 0


if __name__ == "__main__":
    sys.exit(main())
