#!/usr/bin/env python3
"""Compile every .yar / .yara file; exit 1 on any failure. Pass if none."""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yara
except ImportError:
    print("yara-python not installed", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    root = Path(".")
    files = sorted(
        p for p in list(root.rglob("*.yar")) + list(root.rglob("*.yara"))
        if ".git" not in p.parts
    )
    if not files:
        print("yara: no .yar files (pass)")
        print(f"count=0")
        return 0
    bad = 0
    for path in files:
        try:
            yara.compile(filepath=str(path))
            print(f"ok   {path}")
        except yara.Error as exc:
            bad += 1
            print(f"FAIL {path}: {exc}")
    print(f"count={len(files)} bad={bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
