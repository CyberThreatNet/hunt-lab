#!/usr/bin/env python3
"""Flag Sigma |re values that cannot work on Elastic (ES|QL RLIKE, EQL regex, Lucene regexp).

Elastic evaluates these with Lucene's regular-expression engine, which must match the whole
field value and has no ^ or $ anchors, no \\b, \\B, \\A, \\z or \\Z, and no (?...) groups such
as (?i) or lookarounds. A Sigma pattern that relies on them still converts without error, but
the converted check can never match as intended. See
https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax

Also flagged: the |re|i, |re|m and |re|s modifiers (the backends turn them into a (?i), (?m)
or (?s) prefix); any top-level alternative that does not start with .* (Sigma |re searches,
Elastic matches the whole value); and any backslash-letter or -digit escape other than
\\s \\S \\d \\D \\w \\W, which Lucene reads as a literal character.

Not checked: Lucene's optional operators @ # & < > ~ are live by default in a regexp query
(flags ALL), so an unescaped user@host means "anything" there. They do not matter for ES|QL
today; escape them if a Lucene target is ever added.

Usage: check_elastic_regex.py RULE.yml [RULE.yml ...]
Exit 0 if no problem was found, 1 if any pattern was flagged, 2 on a read or parse error.
Cyber-Threat.net Hunt Lab - https://github.com/CyberThreatNet/hunt-lab - MIT
"""
import re
import sys

import yaml

BAD_ESCAPES = {"b": r"\b", "B": r"\B", "A": r"\A", "z": r"\z", "Z": r"\Z"}
LUCENE_CLASS_ESCAPES = set("sSdDwW")  # Lucene supports these; any other backslash-letter or digit is a literal there
RE_FLAG_MODIFIERS = {"i", "m", "s"}  # Sigma re sub-modifiers; the backends turn them into (?i), (?m), (?s)


def top_level_alternatives(pattern):
    """Split a regex on | outside groups and character classes."""
    parts, depth, in_class, start, i = [], 0, False, 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if pattern[i + 1 : i + 2] == "^":
                i += 1
            if pattern[i + 1 : i + 2] == "]":
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(pattern[start:i])
            start = i + 1
        i += 1
    parts.append(pattern[start:])
    return parts


def problems(pattern, modifiers=()):
    """Return the Lucene-incompatible constructs used in a regex, outside character classes."""
    found = [f"|re|{m} (converted to (?{m}))" for m in sorted(RE_FLAG_MODIFIERS & set(modifiers))]
    i, in_class = 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if not in_class and nxt in BAD_ESCAPES:
                found.append(BAD_ESCAPES[nxt])
            elif nxt.isalnum() and nxt not in LUCENE_CLASS_ESCAPES:
                found.append(f"\\{nxt} (a literal '{nxt}' on Elastic)")
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if pattern[i + 1 : i + 2] == "^":
                i += 1  # negated class, not an anchor
            if pattern[i + 1 : i + 2] == "]":
                i += 1  # literal ] as the first class member
        elif c in "^$":
            found.append(f"{c} anchor")
        elif c == "(" and pattern[i + 1 : i + 2] == "?":
            found.append("(?...) group")
        i += 1
    if any(not alt.startswith((".*", "^")) for alt in top_level_alternatives(pattern)):
        found.append("no leading .* (Elastic matches the whole value; Sigma |re matches anywhere)")
    return sorted(set(found))


def regex_values(node):
    """Yield (field|modifiers, value) for every |re item in a detection section."""
    if isinstance(node, dict):
        for key, value in node.items():
            key = str(key)
            if "re" in key.split("|")[1:]:
                values = value if isinstance(value, list) else [value]
                for v in values:
                    yield key, str(v)
            else:
                yield from regex_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from regex_values(item)


def main(paths):
    status = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if d]
        except (OSError, yaml.YAMLError) as exc:
            print(f"::error file={path}::cannot read rule: {exc}")
            return 2
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            for key, value in regex_values(doc.get("detection", {})):
                bad = problems(value, key.split("|")[1:])
                if bad:
                    status = 1
                    print(
                        f"::error file={path}::{key} '{value}': {'; '.join(bad)}. Elastic's Lucene regex engine "
                        "matches the whole value and lacks these, so the converted check errors or never matches. "
                        "Rewrite it as a whole-value match, or drop the Elastic target and say why in ci-targets.txt."
                    )
    return status


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
