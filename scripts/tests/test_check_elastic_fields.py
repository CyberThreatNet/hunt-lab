#!/usr/bin/env python3
"""Unit cases for scripts/check_elastic_fields.py: each case lists the fields that must be flagged.
Offline, standard library plus PyYAML. Run from anywhere: python scripts/tests/test_check_elastic_fields.py
Exit 0 if every case passes, 1 otherwise. Cyber-Threat.net Hunt Lab - MIT (see LICENSE).
"""
import os, sys, tempfile, contextlib, io
import yaml
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from check_elastic_fields import unmapped, main

PROC = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable, CommandLine: process.command_line}
    rule_conditions: [{type: logsource, category: process_creation}]
  - type: add_condition
    conditions: {event.category: process}
    rule_conditions: [{type: logsource, category: process_creation}]
"""
PROC_DESC = PROC.replace("CommandLine: process.command_line", "CommandLine: process.command_line, Description: process.pe.description")
FILE = PROC + """
  - type: field_name_mapping
    mapping: {TargetFilename: file.path, Image: process.executable}
    rule_conditions: [{type: logsource, category: file_event}]
"""
WIN_ONLY = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable}
    rule_conditions: [{type: logsource, category: process_creation, product: windows}]
"""
GLOBAL = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable}
"""
COND_NOT = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable}
    rule_conditions: [{type: logsource, category: process_creation}]
    rule_cond_not: true
"""
FIELD_COND = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable}
    rule_conditions: [{type: logsource, category: process_creation}]
    field_name_conditions: [{type: include_fields, fields: [Image]}]
"""
OTHER_COND = """
transformations:
  - type: field_name_mapping
    mapping: {Image: process.executable}
    rule_conditions: [{type: contains_detection_item, field: Image, value: x}]
"""

def rule(logsource, detection):
    return {"title": "t", "logsource": logsource, "detection": detection}

PC = {"category": "process_creation"}
FE = {"category": "file_event"}
cases = [
 ("mapped fields pass", PROC, rule(PC, {"sel": {"Image|endswith": "\\x.exe", "CommandLine|contains": "y"}, "condition": "sel"}), []),
 ("Description before C1", PROC, rule(PC, {"sel": {"Description": "Rsync"}, "condition": "sel"}), ["Description"]),
 ("Description after C1", PROC_DESC, rule(PC, {"sel": {"Description": "Rsync"}, "condition": "sel"}), []),
 ("file_event without a file_event mapping", PROC, rule(FE, {"sel": {"TargetFilename|endswith": "/a"}, "condition": "sel"}), ["TargetFilename"]),
 ("file_event with the mapping", FILE, rule(FE, {"sel": {"TargetFilename|endswith": "/a", "Image": "/b"}, "condition": "sel"}), []),
 ("process mapping doesn't cover file_event", FILE, rule(FE, {"sel": {"CommandLine": "x"}, "condition": "sel"}), ["CommandLine"]),
 ("ECS name already used passes", FILE, rule(FE, {"sel": {"file.path|endswith": "/a"}, "condition": "sel"}), []),
 ("keyword search has no field", PROC, rule(PC, {"keywords": ["evil", "bad"], "condition": "keywords"}), []),
 ("list of maps", PROC, rule(PC, {"sel": [{"Image": "a"}, {"ParentImage": "b"}], "condition": "sel"}), ["ParentImage"]),
 ("modifier chain stripped", FILE, rule(FE, {"sel": {"TargetFilename|contains|all": ["a", "b"]}, "condition": "sel"}), []),
 ("fieldref value is a field", PROC, rule(PC, {"sel": {"Image|fieldref": "OriginalFileName"}, "condition": "sel"}), ["OriginalFileName"]),
 ("search identifiers and condition are not fields", PROC, rule(PC, {"selection_img": {"Image": "a"}, "filter_main": {"Image": "b"}, "condition": "selection_img and not filter_main", "timeframe": "5m"}), []),
 ("product condition must match", WIN_ONLY, rule({"category": "process_creation", "product": "linux"}, {"sel": {"Image": "a"}, "condition": "sel"}), ["Image"]),
 ("product condition matches", WIN_ONLY, rule({"category": "process_creation", "product": "windows"}, {"sel": {"Image": "a"}, "condition": "sel"}), []),
 ("mapping without conditions applies to all", GLOBAL, rule({"product": "windows", "service": "security"}, {"sel": {"Image": "a"}, "condition": "sel"}), []),
 ("service rule against a category pipeline", PROC, rule({"product": "windows", "service": "security"}, {"sel": {"EventID": 4662}, "condition": "sel"}), ["EventID"]),
 ("non-logsource rule condition not assumed", OTHER_COND, rule(PC, {"sel": {"Image": "a"}, "condition": "sel"}), ["Image"]),
 ("rule_cond_not mapping not assumed (fail closed)", COND_NOT, rule(PC, {"sel": {"Image": "a"}, "condition": "sel"}), ["Image"]),
 ("field_name_conditions mapping not assumed (fail closed)", FIELD_COND, rule(PC, {"sel": {"Image": "a"}, "condition": "sel"}), ["Image"]),
 ("several unmapped, sorted", PROC, rule(FE, {"sel": {"TargetFilename": "a", "Image": "b", "User": "c"}, "condition": "sel"}), ["Image", "TargetFilename", "User"]),
]

bad = 0
for name, pipe, doc, expected in cases:
    got = unmapped(doc, [yaml.safe_load(pipe)])
    if got != expected:
        bad += 1; print("FAIL", name, "expected", expected, "got", got)

# The repository pipeline itself: every Sigma field it maps passes for its own category.
repo = os.path.join(HERE, "..", "..", "pipelines", "ecs-process-creation.yml")
with open(repo, encoding="utf-8") as fh:
    repo_docs = [yaml.safe_load(fh)]
total = len(cases)
for item in repo_docs[0]["transformations"]:
    if item.get("type") != "field_name_mapping":
        continue
    cat = item["rule_conditions"][0]["category"]
    doc = rule({"category": cat}, {"sel": {f: "x" for f in item["mapping"]}, "condition": "sel"})
    total += 1
    got = unmapped(doc, repo_docs)
    if got:
        bad += 1; print("FAIL repo pipeline", cat, got)
for cat, field in (("file_event", "TargetFilename"), ("process_creation", "Description"), ("process_creation", "Image")):
    total += 1
    got = unmapped(rule({"category": cat}, {"sel": {field: "x"}, "condition": "sel"}), repo_docs)
    if got:
        bad += 1; print("FAIL repo pipeline must map", cat, field, got)
total += 1
got = unmapped(rule({"category": "network_connection"}, {"sel": {"DestinationIp": "x"}, "condition": "sel"}), repo_docs)
if got != ["DestinationIp"]:
    bad += 1; print("FAIL repo pipeline must not map network_connection", got)

# Exit codes through main(): 0 clean, 1 unmapped, 2 unreadable rule or pipeline.
with tempfile.TemporaryDirectory() as tmp:
    def write(name, text):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path
    pipe = write("p.yml", FILE)
    ok = write("ok.yml", yaml.safe_dump(rule(FE, {"sel": {"TargetFilename": "a"}, "condition": "sel"})))
    nok = write("nok.yml", yaml.safe_dump(rule(FE, {"sel": {"Hashes": "a"}, "condition": "sel"})))
    broken = write("broken.yml", "detection: [unclosed\n")
    for args, exp in (([pipe, ok], 0), ([pipe, nok], 1), ([pipe, ok, nok], 1), ([pipe, broken], 2),
                      ([os.path.join(tmp, "missing.yml"), ok], 2), ([pipe], 2), ([pipe, os.path.join(tmp, "none.yml")], 2)):
        total += 1
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(args)
        if rc != exp:
            bad += 1; print("FAIL exit code", [os.path.basename(a) for a in args], "expected", exp, "got", rc)

print(f"{total - bad}/{total} passed"); sys.exit(1 if bad else 0)
