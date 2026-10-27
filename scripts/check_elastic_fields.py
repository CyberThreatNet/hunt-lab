#!/usr/bin/env python3
"""Flag Sigma fields that a repository ECS pipeline does not map, for Elastic targets (ES|QL, EQL, Lucene).

The elasticsearch backend keeps any field the pipeline does not map under its bare Sigma name
(for example TargetFilename or Description). Elastic data has no such field, so EQL and ES|QL
reject the whole query and Lucene silently matches nothing, yet `sigma convert` still exits 0.
This check compares every field a rule's detection section uses with the field_name_mapping
transformations in the pipeline that apply to the rule.
Treats a mapping as applying only when its logsource rule_conditions match the rule (category/product/service, all must match). Items with any other condition type are treated as not applying, so the check fails closed.

A field passes if it is a key of an applicable mapping, or is already one of that mapping's ECS
target names. Keyword searches (values without a field) are not field references and pass.
Values of the |fieldref modifier are field names too and are checked the same way.

Usage: check_elastic_fields.py PIPELINE.yml RULE.yml [RULE.yml ...]
Exit 0 if every field is mapped, 1 if any field is not, 2 on a read or parse error.
Cyber-Threat.net Hunt Lab - https://github.com/CyberThreatNet/hunt-lab - MIT
"""
import sys

import yaml

LOGSOURCE_KEYS = ("category", "product", "service")
# Item keys whose conditions this check does not model; an item carrying any of them is treated as not applying.
UNMODELLED_KEYS = (
    "rule_cond_not",
    "rule_cond_op",
    "rule_cond_expr",
    "field_name_conditions",
    "field_name_cond_not",
    "detection_item_conditions",
)


def load_docs(path):
    with open(path, encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def applies(rule_conditions, logsource):
    """True if a pipeline item's logsource conditions all match the rule (no conditions: applies to all)."""
    conds = rule_conditions or []
    for cond in conds:
        if not isinstance(cond, dict) or cond.get("type") != "logsource":
            # Any other rule condition can't be evaluated statically: treat the mapping as not applying.
            return False
        for key in LOGSOURCE_KEYS:
            if cond.get(key) is not None and cond.get(key) != logsource.get(key):
                return False
    return True


def mapped_fields(pipeline_docs, logsource):
    """Return (sigma names, ECS names) from the field_name_mapping items that apply to this logsource."""
    sigma, ecs = set(), set()
    for doc in pipeline_docs:
        if not isinstance(doc, dict):
            continue
        for item in doc.get("transformations") or []:
            if not isinstance(item, dict) or item.get("type") != "field_name_mapping":
                continue
            if any(key in item for key in UNMODELLED_KEYS):
                continue
            if not applies(item.get("rule_conditions"), logsource):
                continue
            for src, dst in (item.get("mapping") or {}).items():
                sigma.add(str(src))
                ecs.update(str(d) for d in (dst if isinstance(dst, list) else [dst]))
    return sigma, ecs


def rule_fields(node):
    """Yield every field name used in the search identifiers' values (a map, or a list of maps)."""
    if isinstance(node, dict):
        for key, value in node.items():
            parts = str(key).split("|")
            if parts[0]:
                yield parts[0]
            if "fieldref" in parts[1:]:
                for v in value if isinstance(value, list) else [value]:
                    yield str(v)
            if isinstance(value, (dict, list)):
                yield from rule_fields(value)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                yield from rule_fields(item)


def unmapped(rule_doc, pipeline_docs):
    """Return the sorted fields of one rule document that the pipeline leaves unmapped."""
    logsource = {k: rule_doc.get("logsource", {}).get(k) for k in LOGSOURCE_KEYS}
    sigma, ecs = mapped_fields(pipeline_docs, logsource)
    searches = [v for k, v in (rule_doc.get("detection") or {}).items() if k not in ("condition", "timeframe")]
    return sorted({f for f in rule_fields(searches) if f not in sigma and f not in ecs})


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    pipeline_path, rule_paths = argv[0], argv[1:]
    try:
        pipeline_docs = load_docs(pipeline_path)
    except (OSError, yaml.YAMLError) as exc:
        print(f"::error file={pipeline_path}::cannot read pipeline: {exc}")
        return 2
    status = 0
    for path in rule_paths:
        try:
            docs = load_docs(path)
        except (OSError, yaml.YAMLError) as exc:
            print(f"::error file={path}::cannot read rule: {exc}")
            return 2
        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            missing = unmapped(doc, pipeline_docs)
            if missing:
                status = 1
                category = (doc.get("logsource") or {}).get("category") or "(no category)"
                print(
                    f"::error file={path}::{', '.join(missing)}: not mapped by {pipeline_path} for logsource "
                    f"category {category}. The Elastic output would keep the bare Sigma name, which Elastic data "
                    "doesn't have, so EQL and ES|QL reject the query and Lucene matches nothing. Add the ECS "
                    "mapping to the pipeline, or drop the Elastic target and say why in ci-targets.txt."
                )
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
