#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import orjson


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Merge finding-level human validation into risk findings."
    )
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("--human", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument(
        "--overwrite-cwe",
        action="store_true",
        help="Overwrite primary_cwe/cwe_ids with human_primary_cwe when provided.",
    )
    return p.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(orjson.loads(line))
    return rows


def load_human_rows(path: Path) -> dict[str, dict[str, Any]]:
    rows: list[dict[str, Any]]
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
    else:
        rows = load_jsonl(path)
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        for finding_id in row_finding_ids(row):
            out[finding_id] = row
    return out


def row_finding_ids(row: dict[str, Any]) -> list[str]:
    value = row.get("finding_ids")
    if isinstance(value, list):
        ids = [str(x) for x in value if x]
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                ids = [str(x) for x in parsed if x]
            else:
                ids = [part.strip() for part in raw.split(";") if part.strip()]
        except json.JSONDecodeError:
            ids = [part.strip() for part in raw.split(";") if part.strip()]
    else:
        ids = []
    fallback = str(row.get("finding_id") or "")
    if fallback:
        ids.append(fallback)
    return sorted(set(ids))


def normalize_validity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"true", "yes", "1", "valid"}:
        return "true"
    if text in {"false", "no", "0", "invalid"}:
        return "false"
    if text in {"needs_review", "review", "uncertain", "unsure"}:
        return "needs_review"
    return ""


def normalize_cwe(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text in {"", "UNKNOWN"}:
        return ""
    if text in {"UNMAPPED", "NONE", "NULL"}:
        return "unmapped"
    if text.startswith("CWE-"):
        return text
    if text.isdigit():
        return f"CWE-{text}"
    return text


def apply_human(row: dict[str, Any], human: dict[str, Any], overwrite_cwe: bool) -> dict[str, Any]:
    out = dict(row)
    validity = normalize_validity(human.get("human_is_valid_risk"))
    human_primary_cwe = normalize_cwe(human.get("human_primary_cwe"))
    human_validation = {
        "review_unit_id": human.get("review_unit_id") or None,
        "human_is_valid_risk": validity or None,
        "human_cwe_granularity": human.get("human_cwe_granularity") or None,
        "human_primary_cwe": human_primary_cwe or None,
        "human_severity": human.get("human_severity") or None,
        "human_notes": human.get("human_notes") or None,
        "updated_at": human.get("updated_at") or None,
    }
    out["human_verified"] = bool(validity)
    out["human_validation"] = human_validation

    if validity == "false":
        out["risk_confidence_tier"] = "excluded"
        out["confidence_tier"] = "excluded"
        out["verdict"] = "human_rejected"
    elif validity == "true":
        if out.get("risk_confidence_tier") in {None, "", "low", "medium"}:
            out["risk_confidence_tier"] = "high"
            out["confidence_tier"] = "high"

    human_severity = str(human.get("human_severity") or "").strip().lower()
    if human_severity and human_severity != "none":
        out["severity"] = human_severity

    granularity = str(human.get("human_cwe_granularity") or "")
    if granularity:
        out["human_cwe_granularity"] = granularity
        if granularity in {"incorrect", "correct_but_too_broad", "unmapped_but_valid_risk"}:
            out["needs_human_cwe_review"] = True

    if overwrite_cwe and human_primary_cwe:
        if human_primary_cwe == "unmapped":
            out["primary_cwe"] = None
            out["cwe_ids"] = []
            out["cwe"] = []
            out["cwe_specificity"] = "unmapped"
        else:
            out["primary_cwe"] = human_primary_cwe
            out["cwe_ids"] = [human_primary_cwe]
            out["cwe"] = [human_primary_cwe]
            out["cwe_specificity"] = "specific"
            out["needs_human_cwe_review"] = False
        out["cwe_confidence_tier"] = "human_verified"

    return out


def main() -> None:
    args = parse_args()
    human_by_id = load_human_rows(args.human)
    total = 0
    matched = 0
    rejected = 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.findings.open("rb") as f, args.out.open("wb") as wf:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            row = orjson.loads(line)
            finding_id = str(row.get("finding_id") or "")
            human = human_by_id.get(finding_id)
            if human:
                matched += 1
                row = apply_human(row, human, args.overwrite_cwe)
                if row.get("risk_confidence_tier") == "excluded":
                    rejected += 1
            wf.write(orjson.dumps(row) + b"\n")
    print(f"Findings read: {total}")
    print(f"Human rows matched: {matched}")
    print(f"Human rejected: {rejected}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
