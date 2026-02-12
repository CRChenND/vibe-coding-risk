#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Any

import orjson
import yaml
from tqdm import tqdm

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run baseline regex rules on candidate JSONL.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--summary-out", type=Path, default=None)
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_rules(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules, list):
        raise ValueError("rules YAML must contain a top-level 'rules' list")

    compiled: list[dict[str, Any]] = []
    for r in rules:
        regex = r.get("regex")
        if not isinstance(regex, str):
            continue
        entry = dict(r)
        entry["_compiled"] = re.compile(regex)
        compiled.append(entry)
    return compiled


def build_finding(candidate: dict[str, Any], rule: dict[str, Any], match: re.Match[str]) -> dict[str, Any]:
    cand_id = str(candidate["candidate_id"])
    rule_id = str(rule["rule_id"])
    finding_id = sha256_text(f"{cand_id}:{rule_id}")[:24]

    quote = match.group(0)
    if len(quote) > 200:
        quote = quote[:197] + "..."

    severity = str(rule.get("severity", "medium"))
    confidence = float(rule.get("confidence", 0.7))

    return {
        "finding_id": finding_id,
        "candidate_id": cand_id,
        "analyzer": "static_rule",
        "is_risky": True,
        "severity": severity,
        "confidence": max(0.0, min(1.0, confidence)),
        "cwe": list(rule.get("cwe", [])),
        "evidence": [
            {
                "quote": quote,
                "reason": str(rule.get("description", "Pattern matched")),
            }
        ],
        "verdict": "possible" if severity in {"low", "medium"} else "likely",
        "rule_id": rule_id,
        "details": {
            "candidate_type": candidate.get("candidate_type"),
            "language_hint": candidate.get("language_hint"),
            "attribution": candidate.get("attribution"),
            "repo_full_name": (candidate.get("repo_context") or {}).get("repo_full_name"),
        },
    }


def main() -> None:
    args = parse_args()
    rules = load_rules(args.rules)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    count_candidates = 0
    count_findings = 0
    per_rule: dict[str, int] = {}
    max_severity = "none"

    with args.candidates.open("rb") as rf, args.out.open("wb") as wf:
        for line in tqdm(rf, desc="rule-scan"):
            line = line.strip()
            if not line:
                continue
            count_candidates += 1
            candidate = orjson.loads(line)
            content = str(candidate.get("content", ""))
            ctype = str(candidate.get("candidate_type", ""))

            for rule in rules:
                if rule.get("candidate_type") != ctype:
                    continue
                m = rule["_compiled"].search(content)
                if not m:
                    continue

                finding = build_finding(candidate, rule, m)
                wf.write(orjson.dumps(finding) + b"\n")
                count_findings += 1
                rid = str(rule["rule_id"])
                per_rule[rid] = per_rule.get(rid, 0) + 1

                sev = str(rule.get("severity", "none"))
                if SEVERITY_ORDER[sev] > SEVERITY_ORDER[max_severity]:
                    max_severity = sev

    summary = {
        "candidates_scanned": count_candidates,
        "findings": count_findings,
        "max_severity": max_severity,
        "per_rule": per_rule,
        "out": str(args.out),
    }

    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_bytes(orjson.dumps(summary, option=orjson.OPT_INDENT_2))

    print(orjson.dumps(summary, option=orjson.OPT_INDENT_2).decode("utf-8"))


if __name__ == "__main__":
    main()
