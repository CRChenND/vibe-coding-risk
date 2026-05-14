#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

import orjson


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export risky findings from no-signal audit for manual inspection.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--judge-findings", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    return p.parse_args()


def load_jsonl_by_id(path: Path, id_field: str = "candidate_id") -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = orjson.loads(line)
            cid = str(obj.get(id_field) or "")
            if cid:
                rows[cid] = obj
    return rows


def short(value: Any, n: int = 1200) -> str:
    text = str(value or "").strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def main() -> None:
    args = parse_args()

    candidates = load_jsonl_by_id(args.candidates)
    findings = load_jsonl_by_id(args.judge_findings)

    args.out.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "candidate_id",
        "chat_id",
        "turn_index",
        "candidate_type",
        "language_hint",
        "severity",
        "confidence",
        "verdict",
        "is_actionable",
        "actionability_reason",
        "cwe",
        "primary_cwe",
        "cwe_specificity",
        "needs_human_cwe_review",
        "evidence",
        "reasoning",
        "preceding_user_text",
        "content",
    ]

    risky_rows = [
        row for row in findings.values()
        if row.get("is_risky") is True
    ]

    with args.out.open("w", newline="", encoding="utf-8") as wf:
        writer = csv.DictWriter(wf, fieldnames=fields)
        writer.writeheader()

        for finding in risky_rows:
            cid = str(finding.get("candidate_id") or "")
            candidate = candidates.get(cid, {})
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            details = finding.get("details") if isinstance(finding.get("details"), dict) else {}

            writer.writerow(
                {
                    "candidate_id": cid,
                    "chat_id": candidate.get("chat_id"),
                    "turn_index": candidate.get("turn_index", candidate.get("message_index")),
                    "candidate_type": candidate.get("candidate_type"),
                    "language_hint": candidate.get("language_hint"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "verdict": finding.get("verdict"),
                    "is_actionable": finding.get("is_actionable"),
                    "actionability_reason": finding.get("actionability_reason"),
                    "cwe": ",".join(finding.get("cwe") or []),
                    "primary_cwe": finding.get("primary_cwe"),
                    "cwe_specificity": finding.get("cwe_specificity"),
                    "needs_human_cwe_review": finding.get("needs_human_cwe_review"),
                    "evidence": short(finding.get("evidence")),
                    "reasoning": short(details.get("reasoning")),
                    "preceding_user_text": short(metadata.get("preceding_user_text")),
                    "content": short(candidate.get("content"), 3000),
                }
            )

    print(f"Risky findings exported: {len(risky_rows)}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()