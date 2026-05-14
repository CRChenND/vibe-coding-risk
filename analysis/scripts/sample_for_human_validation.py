#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

import orjson


CSV_COLUMNS = [
    "episode_id",
    "chat_id",
    "risk_turn_index",
    "candidate_id",
    "cwe_ids",
    "primary_cwe_llm",
    "cwe_abstraction_llm",
    "cwe_specificity_llm",
    "needs_human_cwe_review",
    "risk_summary",
    "analyzer_agreement",
    "risk_confidence_tier",
    "cwe_confidence_tier",
    "interaction_stage_llm",
    "risk_origin_llm",
    "mechanism_llm",
    "risk_evolution_llm",
    "user_reaction_llm",
    "evidence_turns",
    "human_is_valid_risk",
    "human_cwe_is_correct",
    "human_primary_cwe",
    "human_cwe_granularity",
    "human_interaction_stage",
    "human_risk_origin",
    "human_mechanism",
    "human_risk_evolution",
    "human_user_reaction",
    "human_notes",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sample attributed risk episodes for human validation.")
    p.add_argument("--episodes", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--sample-size", type=int, default=300)
    p.add_argument("--stratify-by", type=str, default="risk_origin,cwe_ids,interaction_stage")
    p.add_argument("--seed", type=int, default=13)
    return p.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(orjson.loads(line))
    return rows


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if str(x)]
    if value is None:
        return []
    return [str(value)]


def severity_rank(row: dict[str, Any]) -> int:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    severities = as_list(details.get("severity_values"))
    rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max((rank.get(s.lower(), 0) for s in severities), default=0)


def has_source_disagreement(row: dict[str, Any]) -> bool:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    agreements = set(as_list(details.get("agreements")))
    if agreements:
        return "both" not in agreements
    analyzers = {x for x in as_list(details.get("analyzers")) if x}
    return len(analyzers) == 1 and bool(analyzers & {"llm_judge", "static_rule"})


def analyzer_agreement(row: dict[str, Any]) -> str:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    agreements = as_list(details.get("agreements"))
    if "both" in agreements:
        return "both"
    if agreements:
        return sorted(agreements)[0]
    analyzers = set(as_list(details.get("analyzers")))
    if {"semgrep", "llm_judge"} <= analyzers:
        return "both"
    if "semgrep" in analyzers:
        return "semgrep_only"
    if "llm_judge" in analyzers:
        return "llm_judge_only"
    return "unknown"


def strat_key(row: dict[str, Any], fields: list[str]) -> tuple[str, ...]:
    parts: list[str] = []
    for field in fields:
        values = as_list(row.get(field))
        parts.append("|".join(sorted(values)) if values else "unknown")
    return tuple(parts)


def choose_stratified(rows: list[dict[str, Any]], fields: list[str], sample_size: int, rng: random.Random) -> list[dict[str, Any]]:
    if sample_size <= 0 or sample_size >= len(rows):
        return list(rows)

    selected: dict[str, dict[str, Any]] = {}

    priority = sorted(
        rows,
        key=lambda row: (severity_rank(row), has_source_disagreement(row)),
        reverse=True,
    )
    for row in priority[: min(sample_size // 3, len(priority))]:
        selected[str(row.get("episode_id"))] = row

    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[strat_key(row, fields)].append(row)

    bucket_keys = list(buckets)
    rng.shuffle(bucket_keys)
    while len(selected) < sample_size and bucket_keys:
        progressed = False
        for key in list(bucket_keys):
            bucket = buckets[key]
            if not bucket:
                bucket_keys.remove(key)
                continue
            row = bucket.pop(rng.randrange(len(bucket)))
            selected[str(row.get("episode_id"))] = row
            progressed = True
            if len(selected) >= sample_size:
                break
        if not progressed:
            break

    if len(selected) < sample_size:
        remaining = [row for row in rows if str(row.get("episode_id")) not in selected]
        rng.shuffle(remaining)
        for row in remaining[: sample_size - len(selected)]:
            selected[str(row.get("episode_id"))] = row

    return list(selected.values())[:sample_size]


def csv_row(row: dict[str, Any]) -> dict[str, Any]:
    candidate_ids = as_list(row.get("candidate_ids"))
    return {
        "episode_id": row.get("episode_id", ""),
        "chat_id": row.get("chat_id", ""),
        "risk_turn_index": row.get("risk_turn_index", ""),
        "candidate_id": candidate_ids[0] if candidate_ids else "",
        "cwe_ids": ";".join(as_list(row.get("cwe_ids"))),
        "primary_cwe_llm": row.get("primary_cwe", ""),
        "cwe_abstraction_llm": row.get("cwe_abstraction", ""),
        "cwe_specificity_llm": row.get("cwe_specificity", ""),
        "needs_human_cwe_review": row.get("needs_human_cwe_review", ""),
        "risk_summary": row.get("risk_summary", ""),
        "analyzer_agreement": analyzer_agreement(row),
        "risk_confidence_tier": row.get("risk_confidence_tier", row.get("confidence_tier", "")),
        "cwe_confidence_tier": row.get("cwe_confidence_tier", ""),
        "interaction_stage_llm": row.get("interaction_stage", ""),
        "risk_origin_llm": row.get("risk_origin", ""),
        "mechanism_llm": row.get("mechanism", ""),
        "risk_evolution_llm": row.get("risk_evolution", ""),
        "user_reaction_llm": row.get("user_reaction", ""),
        "evidence_turns": ";".join(as_list(row.get("evidence_turns"))),
        "human_is_valid_risk": "",
        "human_cwe_is_correct": "",
        "human_primary_cwe": "",
        "human_cwe_granularity": "",
        "human_interaction_stage": "",
        "human_risk_origin": "",
        "human_mechanism": "",
        "human_risk_evolution": "",
        "human_user_reaction": "",
        "human_notes": "",
    }


def main() -> None:
    args = parse_args()
    rows = load_jsonl(args.episodes)
    fields = [field.strip() for field in args.stratify_by.split(",") if field.strip()]
    sample = choose_stratified(rows, fields, args.sample_size, random.Random(args.seed))
    sample.sort(key=lambda row: (str(row.get("chat_id") or ""), int(row.get("risk_turn_index") or 0)))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in sample:
            writer.writerow(csv_row(row))

    print(f"Episodes seen: {len(rows)}")
    print(f"Sample size: {len(sample)}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
