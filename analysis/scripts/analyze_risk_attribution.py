#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate descriptive and attribution statistics for risk episodes.")
    p.add_argument("--episodes", type=Path, required=True)
    p.add_argument("--candidates", type=Path, default=None)
    p.add_argument("--findings", type=Path, default=None)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument(
        "--confidence-tiers",
        type=str,
        default="high,medium,low",
        help="Comma-separated confidence tiers to include; use 'all' for no filtering.",
    )
    return p.parse_args()


def load_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
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


def write_counter(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def counter_rows(counter: Counter[str], key_name: str) -> list[dict[str, Any]]:
    return [{key_name: key, "count": count} for key, count in counter.most_common()]


def count_episode_values(episodes: list[dict[str, Any]], field: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in episodes:
        values = as_list(row.get(field))
        if not values:
            counts["unknown"] += 1
        else:
            counts.update(values)
    return counts


def crosstab(episodes: list[dict[str, Any]], left: str, right: str) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for row in episodes:
        left_values = as_list(row.get(left)) or ["unknown"]
        right_values = as_list(row.get(right)) or ["unknown"]
        for lv in left_values:
            for rv in right_values:
                counts[(lv, rv)] += 1
    return [
        {left: lv, right: rv, "count": count}
        for (lv, rv), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def turn_depth_rows(candidates: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidate_by_id = {str(row.get("candidate_id")): row for row in candidates}
    risky_candidate_ids = {
        str(row.get("candidate_id"))
        for row in findings
        if row.get("is_risky") and str(row.get("severity", "none")).lower() != "none"
    }
    buckets: dict[str, Counter[str]] = defaultdict(Counter)
    for cid, candidate in candidate_by_id.items():
        try:
            turn = int(candidate.get("turn_index", candidate.get("message_index", 0)))
        except (TypeError, ValueError):
            turn = 0
        bucket = f"{(turn // 5) * 5}-{(turn // 5) * 5 + 4}"
        buckets[bucket]["candidates"] += 1
        if cid in risky_candidate_ids:
            buckets[bucket]["risky"] += 1
    rows: list[dict[str, Any]] = []
    for bucket, counts in sorted(buckets.items(), key=lambda item: int(item[0].split("-", 1)[0])):
        total = counts["candidates"]
        risky = counts["risky"]
        rows.append(
            {
                "turn_depth": bucket,
                "candidates": total,
                "risky_findings": risky,
                "risk_probability": round(risky / total, 6) if total else 0.0,
            }
        )
    return rows


def repair_debugging_severity(episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for row in episodes:
        if row.get("interaction_stage") != "repair_debugging":
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        severities = as_list(details.get("severity_values")) or ["unknown"]
        counts.update(severities)
    return counter_rows(counts, "severity")


def command_code_distribution(episodes: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in episodes:
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        summaries = details.get("finding_summaries") if isinstance(details.get("finding_summaries"), list) else []
        seen = False
        for summary in summaries:
            if not isinstance(summary, dict):
                continue
            candidate_type = summary.get("candidate_type")
            if candidate_type:
                counts[str(candidate_type)] += 1
                seen = True
        if not seen:
            counts["unknown"] += 1
    return counts


def language_distribution(candidates: list[dict[str, Any]], episodes: list[dict[str, Any]]) -> Counter[str]:
    candidate_by_id = {str(row.get("candidate_id")): row for row in candidates}
    counts: Counter[str] = Counter()
    for episode in episodes:
        for cid in as_list(episode.get("candidate_ids")):
            candidate = candidate_by_id.get(cid)
            if candidate is None:
                counts["unknown"] += 1
            else:
                counts[str(candidate.get("language_hint") or "unknown")] += 1
    return counts


def include_by_confidence(row: dict[str, Any], allowed: set[str] | None) -> bool:
    if allowed is None:
        return True
    return str(row.get("risk_confidence_tier") or row.get("confidence_tier") or "low") in allowed


def episode_agreement(row: dict[str, Any]) -> str:
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


def analyzer_agreement_rows(episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals: Counter[str] = Counter()
    valid: Counter[str] = Counter()
    verified: Counter[str] = Counter()
    for row in episodes:
        source = episode_agreement(row)
        totals[source] += 1
        if row.get("human_verified") is not None:
            verified[source] += 1
            if row.get("human_verified") is True:
                valid[source] += 1
    rows: list[dict[str, Any]] = []
    for source, count in totals.most_common():
        human_n = verified[source]
        rows.append(
            {
                "source": source,
                "count": count,
                "human_validated_n": human_n,
                "human_precision": round(valid[source] / human_n, 6) if human_n else "",
            }
        )
    return rows


def human_validation_outcomes(episodes: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in episodes:
        if row.get("human_verified") is True:
            counts["human_validated_risk"] += 1
        elif row.get("human_verified") is False:
            counts["human_rejected_risk"] += 1
        else:
            counts["not_human_validated"] += 1
    return counts


def human_cwe_granularity_counts(episodes: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in episodes:
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        validation = details.get("human_validation") if isinstance(details.get("human_validation"), dict) else {}
        granularity = validation.get("human_cwe_granularity")
        if granularity:
            counts[str(granularity)] += 1
        else:
            counts["not_human_validated"] += 1
    return counts


def risk_lineage_summary_rows(episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_lineage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in episodes:
        by_lineage[str(row.get("risk_lineage_id") or "unknown")].append(row)
    rows: list[dict[str, Any]] = []
    for lineage_id, rows_for_lineage in sorted(by_lineage.items()):
        turns = [int(row.get("risk_turn_index") or 0) for row in rows_for_lineage]
        rows.append(
            {
                "risk_lineage_id": lineage_id,
                "episode_count": len(rows_for_lineage),
                "start_turn": min(turns) if turns else "",
                "end_turn": max(turns) if turns else "",
                "turn_span": (max(turns) - min(turns)) if turns else "",
                "cross_turn": len(set(turns)) > 1,
            }
        )
    return rows


def main() -> None:
    args = parse_args()
    raw_episodes = load_jsonl(args.episodes)
    allowed_tiers = None if args.confidence_tiers.strip().lower() == "all" else {
        tier.strip() for tier in args.confidence_tiers.split(",") if tier.strip()
    }
    episodes = [row for row in raw_episodes if include_by_confidence(row, allowed_tiers)]
    candidates = load_jsonl(args.candidates)
    findings = load_jsonl(args.findings)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "number_of_chats": len({row.get("chat_id") for row in episodes if row.get("chat_id")}),
        "number_of_candidates": len(candidates) if candidates else len({cid for row in episodes for cid in as_list(row.get("candidate_ids"))}),
        "number_of_risky_findings": len([row for row in findings if row.get("is_risky")]) if findings else len({fid for row in episodes for fid in as_list(row.get("finding_ids"))}),
        "number_of_risk_episodes": len(episodes),
        "number_of_risk_episodes_before_confidence_filter": len(raw_episodes),
        "confidence_tiers_included": sorted(allowed_tiers) if allowed_tiers is not None else "all",
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    distributions = {
        "cwe_distribution.csv": ("cwe_id", count_episode_values(episodes, "cwe_ids")),
        "language_distribution.csv": ("language", language_distribution(candidates, episodes)),
        "command_vs_code_risk_distribution.csv": ("candidate_type", command_code_distribution(episodes)),
        "risk_origin_counts.csv": ("risk_origin", count_episode_values(episodes, "risk_origin")),
        "interaction_stage_counts.csv": ("interaction_stage", count_episode_values(episodes, "interaction_stage")),
        "mechanism_counts.csv": ("mechanism", count_episode_values(episodes, "mechanism")),
        "risk_evolution_counts.csv": ("risk_evolution", count_episode_values(episodes, "risk_evolution")),
        "user_reaction_counts.csv": ("user_reaction", count_episode_values(episodes, "user_reaction")),
        "confidence_tier_distribution.csv": ("confidence_tier", count_episode_values(episodes, "confidence_tier")),
        "risk_confidence_tier_distribution.csv": ("risk_confidence_tier", count_episode_values(episodes, "risk_confidence_tier")),
        "cwe_confidence_tier_distribution.csv": ("cwe_confidence_tier", count_episode_values(episodes, "cwe_confidence_tier")),
        "human_validation_outcomes.csv": ("outcome", human_validation_outcomes(episodes)),
        "human_cwe_granularity_counts.csv": ("human_cwe_granularity", human_cwe_granularity_counts(episodes)),
        "lineage_role_counts.csv": ("lineage_role", count_episode_values(episodes, "lineage_role")),
        "cwe_specificity_distribution.csv": ("cwe_specificity", count_episode_values(episodes, "cwe_specificity")),
    }
    for filename, (key_name, counter) in distributions.items():
        write_counter(args.out_dir / filename, [key_name, "count"], counter_rows(counter, key_name))

    cross_tabs = [
        ("interaction_stage_x_risk_origin.csv", "interaction_stage", "risk_origin"),
        ("interaction_stage_x_cwe.csv", "interaction_stage", "cwe_ids"),
        ("risk_origin_x_user_reaction.csv", "risk_origin", "user_reaction"),
        ("mechanism_x_cwe.csv", "mechanism", "cwe_ids"),
    ]
    for filename, left, right in cross_tabs:
        write_counter(args.out_dir / filename, [left, right, "count"], crosstab(episodes, left, right))

    write_counter(
        args.out_dir / "turn_depth_x_risk_probability.csv",
        ["turn_depth", "candidates", "risky_findings", "risk_probability"],
        turn_depth_rows(candidates, findings),
    )
    write_counter(
        args.out_dir / "repair_debugging_x_severity.csv",
        ["severity", "count"],
        repair_debugging_severity(episodes),
    )
    write_counter(
        args.out_dir / "analyzer_agreement.csv",
        ["source", "count", "human_validated_n", "human_precision"],
        analyzer_agreement_rows(episodes),
    )
    write_counter(
        args.out_dir / "risk_lineage_summary.csv",
        ["risk_lineage_id", "episode_count", "start_turn", "end_turn", "turn_span", "cross_turn"],
        risk_lineage_summary_rows(episodes),
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Output directory: {args.out_dir}")


if __name__ == "__main__":
    main()
