#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson

ASSISTANT_DRIVEN = {"assistant_over_implemented", "assistant_hallucinated_risk"}
USER_OR_CONTEXT_DRIVEN = {"user_requested_risk", "inherited_or_context_risk"}
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compute trajectory causal attribution metrics.")
    p.add_argument(
        "--enriched",
        type=Path,
        default=Path("analysis/output/attribution_analysis/attribution_enriched.csv"),
        help="Input enriched CSV from analyze_attribution_patterns.py",
    )
    p.add_argument(
        "--tracing",
        type=Path,
        default=Path("analysis/output/attribution_analysis/conversation_tracing.csv"),
        help="Input tracing CSV from analyze_attribution_patterns.py",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path("analysis/output/trajectory_analysis"),
    )
    p.add_argument("--top-turns", type=int, default=25)
    p.add_argument("--min-cwe-n", type=int, default=5)
    return p.parse_args()


def to_int(v: Any) -> int | None:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def norm_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes"}
    return False


def safe_prob(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def p90(values: list[int]) -> int | None:
    if not values:
        return None
    arr = sorted(values)
    idx = int(0.9 * (len(arr) - 1))
    return arr[idx]


def gap_bucket(gap: int | None) -> str:
    if gap is None:
        return "missing"
    if gap <= 0:
        return "<=0"
    if gap == 1:
        return "1"
    if 2 <= gap <= 3:
        return "2-3"
    if 4 <= gap <= 7:
        return "4-7"
    if 8 <= gap <= 15:
        return "8-15"
    return "16+"


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k) for k in fieldnames})


def source_bucket(primary_cause: str) -> str:
    if primary_cause in ASSISTANT_DRIVEN:
        return "assistant_driven"
    if primary_cause in USER_OR_CONTEXT_DRIVEN:
        return "user_driven"
    return "unclear"


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    enriched_rows = list(csv.DictReader(args.enriched.open(encoding="utf-8")))
    tracing_rows = list(csv.DictReader(args.tracing.open(encoding="utf-8")))

    by_finding = {str(r.get("finding_id", "")): r for r in tracing_rows if r.get("finding_id")}

    # 1) Risk emergence position: P(risk first appears at turn t)
    emergence_counter: Counter[int] = Counter()
    emergence_bucket_counter: Counter[str] = Counter()

    # 2) Risk escalation depth
    mention_gaps: list[int] = []
    concrete_gaps: list[int] = []
    persistence_gaps: list[int] = []

    # 3) User vs assistant initiation
    initiation = Counter()

    # 4) Assistant security regression rate (proxy)
    reg_num = 0
    reg_den = 0
    reg_by_cwe: dict[str, list[int]] = defaultdict(list)

    # Security degradation trajectory proxy via gap buckets x severity
    severity_by_bucket: dict[str, Counter[str]] = defaultdict(Counter)

    # Analysis A: temporal degradation / survival
    event_turns: list[int] = []
    censor_turns: list[int] = []

    # Analysis B: source vs CWE
    source_by_cwe: dict[str, Counter[str]] = defaultdict(Counter)

    per_sample_rows: list[dict[str, Any]] = []

    for e in enriched_rows:
        fid = str(e.get("finding_id", ""))
        t = by_finding.get(fid, {})

        cause = str(e.get("primary_cause", ""))
        severity = str(e.get("severity", "")).lower()
        if severity not in SEVERITY_ORDER:
            severity = "none"

        ar = to_int(t.get("assistant_risk_turn"))
        fm = to_int(t.get("first_mention_turn"))
        fc = to_int(t.get("first_concretization_turn"))
        fp = to_int(t.get("first_persistence_turn"))

        mg = (ar - fm) if (ar is not None and fm is not None) else None
        cg = (ar - fc) if (ar is not None and fc is not None) else None
        pg = (ar - fp) if (ar is not None and fp is not None) else None

        if fm is not None:
            emergence_counter[fm] += 1
            event_turns.append(fm)
            if fm <= 1:
                emergence_bucket_counter["0-1"] += 1
            elif fm <= 3:
                emergence_bucket_counter["2-3"] += 1
            elif fm <= 7:
                emergence_bucket_counter["4-7"] += 1
            elif fm <= 15:
                emergence_bucket_counter["8-15"] += 1
            else:
                emergence_bucket_counter["16+"] += 1
        elif ar is not None:
            # Right-censored: no clear first mention found up to observed risky turn.
            censor_turns.append(ar)

        if mg is not None:
            mention_gaps.append(mg)
        if cg is not None:
            concrete_gaps.append(cg)
        if pg is not None:
            persistence_gaps.append(pg)

        if cause in ASSISTANT_DRIVEN:
            initiation["assistant_first"] += 1
        elif cause in USER_OR_CONTEXT_DRIVEN:
            initiation["user_or_context_first"] += 1
        else:
            initiation["unclear"] += 1

        # Proxy: assistant-driven + prior mention before final risky output
        if cause in ASSISTANT_DRIVEN and ar is not None:
            reg_den += 1
            is_regressed = int(fm is not None and fm < ar)
            reg_num += is_regressed
            for cwe in str(e.get("cwe", "")).split("|"):
                if cwe:
                    reg_by_cwe[cwe].append(is_regressed)

        src = source_bucket(cause)
        for cwe in str(e.get("cwe", "")).split("|"):
            if cwe:
                source_by_cwe[cwe][src] += 1

        severity_by_bucket[gap_bucket(mg)][severity] += 1

        per_sample_rows.append(
            {
                "finding_id": fid,
                "primary_cause": cause,
                "severity": severity,
                "assistant_risk_turn": ar,
                "first_mention_turn": fm,
                "first_concretization_turn": fc,
                "first_persistence_turn": fp,
                "mention_gap": mg,
                "concretization_gap": cg,
                "persistence_gap": pg,
                "is_assistant_driven": norm_bool(e.get("is_assistant_driven")),
                "attribution_confidence": to_float(e.get("attribution_confidence"), 0.0),
                "cwe": e.get("cwe", ""),
            }
        )

    emergence_total = sum(emergence_counter.values())
    emergence_rows = [
        {
            "turn": turn,
            "count": count,
            "probability": safe_prob(count, emergence_total),
        }
        for turn, count in sorted(emergence_counter.items(), key=lambda x: x[0])
    ]

    emergence_bucket_rows = [
        {
            "turn_bucket": bucket,
            "count": emergence_bucket_counter[bucket],
            "probability": safe_prob(emergence_bucket_counter[bucket], emergence_total),
        }
        for bucket in ["0-1", "2-3", "4-7", "8-15", "16+"]
    ]

    regression_cwe_rows: list[dict[str, Any]] = []
    for cwe, vals in sorted(reg_by_cwe.items(), key=lambda x: (-len(x[1]), x[0])):
        n = len(vals)
        if n < args.min_cwe_n:
            continue
        reg = sum(vals)
        regression_cwe_rows.append(
            {
                "cwe": cwe,
                "n_assistant_driven": n,
                "n_regressed": reg,
                "regression_rate": safe_prob(reg, n),
            }
        )

    severity_bucket_rows: list[dict[str, Any]] = []
    for bucket in ["<=0", "1", "2-3", "4-7", "8-15", "16+", "missing"]:
        c = severity_by_bucket[bucket]
        total = sum(c.values())
        severity_bucket_rows.append(
            {
                "gap_bucket": bucket,
                "total": total,
                "none": c["none"],
                "low": c["low"],
                "medium": c["medium"],
                "high": c["high"],
                "critical": c["critical"],
                "high_or_critical_ratio": safe_prob(c["high"] + c["critical"], total),
            }
        )

    # Analysis A: Temporal security degradation curve (discrete-time Kaplan-Meier style).
    max_turn = 0
    if event_turns:
        max_turn = max(max_turn, max(event_turns))
    if censor_turns:
        max_turn = max(max_turn, max(censor_turns))

    total_rows = len(enriched_rows)
    event_counter = Counter(event_turns)
    censor_counter = Counter(censor_turns)
    temporal_rows: list[dict[str, Any]] = []

    survival = 1.0
    cumulative_events = 0
    for turn in range(max_turn + 1):
        at_risk = 0
        for et in event_turns:
            if et >= turn:
                at_risk += 1
        for ct in censor_turns:
            if ct >= turn:
                at_risk += 1

        events = event_counter[turn]
        censored = censor_counter[turn]
        cumulative_events += events
        hazard = (events / at_risk) if at_risk else 0.0
        if at_risk and events:
            survival *= (1.0 - hazard)
        temporal_rows.append(
            {
                "turn": turn,
                "at_risk": at_risk,
                "new_risk_events": events,
                "new_censored": censored,
                "risk_probability_turn": round(events / total_rows, 6) if total_rows else 0.0,
                "hazard": round(hazard, 6),
                "survival_remaining_secure": round(survival, 6),
                "cumulative_risk_probability": round(cumulative_events / total_rows, 6) if total_rows else 0.0,
            }
        )

    # Analysis B: Attribution source vs CWE.
    source_cwe_rows: list[dict[str, Any]] = []
    for cwe, cnt in sorted(source_by_cwe.items(), key=lambda x: (-sum(x[1].values()), x[0])):
        total = sum(cnt.values())
        source_cwe_rows.append(
            {
                "cwe": cwe,
                "total": total,
                "assistant_driven": cnt["assistant_driven"],
                "assistant_driven_ratio": safe_prob(cnt["assistant_driven"], total),
                "user_driven": cnt["user_driven"],
                "user_driven_ratio": safe_prob(cnt["user_driven"], total),
                "unclear": cnt["unclear"],
                "unclear_ratio": safe_prob(cnt["unclear"], total),
            }
        )

    summary = {
        "n_enriched_rows": len(enriched_rows),
        "n_tracing_rows": len(tracing_rows),
        "risk_emergence_position": {
            "covered_rows": emergence_total,
            "top_turns": sorted(emergence_rows, key=lambda x: x["count"], reverse=True)[: args.top_turns],
            "bucket_distribution": emergence_bucket_rows,
        },
        "risk_escalation_depth": {
            "mention_gap": {
                "count": len(mention_gaps),
                "median": statistics.median(mention_gaps) if mention_gaps else None,
                "p90": p90(mention_gaps),
            },
            "concretization_gap": {
                "count": len(concrete_gaps),
                "median": statistics.median(concrete_gaps) if concrete_gaps else None,
                "p90": p90(concrete_gaps),
            },
            "persistence_gap": {
                "count": len(persistence_gaps),
                "median": statistics.median(persistence_gaps) if persistence_gaps else None,
                "p90": p90(persistence_gaps),
            },
        },
        "user_vs_assistant_initiation": {
            k: {"count": v, "ratio": safe_prob(v, len(enriched_rows))}
            for k, v in initiation.items()
        },
        "assistant_security_regression_rate_proxy": {
            "numerator": reg_num,
            "denominator_assistant_driven": reg_den,
            "rate": safe_prob(reg_num, reg_den),
        },
        "temporal_security_degradation": {
            "covered_events": len(event_turns),
            "covered_censored": len(censor_turns),
            "max_turn_in_curve": max_turn,
            "final_survival_remaining_secure": temporal_rows[-1]["survival_remaining_secure"] if temporal_rows else None,
        },
    }

    write_csv(
        args.out_dir / "risk_emergence_turn_distribution.csv",
        emergence_rows,
        ["turn", "count", "probability"],
    )
    write_csv(
        args.out_dir / "risk_emergence_bucket_distribution.csv",
        emergence_bucket_rows,
        ["turn_bucket", "count", "probability"],
    )
    write_csv(
        args.out_dir / "risk_escalation_samples.csv",
        per_sample_rows,
        [
            "finding_id",
            "primary_cause",
            "severity",
            "assistant_risk_turn",
            "first_mention_turn",
            "first_concretization_turn",
            "first_persistence_turn",
            "mention_gap",
            "concretization_gap",
            "persistence_gap",
            "is_assistant_driven",
            "attribution_confidence",
            "cwe",
        ],
    )
    write_csv(
        args.out_dir / "assistant_regression_by_cwe.csv",
        regression_cwe_rows,
        ["cwe", "n_assistant_driven", "n_regressed", "regression_rate"],
    )
    write_csv(
        args.out_dir / "severity_by_mention_gap_bucket.csv",
        severity_bucket_rows,
        ["gap_bucket", "total", "none", "low", "medium", "high", "critical", "high_or_critical_ratio"],
    )
    write_csv(
        args.out_dir / "temporal_security_degradation_curve.csv",
        temporal_rows,
        [
            "turn",
            "at_risk",
            "new_risk_events",
            "new_censored",
            "risk_probability_turn",
            "hazard",
            "survival_remaining_secure",
            "cumulative_risk_probability",
        ],
    )
    write_csv(
        args.out_dir / "attribution_source_by_cwe.csv",
        source_cwe_rows,
        [
            "cwe",
            "total",
            "assistant_driven",
            "assistant_driven_ratio",
            "user_driven",
            "user_driven_ratio",
            "unclear",
            "unclear_ratio",
        ],
    )

    (args.out_dir / "summary.json").write_bytes(orjson.dumps(summary, option=orjson.OPT_INDENT_2))

    print(f"Input enriched rows: {len(enriched_rows)}")
    print(f"Input tracing rows: {len(tracing_rows)}")
    print(f"Emergence coverage rows: {emergence_total}")
    print(f"Assistant-driven rows: {reg_den}")
    print(f"Regression proxy rate: {safe_prob(reg_num, reg_den)}")
    print(f"Output dir: {args.out_dir}")


if __name__ == "__main__":
    main()
