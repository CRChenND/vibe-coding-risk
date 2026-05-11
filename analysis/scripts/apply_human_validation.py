#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

import orjson


LABEL_FIELDS = [
    "interaction_stage",
    "risk_origin",
    "mechanism",
    "risk_evolution",
    "user_reaction",
]

ALLOWED_LABELS = {
    "interaction_stage": {
        "initial_generation",
        "repair_debugging",
        "optimization_refactor",
        "feature_expansion",
        "dependency_installation",
        "deployment_configuration",
        "security_fix",
        "unknown",
    },
    "risk_origin": {
        "user_induced",
        "agent_induced",
        "repair_induced",
        "context_loss_induced",
        "tool_or_retrieval_induced",
        "ambiguity_induced",
        "mixed",
        "unknown",
    },
    "mechanism": {
        "validation_removal",
        "unsafe_default",
        "hardcoded_secret",
        "insecure_deserialization",
        "raw_query_construction",
        "command_injection_pattern",
        "disabled_tls_or_auth",
        "overbroad_permission",
        "dangerous_shell_command",
        "hallucinated_secure_api",
        "unsafe_dependency_recommendation",
        "partial_fix",
        "security_requirement_omission",
        "unknown",
    },
    "risk_evolution": {
        "introduced",
        "persisted",
        "amplified",
        "partially_fixed",
        "fully_fixed",
        "reintroduced",
        "propagated",
        "unknown",
    },
    "user_reaction": {
        "accepted_without_questioning",
        "questioned_security",
        "requested_fix",
        "executed_or_planned_execution",
        "ignored",
        "unknown",
    },
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge filled human validation CSV labels back into episodes.")
    p.add_argument("--episodes", type=Path, required=True)
    p.add_argument("--human-csv", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--report-out", type=Path, default=None)
    p.add_argument("--second-human-csv", type=Path, default=None)
    return p.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(orjson.loads(line))
    return rows


def load_csv(path: Path) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            episode_id = (row.get("episode_id") or "").strip()
            if episode_id:
                rows[episode_id] = {k: (v or "").strip() for k, v in row.items()}
    return rows


def parse_bool(value: str) -> bool | None:
    v = value.strip().lower()
    if v in {"true", "yes", "y", "1", "valid"}:
        return True
    if v in {"false", "no", "n", "0", "invalid", "rejected"}:
        return False
    return None


def bool_label(value: str) -> str:
    parsed = parse_bool(value)
    if parsed is True:
        return "true"
    if parsed is False:
        return "false"
    return ""


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    pairs = [(a, b) for a, b in pairs if a and b]
    if not pairs:
        return None
    total = len(pairs)
    observed = sum(1 for a, b in pairs if a == b) / total
    left = Counter(a for a, _ in pairs)
    right = Counter(b for _, b in pairs)
    expected = sum((left[label] / total) * (right[label] / total) for label in set(left) | set(right))
    if math.isclose(1.0, expected):
        return 1.0 if math.isclose(1.0, observed) else None
    return round((observed - expected) / (1 - expected), 6)


def human_label(row: dict[str, str], field: str) -> str:
    value = row.get(f"human_{field}", "").strip()
    if value and value not in ALLOWED_LABELS[field]:
        return "unknown"
    return value


def apply_row(episode: dict[str, Any], human: dict[str, str] | None, stats: Counter[str]) -> dict[str, Any]:
    if human is None:
        return episode

    out = dict(episode)
    details = dict(out.get("details") or {})
    validation = {
        "human_is_valid_risk": human.get("human_is_valid_risk", ""),
        "original_labels": {field: episode.get(field) for field in LABEL_FIELDS},
        "corrected_labels": {},
        "human_notes": human.get("human_notes", ""),
    }

    valid = parse_bool(human.get("human_is_valid_risk", ""))
    if valid is not None:
        out["human_verified"] = valid
        stats["validated_rows"] += 1
        if valid:
            stats["valid_risk"] += 1
            if out.get("confidence_tier") != "high":
                out["confidence_tier"] = "high"
        else:
            stats["rejected_risk"] += 1
            out["confidence_tier"] = "excluded"

    human_cwe_is_correct = parse_bool(human.get("human_cwe_is_correct", ""))
    human_primary_cwe = human.get("human_primary_cwe", "").strip().upper()
    human_more_specific = parse_bool(human.get("human_cwe_should_be_more_specific", ""))
    if human_cwe_is_correct is not None:
        stats["cwe_validated_rows"] += 1
        if human_cwe_is_correct:
            stats["cwe_correct"] += 1
        else:
            stats["cwe_corrected_or_rejected"] += 1
            out["needs_human_cwe_review"] = False
    if human_primary_cwe:
        if re.fullmatch(r"CWE-\d+", human_primary_cwe):
            stats["human_primary_cwe_filled"] += 1
            if human_primary_cwe != episode.get("primary_cwe"):
                stats["primary_cwe_corrected"] += 1
            out["primary_cwe"] = human_primary_cwe
            out["cwe_ids"] = [human_primary_cwe]
            out["cwe_specificity"] = "specific"
            out["needs_human_cwe_review"] = False
        elif human_primary_cwe in {"NONE", "NULL", "UNMAPPED"}:
            stats["primary_cwe_unmapped_by_human"] += 1
            out["primary_cwe"] = None
            out["cwe_ids"] = []
            out["cwe_specificity"] = "unmapped"
            out["needs_human_cwe_review"] = False
    if human_more_specific is not None:
        validation["human_cwe_should_be_more_specific"] = human_more_specific

    for field in LABEL_FIELDS:
        corrected = human_label(human, field)
        if corrected:
            stats[f"{field}_filled"] += 1
            if corrected != episode.get(field):
                stats[f"{field}_corrected"] += 1
            out[field] = corrected
            validation["corrected_labels"][field] = corrected

    notes = human.get("human_notes", "")
    if notes:
        out["human_notes"] = notes

    details["human_validation"] = validation
    out["details"] = details
    return out


def validation_report(
    original: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    human_a: dict[str, dict[str, str]],
    human_b: dict[str, dict[str, str]] | None,
    stats: Counter[str],
) -> dict[str, Any]:
    validated = stats["validated_rows"]
    report: dict[str, Any] = {
        "episodes_seen": len(original),
        "human_rows": len(human_a),
        "episodes_written": len(verified),
        "manual_validation_precision": round(stats["valid_risk"] / validated, 6) if validated else None,
        "risk_rejection_rate": round(stats["rejected_risk"] / validated, 6) if validated else None,
        "cwe_exact_precision": round(stats["cwe_correct"] / stats["cwe_validated_rows"], 6)
        if stats["cwe_validated_rows"]
        else None,
        "cwe_correction_rate": round(stats["primary_cwe_corrected"] / stats["human_primary_cwe_filled"], 6)
        if stats["human_primary_cwe_filled"]
        else None,
        "label_correction_rate": {},
        "most_confused_labels": {},
    }
    for field in LABEL_FIELDS:
        filled = stats[f"{field}_filled"]
        report["label_correction_rate"][field] = (
            round(stats[f"{field}_corrected"] / filled, 6) if filled else None
        )
        confusion = Counter()
        for ep in original:
            row = human_a.get(str(ep.get("episode_id") or ""))
            if not row:
                continue
            corrected = human_label(row, field)
            if corrected and corrected != ep.get(field):
                confusion[f"{ep.get(field)} -> {corrected}"] += 1
        report["most_confused_labels"][field] = dict(confusion.most_common(10))

    cwe_confusion = Counter()
    for ep in original:
        row = human_a.get(str(ep.get("episode_id") or ""))
        if not row:
            continue
        corrected = row.get("human_primary_cwe", "").strip().upper()
        if corrected and re.fullmatch(r"CWE-\d+", corrected) and corrected != ep.get("primary_cwe"):
            cwe_confusion[f"{ep.get('primary_cwe')} -> {corrected}"] += 1
    report["most_confused_cwes"] = dict(cwe_confusion.most_common(20))

    if human_b is not None:
        shared = sorted(set(human_a) & set(human_b))
        report["inter_rater_reliability"] = {
            "cohen_kappa_risk_validity": cohen_kappa(
                [
                    (
                        bool_label(human_a[eid].get("human_is_valid_risk", "")),
                        bool_label(human_b[eid].get("human_is_valid_risk", "")),
                    )
                    for eid in shared
                ]
            ),
            "cohen_kappa_risk_origin": cohen_kappa(
                [(human_label(human_a[eid], "risk_origin"), human_label(human_b[eid], "risk_origin")) for eid in shared]
            ),
            "cohen_kappa_interaction_stage": cohen_kappa(
                [
                    (human_label(human_a[eid], "interaction_stage"), human_label(human_b[eid], "interaction_stage"))
                    for eid in shared
                ]
            ),
            "cohen_kappa_mechanism": cohen_kappa(
                [(human_label(human_a[eid], "mechanism"), human_label(human_b[eid], "mechanism")) for eid in shared]
            ),
        }
    return report


def main() -> None:
    args = parse_args()
    episodes = load_jsonl(args.episodes)
    human_a = load_csv(args.human_csv)
    human_b = load_csv(args.second_human_csv) if args.second_human_csv else None
    stats: Counter[str] = Counter()
    verified = [apply_row(ep, human_a.get(str(ep.get("episode_id") or "")), stats) for ep in episodes]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("wb") as wf:
        for row in verified:
            wf.write(orjson.dumps(row) + b"\n")

    report = validation_report(episodes, verified, human_a, human_b, stats)
    report_path = args.report_out or args.out.with_suffix(".report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Output: {args.out}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
