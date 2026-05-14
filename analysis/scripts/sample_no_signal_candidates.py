#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Any

import orjson


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sample no-signal candidates for LLM audit.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--cwe-candidates", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--sample-size", type=int, default=2000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--stratify-by-type",
        action="store_true",
        help="Sample roughly proportionally across candidate_type and language_hint.",
    )
    return p.parse_args()


def load_jsonl_by_candidate_id(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = orjson.loads(line)
            cid = str(obj.get("candidate_id") or "")
            if cid:
                rows[cid] = obj
    return rows


def has_nonempty_options(row: dict[str, Any] | None) -> bool:
    if not row:
        return False
    options = row.get("candidate_cwe_options") or row.get("cwe_options")
    return isinstance(options, list) and len(options) > 0


def has_risk_signal(cwe_row: dict[str, Any] | None) -> bool:
    if not cwe_row:
        return False

    if bool(cwe_row.get("semgrep_matched")):
        return True

    if bool(cwe_row.get("pattern_matched")):
        return True

    risk_tags = cwe_row.get("risk_tags")
    if isinstance(risk_tags, list) and len(risk_tags) > 0:
        return True

    if has_nonempty_options(cwe_row):
        return True

    return False


def load_no_signal_candidates(
    candidates_path: Path,
    cwe_rows: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    with candidates_path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            candidate = orjson.loads(line)
            cid = str(candidate.get("candidate_id") or "")
            cwe_row = cwe_rows.get(cid)

            if not has_risk_signal(cwe_row):
                out.append(candidate)

    return out


def stratum_key(candidate: dict[str, Any]) -> tuple[str, str]:
    ctype = str(candidate.get("candidate_type") or "unknown")
    lang = str(candidate.get("language_hint") or "unknown").lower().split(":", 1)[0]
    return ctype, lang


def sample_plain(rows: list[dict[str, Any]], sample_size: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    if sample_size >= len(rows):
        return rows
    return rng.sample(rows, sample_size)


def sample_stratified(rows: list[dict[str, Any]], sample_size: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)

    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        buckets.setdefault(stratum_key(row), []).append(row)

    if sample_size >= len(rows):
        return rows

    sampled: list[dict[str, Any]] = []

    # Proportional allocation, with at least one item from non-empty buckets
    # when possible.
    for _, bucket in sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        quota = round(sample_size * len(bucket) / len(rows))
        quota = max(1, quota)
        quota = min(quota, len(bucket))
        sampled.extend(rng.sample(bucket, quota))

    # Adjust if rounding overshoots.
    if len(sampled) > sample_size:
        sampled = rng.sample(sampled, sample_size)

    # Adjust if rounding undershoots.
    if len(sampled) < sample_size:
        sampled_ids = {str(row.get("candidate_id") or "") for row in sampled}
        remaining = [
            row for row in rows
            if str(row.get("candidate_id") or "") not in sampled_ids
        ]
        need = min(sample_size - len(sampled), len(remaining))
        sampled.extend(rng.sample(remaining, need))

    return sampled


def main() -> None:
    args = parse_args()

    cwe_rows = load_jsonl_by_candidate_id(args.cwe_candidates)
    no_signal = load_no_signal_candidates(args.candidates, cwe_rows)

    if args.stratify_by_type:
        sampled = sample_stratified(no_signal, args.sample_size, args.seed)
    else:
        sampled = sample_plain(no_signal, args.sample_size, args.seed)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("wb") as wf:
        for row in sampled:
            wf.write(orjson.dumps(row) + b"\n")

    print(f"No-signal candidates found: {len(no_signal)}")
    print(f"Sample size requested: {args.sample_size}")
    print(f"Sample size written: {len(sampled)}")
    print(f"Stratified: {args.stratify_by_type}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()