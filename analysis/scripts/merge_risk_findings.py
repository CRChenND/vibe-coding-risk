#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson


SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Deduplicate and merge Semgrep and LLM risk findings.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--semgrep-findings", type=Path, default=None)
    p.add_argument("--judge-findings", type=Path, default=None)
    p.add_argument("--out", type=Path, required=True)
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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


def clip(s: str, n: int = 500) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 3] + "..."


def cwe_values(row: dict[str, Any]) -> list[str]:
    raw = row.get("cwe_ids") or row.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    return sorted({str(x) for x in raw if isinstance(x, str) and re.fullmatch(r"CWE-\d+", x)})


def split_cwe_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        values = raw
    else:
        values = re.split(r"[,/;|\n]+", str(raw or ""))
    return sorted({str(x).strip().upper() for x in values if re.fullmatch(r"CWE-\d+", str(x).strip().upper())})


def analyzer_name(row: dict[str, Any]) -> str:
    analyzer = str(row.get("analyzer") or "").lower()
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    if analyzer == "static_rule" or details.get("engine") == "semgrep":
        return "semgrep"
    if analyzer == "llm_judge":
        return "llm_judge"
    return analyzer or "unknown"


def is_risky(row: dict[str, Any]) -> bool:
    return bool(row.get("is_risky")) and str(row.get("severity", "none")).lower() != "none"


def risky_line_range(row: dict[str, Any]) -> str:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    location = str(details.get("semgrep_location") or "")
    if location:
        parts = location.split(":")
        if len(parts) >= 5:
            return ":".join(parts[-4:])
        return location
    if analyzer_name(row) == "llm_judge":
        return "unknown"
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    quotes = []
    for ev in evidence:
        if isinstance(ev, dict):
            quote = str(ev.get("quote") or "").strip()
            if quote:
                quotes.append(quote)
    if quotes:
        return "quote:" + sha256_text("\n".join(quotes))[:12]
    return "unknown"


def merge_key(row: dict[str, Any], candidate: dict[str, Any] | None) -> tuple[str, str, str, str]:
    candidate_id = str(row.get("candidate_id") or "")
    chat_id = str(row.get("chat_id") or (candidate or {}).get("chat_id") or "")
    cwes = cwe_values(row)
    cwe_key = "+".join(cwes) if cwes else "NO_CWE"
    return chat_id, candidate_id, cwe_key, risky_line_range(row)


def severity_max(rows: list[dict[str, Any]]) -> str:
    rank = max((SEVERITY_RANK.get(str(row.get("severity") or "none").lower(), 0) for row in rows), default=0)
    return RANK_SEVERITY[rank]


def confidence_max(rows: list[dict[str, Any]]) -> float:
    values: list[float] = []
    for row in rows:
        try:
            values.append(float(row.get("confidence", 0.0)))
        except (TypeError, ValueError):
            continue
    return max(values, default=0.0)


def cwe_confidence_max(rows: list[dict[str, Any]]) -> float:
    values: list[float] = []
    for row in rows:
        try:
            values.append(float(row.get("cwe_confidence", row.get("confidence", 0.0)) or 0.0))
        except (TypeError, ValueError):
            continue
    return max(values, default=0.0)


def risk_confidence_tier(rows: list[dict[str, Any]], analyzers: set[str]) -> str:
    if {"semgrep", "llm_judge"} <= analyzers:
        return "high"
    llm_rows = [row for row in rows if analyzer_name(row) == "llm_judge"]
    if llm_rows:
        strong_evidence = any(confidence_max([row]) >= 0.75 for row in llm_rows)
        has_evidence = any(row.get("evidence") for row in llm_rows)
        if strong_evidence and has_evidence:
            return "medium"
    return "low"


def cwe_confidence_tier(rows: list[dict[str, Any]], analyzers: set[str], cwes: list[str]) -> str:
    if not cwes:
        return "unmapped"
    if {"semgrep", "llm_judge"} <= analyzers:
        return "high"
    if any(row.get("cwe_specificity") == "unmapped" for row in rows):
        return "unmapped"
    if cwe_confidence_max(rows) >= 0.75 and cwes:
        return "medium"
    return "low"


def primary_cwe(rows: list[dict[str, Any]], cwes: list[str]) -> str | None:
    for row in rows:
        value = row.get("primary_cwe")
        if isinstance(value, str) and value in cwes:
            return value
    return cwes[0] if cwes else None


def cwe_specificity(rows: list[dict[str, Any]], primary: str | None) -> str:
    for row in rows:
        if row.get("primary_cwe") == primary and row.get("cwe_specificity"):
            return str(row.get("cwe_specificity"))
    return "specific" if primary else "unmapped"


def cwe_abstraction(rows: list[dict[str, Any]], primary: str | None) -> str | None:
    for row in rows:
        if row.get("primary_cwe") == primary:
            value = row.get("cwe_abstraction")
            if isinstance(value, str) and value:
                return value
    return None


def merged_evidence(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_analyzer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rule_ids: set[str] = set()
    for row in rows:
        analyzer = analyzer_name(row)
        for ev in row.get("evidence") or []:
            if isinstance(ev, dict):
                by_analyzer[analyzer].append(
                    {
                        "quote": clip(str(ev.get("quote") or ""), 240),
                        "reason": clip(str(ev.get("reason") or ""), 300),
                    }
                )
        rule_id = row.get("rule_id")
        if isinstance(rule_id, str) and rule_id:
            rule_ids.add(rule_id)
    return {
        "by_analyzer": dict(sorted(by_analyzer.items())),
        "semgrep_rule_ids": sorted(rule_ids),
    }


def build_merged_finding(rows: list[dict[str, Any]], candidates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    first = rows[0]
    candidate_id = str(first.get("candidate_id") or "")
    candidate = candidates.get(candidate_id, {})
    chat_id = str(first.get("chat_id") or candidate.get("chat_id") or "")
    turn_index = candidate.get("turn_index", candidate.get("message_index"))
    cwes = sorted({cwe for row in rows for cwe in cwe_values(row)})
    primary = primary_cwe(rows, cwes)
    analyzers = {analyzer_name(row) for row in rows}
    risk_tier = risk_confidence_tier(rows, analyzers)
    cwe_tier = cwe_confidence_tier(rows, analyzers, cwes)
    agreement = "both" if {"semgrep", "llm_judge"} <= analyzers else f"{sorted(analyzers)[0]}_only"
    finding_ids = sorted(str(row.get("finding_id") or "") for row in rows if row.get("finding_id"))
    basis = f"{chat_id}:{candidate_id}:{','.join(cwes)}:{','.join(finding_ids)}"

    return {
        "finding_id": "merged-finding:" + sha256_text(basis)[:24],
        "source_finding_ids": finding_ids,
        "candidate_id": candidate_id,
        "chat_id": chat_id,
        "turn_index": turn_index,
        "analyzer": "fusion",
        "analyzers": sorted(analyzers),
        "agreement": agreement,
        "is_risky": True,
        "is_actionable": any(bool(row.get("is_actionable")) for row in rows),
        "severity": severity_max(rows),
        "confidence": confidence_max(rows),
        "confidence_tier": risk_tier,
        "risk_confidence_tier": risk_tier,
        "cwe_confidence_tier": cwe_tier,
        "cwe": cwes,
        "cwe_ids": cwes,
        "primary_cwe": primary,
        "cwe_abstraction": cwe_abstraction(rows, primary),
        "cwe_candidates_considered": sorted(
            {cwe for row in rows for cwe in split_cwe_list(row.get("cwe_candidates_considered", []))}
        ),
        "rejected_cwes": [
            rejected
            for row in rows
            for rejected in (row.get("rejected_cwes") or [])
            if isinstance(rejected, dict)
        ],
        "cwe_confidence": cwe_confidence_max(rows),
        "cwe_specificity": cwe_specificity(rows, primary),
        "needs_human_cwe_review": any(bool(row.get("needs_human_cwe_review")) for row in rows),
        "evidence": merged_evidence(rows),
        "verdict": "confirmed" if agreement == "both" else "likely",
        "rule_id": None,
        "details": {
            "merge_key": list(merge_key(first, candidate)),
            "candidate_type": candidate.get("candidate_type"),
            "language_hint": candidate.get("language_hint"),
            "content_hash": candidate.get("content_hash"),
            "source_count": len(rows),
            "source_findings": rows,
        },
    }


def coalesce_unknown_line_ranges(
    buckets: dict[tuple[str, str, str, str], list[dict[str, Any]]],
) -> dict[tuple[str, str, str, str], list[dict[str, Any]]]:
    by_base: dict[tuple[str, str, str], list[tuple[tuple[str, str, str, str], list[dict[str, Any]]]]] = defaultdict(list)
    for key, rows in buckets.items():
        by_base[key[:3]].append((key, rows))

    out: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for _base, keyed_rows in by_base.items():
        unknown_rows: list[dict[str, Any]] = []
        concrete: list[tuple[tuple[str, str, str, str], list[dict[str, Any]]]] = []
        for key, rows in keyed_rows:
            if key[3] == "unknown":
                unknown_rows.extend(rows)
            else:
                concrete.append((key, rows))

        if unknown_rows and len(concrete) == 1:
            key, rows = concrete[0]
            out[key] = rows + unknown_rows
        else:
            for key, rows in concrete:
                out[key] = rows
            if unknown_rows:
                base = keyed_rows[0][0][:3]
                out[(base[0], base[1], base[2], "unknown")] = unknown_rows
    return out


def main() -> None:
    args = parse_args()
    candidates = {str(row.get("candidate_id")): row for row in load_jsonl(args.candidates)}
    raw_findings = load_jsonl(args.semgrep_findings) + load_jsonl(args.judge_findings)
    counts: Counter[str] = Counter()
    buckets: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for row in raw_findings:
        counts["findings_seen"] += 1
        if not is_risky(row):
            counts["not_risky"] += 1
            continue
        candidate = candidates.get(str(row.get("candidate_id") or ""))
        if candidate is None:
            counts["missing_candidate"] += 1
            continue
        buckets[merge_key(row, candidate)].append(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    merged_buckets = coalesce_unknown_line_ranges(buckets)
    merged = [build_merged_finding(rows, candidates) for _, rows in sorted(merged_buckets.items())]
    with args.out.open("wb") as wf:
        for row in merged:
            wf.write(orjson.dumps(row) + b"\n")

    agreement_counts = Counter(str(row.get("agreement")) for row in merged)
    tier_counts = Counter(str(row.get("confidence_tier")) for row in merged)
    print(f"Findings seen: {counts['findings_seen']}")
    print(f"Merged risky findings: {len(merged)}")
    print(f"Agreement: {dict(sorted(agreement_counts.items()))}")
    print(f"Confidence tiers: {dict(sorted(tier_counts.items()))}")
    print(f"Skipped: {dict(sorted((k, v) for k, v in counts.items() if k != 'findings_seen'))}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
