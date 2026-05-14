#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build a compact browser annotation dataset from risk findings and candidates."
    )
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--chats-dir", type=Path, default=None)
    p.add_argument("--context-before", type=int, default=2)
    p.add_argument("--context-after", type=int, default=1)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--content-chars", type=int, default=12000)
    p.add_argument("--context-chars", type=int, default=1600)
    p.add_argument("--evidence-chars", type=int, default=900)
    p.add_argument("--only-needs-human-cwe-review", action="store_true")
    p.add_argument("--agreement", type=str, default="")
    p.add_argument("--severity", type=str, default="")
    p.add_argument(
        "--review-unit-scope",
        choices=("chat_cwe", "turn_cwe", "file_turn_cwe"),
        default="chat_cwe",
        help="How aggressively to merge findings into human-review units.",
    )
    p.add_argument(
        "--group-review-units",
        dest="group_review_units",
        action="store_true",
        default=True,
    )
    p.add_argument("--no-group-review-units", dest="group_review_units", action="store_false")
    p.add_argument(
        "--group-unknown-file-by-turn",
        dest="group_unknown_file_by_turn",
        action="store_true",
        default=True,
    )
    p.add_argument(
        "--no-group-unknown-file-by-turn",
        dest="group_unknown_file_by_turn",
        action="store_false",
    )
    return p.parse_args()


def clip(value: Any, n: int) -> str:
    text = str(value or "").strip()
    if n <= 0 or len(text) <= n:
        return text
    return text[: n - 3] + "..."


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(orjson.loads(line))
    return rows


def iter_jsonl(path: Path):
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                yield orjson.loads(line)


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if x is not None and str(x)]
    if value is None or value == "":
        return []
    return [str(value)]


def flatten_blocks(blocks: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(blocks, list):
        return out
    for entry in blocks:
        if isinstance(entry, dict):
            out.append(entry)
        elif isinstance(entry, list):
            out.extend(inner for inner in entry if isinstance(inner, dict))
    return out


def load_chat_context(
    chats_dir: Path | None,
    chat_id: str,
    risk_turn: int,
    before: int,
    after: int,
    context_chars: int,
) -> list[dict[str, Any]]:
    if chats_dir is None:
        return []
    path = chats_dir / f"{chat_id}.md.json"
    if not path.exists():
        return []
    try:
        data = orjson.loads(path.read_bytes())
    except Exception:  # noqa: BLE001
        return []

    start = max(0, risk_turn - max(0, before))
    end = risk_turn + max(0, after)
    turns: list[dict[str, Any]] = []
    for idx, msg in enumerate(data.get("messages") or []):
        if idx < start or idx > end:
            continue
        role = str(msg.get("role") or "tool").lower()
        if role not in {"user", "assistant", "tool"}:
            role = "tool"
        parts: list[str] = []
        for block in flatten_blocks(msg.get("blocks")):
            content = block.get("content")
            if isinstance(content, str) and content.strip():
                parts.append(content.strip())
        text = clip("\n\n".join(parts), context_chars)
        if text:
            turns.append({"turn_index": idx, "role": role, "text": text})
    return turns


def load_chat_blocks(
    chats_dir: Path | None,
    chat_id: str,
    turn_index: int,
    cache: dict[tuple[str, int], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if chats_dir is None:
        return []
    key = (chat_id, turn_index)
    if key in cache:
        return cache[key]
    path = chats_dir / f"{chat_id}.md.json"
    try:
        data = orjson.loads(path.read_bytes())
        msg = data["messages"][turn_index]
        blocks = flatten_blocks(msg.get("blocks"))
    except Exception:  # noqa: BLE001
        blocks = []
    cache[key] = blocks
    return blocks


def file_path_for_candidate(
    candidate: dict[str, Any],
    args: argparse.Namespace,
    block_cache: dict[tuple[str, int], list[dict[str, Any]]],
) -> str:
    chat_id = str(candidate.get("chat_id") or "")
    try:
        turn_index = int(candidate.get("turn_index", 0))
        block_index = int(candidate.get("block_index", -1))
    except (TypeError, ValueError):
        return "unknown"

    blocks = load_chat_blocks(args.chats_dir, chat_id, turn_index, block_cache)
    current = "unknown"
    for block in blocks[: max(0, min(block_index, len(blocks) - 1)) + 1]:
        content = str(block.get("content") or "")
        marker = "<summary>Edit file:"
        if marker in content:
            start = content.find(marker) + len(marker)
            end = content.find("</summary>", start)
            if end > start:
                current = content[start:end].strip()
        if "</details>" in content:
            current = "unknown"
    if current != "unknown":
        return current

    content = str(candidate.get("content") or "")
    for line in content.splitlines():
        for prefix in ("+++ b/", "--- a/"):
            if line.startswith(prefix):
                value = line[len(prefix) :].strip()
                if value and value != "/dev/null":
                    return value
        if line.startswith("diff --git a/"):
            parts = line.split()
            if len(parts) >= 3 and parts[2].startswith("b/"):
                return parts[2][2:]
    return "unknown"


def select_findings(args: argparse.Namespace) -> list[dict[str, Any]]:
    agreements = {x.strip() for x in args.agreement.split(",") if x.strip()}
    severities = {x.strip() for x in args.severity.split(",") if x.strip()}
    selected: list[dict[str, Any]] = []
    for row in iter_jsonl(args.findings):
        if args.only_needs_human_cwe_review and not row.get("needs_human_cwe_review"):
            continue
        if agreements and str(row.get("agreement") or "") not in agreements:
            continue
        if severities and str(row.get("severity") or "") not in severities:
            continue
        selected.append(row)
        if args.limit > 0 and len(selected) >= args.limit:
            break
    return selected


def load_needed_candidates(
    candidates_path: Path,
    candidate_ids: set[str],
) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    if not candidate_ids:
        return candidates
    for row in tqdm(iter_jsonl(candidates_path), desc="candidate-lookup"):
        candidate_id = str(row.get("candidate_id") or "")
        if candidate_id in candidate_ids:
            candidates[candidate_id] = row
            if len(candidates) >= len(candidate_ids):
                break
    return candidates


def simplify_evidence(evidence: Any, max_chars: int) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    by_analyzer = evidence.get("by_analyzer")
    simplified: dict[str, Any] = {
        "semgrep_rule_ids": normalize_list(evidence.get("semgrep_rule_ids")),
        "by_analyzer": {},
    }
    if isinstance(by_analyzer, dict):
        for analyzer, items in by_analyzer.items():
            fixed_items: list[dict[str, str]] = []
            if isinstance(items, list):
                for item in items[:8]:
                    if not isinstance(item, dict):
                        continue
                    fixed_items.append(
                        {
                            "quote": clip(item.get("quote"), max_chars),
                            "reason": clip(item.get("reason"), max_chars),
                        }
                    )
            simplified["by_analyzer"][str(analyzer)] = fixed_items
    return simplified


def source_reasoning(finding: dict[str, Any], max_chars: int) -> str:
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    source_findings = details.get("source_findings")
    if isinstance(source_findings, list):
        chunks: list[str] = []
        for src in source_findings[:3]:
            if isinstance(src, dict):
                reasoning = src.get("details", {}).get("reasoning")
                if reasoning:
                    chunks.append(str(reasoning))
                actionability = src.get("actionability_reason")
                if actionability:
                    chunks.append(str(actionability))
        if chunks:
            return clip("\n\n".join(chunks), max_chars)
    return clip(details.get("reasoning"), max_chars)


def build_record(
    finding: dict[str, Any],
    candidate: dict[str, Any],
    args: argparse.Namespace,
    block_cache: dict[tuple[str, int], list[dict[str, Any]]],
) -> dict[str, Any]:
    chat_id = str(finding.get("chat_id") or candidate.get("chat_id") or "")
    try:
        turn_index = int(finding.get("turn_index", candidate.get("turn_index", 0)))
    except (TypeError, ValueError):
        turn_index = 0

    file_path = file_path_for_candidate(candidate, args, block_cache)
    return {
        "id": str(finding.get("finding_id") or finding.get("candidate_id") or ""),
        "record_type": "finding",
        "finding_id": finding.get("finding_id"),
        "finding_ids": [finding.get("finding_id")] if finding.get("finding_id") else [],
        "candidate_id": finding.get("candidate_id"),
        "candidate_ids": [finding.get("candidate_id")] if finding.get("candidate_id") else [],
        "chat_id": chat_id,
        "turn_index": turn_index,
        "file_path": file_path,
        "message_id": candidate.get("message_id"),
        "block_index": candidate.get("block_index"),
        "platform": candidate.get("platform"),
        "timestamp": candidate.get("timestamp"),
        "candidate_type": candidate.get("candidate_type")
        or finding.get("details", {}).get("candidate_type"),
        "language_hint": candidate.get("language_hint")
        or finding.get("details", {}).get("language_hint"),
        "content": clip(candidate.get("content"), args.content_chars),
        "preceding_user_text": clip(
            (candidate.get("metadata") or {}).get("preceding_user_text"),
            args.context_chars,
        ),
        "severity": finding.get("severity"),
        "agreement": finding.get("agreement"),
        "analyzers": normalize_list(finding.get("analyzers") or finding.get("analyzer")),
        "risk_confidence_tier": finding.get("risk_confidence_tier")
        or finding.get("confidence_tier"),
        "cwe_confidence_tier": finding.get("cwe_confidence_tier"),
        "confidence": finding.get("confidence"),
        "primary_cwe": finding.get("primary_cwe"),
        "cwe_ids": normalize_list(finding.get("cwe_ids") or finding.get("cwe")),
        "cwe_specificity": finding.get("cwe_specificity"),
        "needs_human_cwe_review": bool(finding.get("needs_human_cwe_review")),
        "cwe_candidates_considered": normalize_list(finding.get("cwe_candidates_considered")),
        "rejected_cwes": finding.get("rejected_cwes")
        if isinstance(finding.get("rejected_cwes"), list)
        else [],
        "evidence": simplify_evidence(finding.get("evidence"), args.evidence_chars),
        "reasoning": source_reasoning(finding, args.evidence_chars),
        "context_turns": load_chat_context(
            args.chats_dir,
            chat_id,
            turn_index,
            args.context_before,
            args.context_after,
            args.context_chars,
        ),
    }


def severity_rank(value: Any) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        str(value or "").lower(),
        -1,
    )


def review_unit_key(
    record: dict[str, Any],
    review_unit_scope: str,
    group_unknown_file_by_turn: bool,
) -> tuple[str, str, str, str, str]:
    cwe = str(record.get("primary_cwe") or (record.get("cwe_ids") or ["unmapped"])[0])
    chat_id = str(record.get("chat_id") or "")
    turn_index = str(record.get("turn_index") or "")
    file_path = str(record.get("file_path") or "unknown")
    if review_unit_scope == "chat_cwe":
        return ("chat-cwe", chat_id, cwe, "", "")
    if review_unit_scope == "turn_cwe":
        return ("turn-cwe", chat_id, turn_index, cwe, "")
    if file_path == "unknown":
        if group_unknown_file_by_turn:
            return (
                "unknown-file-turn",
                chat_id,
                turn_index,
                cwe,
                "",
            )
        return (
            "unknown-file-candidate",
            str(record.get("candidate_id") or ""),
            cwe,
            "",
            "",
        )
    return (
        "known-file",
        chat_id,
        turn_index,
        file_path,
        cwe,
    )


def review_unit_id(key: tuple[str, str, str, str, str]) -> str:
    raw = "\x1f".join(key)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]
    return f"review-unit:{digest}"


def merge_review_unit(
    records: list[dict[str, Any]],
    key: tuple[str, str, str, str, str],
) -> dict[str, Any]:
    base = max(records, key=lambda row: severity_rank(row.get("severity")))
    findings = []
    candidates = []
    seen_candidates: set[str] = set()
    analyzers: set[str] = set()
    agreements: set[str] = set()
    cwe_ids: set[str] = set()
    file_paths: set[str] = set()
    turn_indices: set[int] = set()
    needs_human_cwe_review = False
    for row in records:
        findings.append(
            {
                "finding_id": row.get("finding_id"),
                "candidate_id": row.get("candidate_id"),
                "severity": row.get("severity"),
                "agreement": row.get("agreement"),
                "risk_confidence_tier": row.get("risk_confidence_tier"),
                "cwe_confidence_tier": row.get("cwe_confidence_tier"),
                "evidence": row.get("evidence"),
                "reasoning": row.get("reasoning"),
            }
        )
        candidate_id = str(row.get("candidate_id") or "")
        if candidate_id and candidate_id not in seen_candidates:
            seen_candidates.add(candidate_id)
            candidates.append(
                {
                    "candidate_id": row.get("candidate_id"),
                    "turn_index": row.get("turn_index"),
                    "block_index": row.get("block_index"),
                    "candidate_type": row.get("candidate_type"),
                    "language_hint": row.get("language_hint"),
                    "file_path": row.get("file_path"),
                    "content": row.get("content"),
                    "context_turns": row.get("context_turns"),
                }
            )
        analyzers.update(normalize_list(row.get("analyzers")))
        if row.get("agreement"):
            agreements.add(str(row.get("agreement")))
        cwe_ids.update(normalize_list(row.get("cwe_ids")))
        if row.get("file_path"):
            file_paths.add(str(row.get("file_path")))
        try:
            turn_indices.add(int(row.get("turn_index", 0)))
        except (TypeError, ValueError):
            pass
        needs_human_cwe_review = needs_human_cwe_review or bool(row.get("needs_human_cwe_review"))

    out = dict(base)
    out["id"] = review_unit_id(key)
    out["record_type"] = "review_unit"
    out["review_unit_id"] = out["id"]
    out["review_unit_key"] = list(key)
    out["finding_id"] = out["id"]
    out["finding_ids"] = [row["finding_id"] for row in records if row.get("finding_id")]
    out["candidate_ids"] = [row["candidate_id"] for row in records if row.get("candidate_id")]
    out["candidate_id"] = out["candidate_ids"][0] if out["candidate_ids"] else None
    out["finding_count"] = len(out["finding_ids"])
    out["candidate_count"] = len(seen_candidates)
    out["file_paths"] = sorted(file_paths)
    out["turn_indices"] = sorted(turn_indices)
    if len(file_paths) == 1:
        out["file_path"] = next(iter(file_paths))
    elif len(file_paths) > 1:
        out["file_path"] = "multiple files"
    out["findings"] = findings
    out["candidates"] = candidates
    out["analyzers"] = sorted(analyzers)
    out["agreement"] = "+".join(sorted(agreements)) if agreements else None
    out["cwe_ids"] = sorted(cwe_ids)
    out["needs_human_cwe_review"] = needs_human_cwe_review
    return out


def group_review_units(
    records: list[dict[str, Any]],
    review_unit_scope: str,
    group_unknown_file_by_turn: bool,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str, str, str, str]] = []
    for record in records:
        key = review_unit_key(record, review_unit_scope, group_unknown_file_by_turn)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(record)
    return [merge_review_unit(grouped[key], key) for key in order]


def main() -> None:
    args = parse_args()
    findings = select_findings(args)
    candidate_ids = {str(row.get("candidate_id") or "") for row in findings}
    candidate_ids.discard("")
    candidates = load_needed_candidates(args.candidates, candidate_ids)

    records: list[dict[str, Any]] = []
    missing_candidates = 0
    block_cache: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for finding in tqdm(findings, desc="records"):
        candidate_id = str(finding.get("candidate_id") or "")
        candidate = candidates.get(candidate_id)
        if candidate is None:
            missing_candidates += 1
            candidate = {}
        records.append(build_record(finding, candidate, args, block_cache))

    finding_record_count = len(records)
    if args.group_review_units:
        records = group_review_units(
            records,
            args.review_unit_scope,
            args.group_unknown_file_by_turn,
        )

    severity_counts = Counter(str(row.get("severity") or "unknown") for row in records)
    agreement_counts = Counter(str(row.get("agreement") or "unknown") for row in records)
    cwe_counts = Counter(cwe for row in records for cwe in row.get("cwe_ids", []))
    payload = {
        "metadata": {
            "source_findings": str(args.findings),
            "source_candidates": str(args.candidates),
            "record_count": len(records),
            "finding_record_count": finding_record_count,
            "group_review_units": args.group_review_units,
            "review_unit_scope": args.review_unit_scope,
            "group_unknown_file_by_turn": args.group_unknown_file_by_turn,
            "missing_candidates": missing_candidates,
            "severity_counts": dict(severity_counts),
            "agreement_counts": dict(agreement_counts),
            "top_cwe": cwe_counts.most_common(30),
            "context_before": args.context_before,
            "context_after": args.context_after,
        },
        "records": records,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
    print(f"Records: {len(records)}")
    if args.group_review_units:
        print(f"Source finding records: {finding_record_count}")
    print(f"Missing candidates: {missing_candidates}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
