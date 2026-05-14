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
    p = argparse.ArgumentParser(description="Group risky findings into conversation-level risk episodes.")
    p.add_argument("--chats-dir", type=Path, required=True)
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--window-before", type=int, default=4)
    p.add_argument("--window-after", type=int, default=2)
    p.add_argument("--merge-max-turn-distance", type=int, default=3)
    p.add_argument(
        "--merge-strategy",
        choices=["cwe_or_candidate_lineage", "cwe", "candidate_lineage", "turn_only"],
        default="cwe_or_candidate_lineage",
    )
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clip(s: str, n: int = 500) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 3] + "..."


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(orjson.loads(line))
    return rows


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


def load_chat_turns(chats_dir: Path, chat_id: str) -> list[dict[str, Any]]:
    path = chats_dir / f"{chat_id}.md.json"
    if not path.exists():
        return []
    data = orjson.loads(path.read_bytes())
    turns: list[dict[str, Any]] = []
    for idx, msg in enumerate(data.get("messages") or []):
        role = str(msg.get("role") or "unknown").strip().lower()
        if role == "assistant":
            role = "assistant"
        elif role == "user":
            role = "user"
        else:
            role = "tool"

        parts: list[str] = []
        for block in flatten_blocks(msg.get("blocks")):
            content = block.get("content")
            if isinstance(content, str) and content.strip():
                btype = str(block.get("type") or "text")
                parts.append(f"[{btype}] {content.strip()}")
        turns.append({"turn_index": idx, "role": role, "text": "\n\n".join(parts)})
    return turns


def cwe_values(finding: dict[str, Any]) -> list[str]:
    raw = finding.get("cwe") or finding.get("cwe_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    return sorted({str(x) for x in raw if isinstance(x, str) and x.startswith("CWE-")})


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if str(x)]
    if value is None:
        return []
    return [str(value)]


def is_risky_finding(finding: dict[str, Any]) -> bool:
    return bool(finding.get("is_risky")) and str(finding.get("severity", "none")).lower() != "none"


def candidate_turn(candidate: dict[str, Any]) -> int:
    value = candidate.get("turn_index", candidate.get("message_index", 0))
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def episode_id_for(chat_id: str, finding_ids: list[str], start_turn: int, end_turn: int) -> str:
    basis = f"{chat_id}:{start_turn}:{end_turn}:{','.join(sorted(finding_ids))}"
    return "risk-episode:" + sha256_text(basis)[:24]


def finding_lineage_key(item: dict[str, Any]) -> str:
    finding = item["finding"]
    candidate = item["candidate"]
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    content_hash = candidate.get("content_hash") or details.get("content_hash")
    if content_hash:
        return f"content:{content_hash}"
    candidate_id = candidate.get("candidate_id")
    if candidate_id:
        parts = str(candidate_id).split(":")
        if len(parts) >= 2:
            return f"candidate-msg:{parts[0]}:{parts[1]}"
    language = candidate.get("language_hint") or details.get("language_hint") or "unknown"
    cwes = ",".join(cwe_values(finding)) or "NO_CWE"
    return f"{language}:{cwes}"


def related_findings(left: dict[str, Any], right: dict[str, Any], strategy: str) -> bool:
    if strategy == "turn_only":
        return True
    left_cwes = set(cwe_values(left["finding"]))
    right_cwes = set(cwe_values(right["finding"]))
    same_cwe = bool(left_cwes and right_cwes and left_cwes & right_cwes)
    same_lineage = finding_lineage_key(left) == finding_lineage_key(right)
    if strategy == "cwe":
        return same_cwe
    if strategy == "candidate_lineage":
        return same_lineage
    return same_cwe or same_lineage


def group_lineage_id(chat_id: str, group: list[dict[str, Any]]) -> str:
    cwes = sorted({cwe for item in group for cwe in cwe_values(item["finding"])})
    lineage_keys = sorted({finding_lineage_key(item) for item in group})
    basis = f"{chat_id}:{','.join(cwes) or 'NO_CWE'}:{','.join(lineage_keys)}"
    return "risk-lineage:" + sha256_text(basis)[:24]


def strongest_confidence_tier(grouped: list[dict[str, Any]]) -> str:
    rank = {"excluded": 0, "low": 1, "medium": 2, "high": 3}
    best = "low"
    for item in grouped:
        tier = str(item["finding"].get("confidence_tier") or "low")
        if rank.get(tier, 1) > rank[best]:
            best = tier
    return best


def strongest_tier(grouped: list[dict[str, Any]], field: str, default: str = "low") -> str:
    rank = {"excluded": 0, "unmapped": 0, "low": 1, "medium": 2, "high": 3}
    best = default
    for item in grouped:
        tier = str(item["finding"].get(field) or default)
        if rank.get(tier, rank.get(default, 1)) > rank.get(best, 1):
            best = tier
    return best


def primary_cwe_for_group(grouped: list[dict[str, Any]], cwes: list[str]) -> str | None:
    for item in grouped:
        value = item["finding"].get("primary_cwe")
        if isinstance(value, str) and value in cwes:
            return value
    return cwes[0] if cwes else None


def build_evidence_quotes(turns: list[dict[str, Any]], start_turn: int, end_turn: int, risk_turns: set[int]) -> list[dict[str, Any]]:
    quotes: list[dict[str, Any]] = []
    for turn in turns:
        idx = int(turn["turn_index"])
        if idx < start_turn or idx > end_turn:
            continue
        text = clip(turn.get("text") or "", 700)
        if not text:
            continue
        why = "risk candidate turn" if idx in risk_turns else "context window"
        quotes.append(
            {
                "turn_index": idx,
                "role": turn["role"],
                "quote": text,
                "why_relevant": why,
            }
        )
    return quotes


def build_episode(
    chat_id: str,
    grouped: list[dict[str, Any]],
    turns: list[dict[str, Any]],
    window_before: int,
    window_after: int,
    risk_lineage_id: str,
    lineage_role: str,
) -> dict[str, Any]:
    finding_ids = sorted({str(item["finding"].get("finding_id") or "") for item in grouped if item["finding"].get("finding_id")})
    candidate_ids = sorted({str(item["candidate"].get("candidate_id") or "") for item in grouped if item["candidate"].get("candidate_id")})
    risk_turns = sorted({int(item["turn_index"]) for item in grouped})
    start_turn = max(0, min(risk_turns) - window_before)
    max_turn = max((int(t["turn_index"]) for t in turns), default=max(risk_turns))
    end_turn = min(max_turn, max(risk_turns) + window_after)
    cwes = sorted({cwe for item in grouped for cwe in cwe_values(item["finding"])})
    primary_cwe = primary_cwe_for_group(grouped, cwes)
    severities = sorted({str(item["finding"].get("severity") or "none") for item in grouped})
    analyzers = sorted(
        {
            analyzer
            for item in grouped
            for analyzer in (
                as_list(item["finding"].get("analyzers"))
                or [str(item["finding"].get("analyzer") or "unknown")]
            )
        }
    )
    agreements = sorted({str(item["finding"].get("agreement") or "unknown") for item in grouped})

    summary_bits = []
    if cwes:
        summary_bits.append("/".join(cwes))
    if analyzers:
        summary_bits.append("+".join(analyzers))
    risk_summary = f"Preliminary episode for {' '.join(summary_bits) or 'risk'} at turn {min(risk_turns)}."

    return {
        "episode_id": episode_id_for(chat_id, finding_ids, start_turn, end_turn),
        "chat_id": chat_id,
        "finding_ids": finding_ids,
        "candidate_ids": candidate_ids,
        "risk_lineage_id": risk_lineage_id,
        "lineage_role": lineage_role,
        "risk_turn_index": min(risk_turns),
        "episode_window": {"start_turn": start_turn, "end_turn": end_turn},
        "interaction_stage": "unknown",
        "risk_origin": "unknown",
        "mechanism": "unknown",
        "risk_evolution": "introduced",
        "user_reaction": "unknown",
        "confidence_tier": strongest_confidence_tier(grouped),
        "risk_confidence_tier": strongest_tier(grouped, "risk_confidence_tier")
        if any(item["finding"].get("risk_confidence_tier") for item in grouped)
        else strongest_confidence_tier(grouped),
        "cwe_confidence_tier": strongest_tier(grouped, "cwe_confidence_tier", "unmapped")
        if any(item["finding"].get("cwe_confidence_tier") for item in grouped)
        else ("medium" if cwes else "unmapped"),
        "cwe_ids": cwes,
        "primary_cwe": primary_cwe,
        "cwe_abstraction": next(
            (
                item["finding"].get("cwe_abstraction")
                for item in grouped
                if item["finding"].get("primary_cwe") == primary_cwe
            ),
            None,
        ),
        "cwe_specificity": next(
            (
                item["finding"].get("cwe_specificity")
                for item in grouped
                if item["finding"].get("primary_cwe") == primary_cwe
            ),
            "specific" if primary_cwe else "unmapped",
        ),
        "needs_human_cwe_review": any(bool(item["finding"].get("needs_human_cwe_review")) for item in grouped),
        "risk_summary": risk_summary,
        "evidence_turns": list(range(start_turn, end_turn + 1)),
        "evidence_quotes": build_evidence_quotes(turns, start_turn, end_turn, set(risk_turns)),
        "human_verified": None,
        "human_notes": None,
        "details": {
            "severity_values": severities,
            "analyzers": analyzers,
            "agreements": agreements,
            "finding_summaries": [
                {
                    "finding_id": item["finding"].get("finding_id"),
                    "candidate_id": item["candidate"].get("candidate_id"),
                    "turn_index": item["turn_index"],
                    "analyzer": item["finding"].get("analyzer"),
                    "analyzers": item["finding"].get("analyzers"),
                    "agreement": item["finding"].get("agreement"),
                    "confidence_tier": item["finding"].get("confidence_tier"),
                    "risk_confidence_tier": item["finding"].get("risk_confidence_tier"),
                    "cwe_confidence_tier": item["finding"].get("cwe_confidence_tier"),
                    "severity": item["finding"].get("severity"),
                    "cwe": cwe_values(item["finding"]),
                    "candidate_type": item["candidate"].get("candidate_type"),
                    "language_hint": item["candidate"].get("language_hint"),
                    "rule_id": item["finding"].get("rule_id"),
                    "evidence": item["finding"].get("evidence", []),
                }
                for item in grouped
            ],
        },
    }


def main() -> None:
    args = parse_args()
    candidates = {str(c.get("candidate_id")): c for c in load_jsonl(args.candidates)}
    findings = load_jsonl(args.findings)
    by_chat: dict[str, list[dict[str, Any]]] = {}
    counts: Counter[str] = Counter()

    for finding in findings:
        counts["findings_seen"] += 1
        if not is_risky_finding(finding):
            counts["findings_not_risky"] += 1
            continue
        candidate = candidates.get(str(finding.get("candidate_id") or ""))
        if candidate is None:
            counts["missing_candidate"] += 1
            continue
        chat_id = str(candidate.get("chat_id") or finding.get("chat_id") or "")
        if not chat_id:
            counts["missing_chat_id"] += 1
            continue
        by_chat.setdefault(chat_id, []).append(
            {"finding": finding, "candidate": candidate, "turn_index": candidate_turn(candidate)}
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    episode_count = 0
    with args.out.open("wb") as wf:
        for chat_id, items in tqdm(sorted(by_chat.items()), desc="risk-episodes"):
            turns = load_chat_turns(args.chats_dir, chat_id)
            items.sort(key=lambda item: (item["turn_index"], str(item["finding"].get("finding_id") or "")))
            groups: list[list[dict[str, Any]]] = []
            for item in items:
                if groups:
                    previous = groups[-1][-1]
                    turn_distance = int(item["turn_index"]) - int(previous["turn_index"])
                    if (
                        turn_distance <= args.merge_max_turn_distance
                        and related_findings(previous, item, args.merge_strategy)
                    ):
                        groups[-1].append(item)
                        continue
                groups.append([item])

            lineage_seen: Counter[str] = Counter()
            for group in groups:
                lineage_id = group_lineage_id(chat_id, group)
                lineage_seen[lineage_id] += 1
                lineage_role = "introduced" if lineage_seen[lineage_id] == 1 else "propagated"
                episode = build_episode(
                    chat_id,
                    group,
                    turns,
                    args.window_before,
                    args.window_after,
                    lineage_id,
                    lineage_role,
                )
                wf.write(orjson.dumps(episode) + b"\n")
                episode_count += 1

    print(f"Findings seen: {counts['findings_seen']}")
    print(f"Risky findings with candidates: {sum(len(v) for v in by_chat.values())}")
    print(f"Risk episodes: {episode_count}")
    print(f"Skipped: {dict(sorted((k, v) for k, v in counts.items() if k not in {'findings_seen'}))}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
