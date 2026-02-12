#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson

DANGEROUS_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    re.compile(r"\b(md5|sha1|des|ecb)\b", re.IGNORECASE),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.(Popen|run)\s*\("),
    re.compile(r"\bSELECT\b.+\+.+\bFROM\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.+\|\s*(sh|bash)\b", re.IGNORECASE),
]

STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "please",
    "your",
    "have",
    "will",
    "should",
    "were",
    "been",
    "about",
    "output",
    "summary",
    "feature",
    "settings",
    "error",
    "issue",
    "token",
}


CAUSES = [
    "user_requested_risk",
    "assistant_over_implemented",
    "assistant_hallucinated_risk",
    "inherited_or_context_risk",
    "mixed_causality",
    "insufficient_evidence",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze attribution and causal patterns for risky backtrace data.")
    p.add_argument("--backtrace", type=Path, default=Path("analysis/output/risky_backtrace_all.jsonl"))
    p.add_argument("--attribution", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, default=Path("analysis/output/attribution_analysis"))
    p.add_argument("--min-confidence", type=float, default=0.0)
    p.add_argument("--only-high-confidence", action="store_true", default=False)
    return p.parse_args()


def flatten_blocks(blocks: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(blocks, list):
        return out
    for entry in blocks:
        if isinstance(entry, dict):
            out.append(entry)
        elif isinstance(entry, list):
            for inner in entry:
                if isinstance(inner, dict):
                    out.append(inner)
    return out


def message_text(msg: dict[str, Any]) -> str:
    parts: list[str] = []
    for blk in flatten_blocks(msg.get("blocks")):
        if blk.get("type") == "text" and isinstance(blk.get("content"), str):
            parts.append(blk["content"])
    return "\n".join(parts).strip()


def short(s: str, n: int = 220) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for raw in f:
            if not raw.strip():
                continue
            rows.append(orjson.loads(raw))
    return rows


def extract_keywords(rec: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()

    candidate = (((rec.get("assistant_context") or {}).get("candidate_text")) or "")
    for t in re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{3,}", candidate):
        low = t.lower()
        if low not in STOPWORDS:
            tokens.add(low)

    for ev in (rec.get("risk") or {}).get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        quote = str(ev.get("quote", ""))
        for t in re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{3,}", quote):
            low = t.lower()
            if low not in STOPWORDS:
                tokens.add(low)

    for cwe in (rec.get("risk") or {}).get("cwe") or []:
        if isinstance(cwe, str) and cwe.startswith("CWE-"):
            tokens.add(cwe.lower())

    # keep top size to avoid noisy matching
    return set(sorted(tokens, key=len, reverse=True)[:30])


def hit_score(text: str, keywords: set[str]) -> int:
    low = text.lower()
    score = 0
    for k in keywords:
        if len(k) >= 6 and k in low:
            score += 1
    for pat in DANGEROUS_PATTERNS:
        if pat.search(text):
            score += 2
    return score


def looks_concrete_risky_assistant(text: str) -> bool:
    if any(p.search(text) for p in DANGEROUS_PATTERNS):
        return True
    if "```" in text:
        return True
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return any(ln.startswith(("curl ", "wget ", "sudo ", "chmod ", "docker ", "kubectl ")) for ln in lines)


def trace_chat_turns(chat_path: Path, assistant_turn: int, keywords: set[str]) -> dict[str, Any]:
    if not chat_path.exists():
        return {
            "first_mention_turn": None,
            "first_concretization_turn": None,
            "first_persistence_turn": None,
            "trace_note": "chat_missing",
        }

    chat = orjson.loads(chat_path.read_bytes())
    messages = chat.get("messages") or []
    if not isinstance(messages, list):
        return {
            "first_mention_turn": None,
            "first_concretization_turn": None,
            "first_persistence_turn": None,
            "trace_note": "invalid_chat_messages",
        }

    first_mention: int | None = None
    first_concrete: int | None = None
    first_persist: int | None = None

    max_idx = min(assistant_turn, len(messages) - 1)
    for idx in range(0, max_idx + 1):
        msg = messages[idx]
        if not isinstance(msg, dict):
            continue
        text = message_text(msg)
        if not text:
            continue

        score = hit_score(text, keywords)
        if score >= 2 and first_mention is None:
            first_mention = idx

        role = str(msg.get("role", "")).lower()
        if role == "assistant" and score >= 2 and looks_concrete_risky_assistant(text):
            if first_concrete is None:
                first_concrete = idx
            elif idx > first_concrete and first_persist is None:
                first_persist = idx

    return {
        "first_mention_turn": first_mention,
        "first_concretization_turn": first_concrete,
        "first_persistence_turn": first_persist,
        "trace_note": "ok",
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k) for k in fieldnames})


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    backtrace_rows = load_jsonl(args.backtrace)
    attribution_rows = load_jsonl(args.attribution)

    by_finding = {str(r.get("finding_id")): r for r in backtrace_rows if r.get("finding_id")}

    selected: list[dict[str, Any]] = []
    for att in attribution_rows:
        fid = str(att.get("finding_id", ""))
        if not fid or fid not in by_finding:
            continue

        conf = float(att.get("confidence", 0.0) or 0.0)
        if args.only_high_confidence and conf < max(args.min_confidence, 0.7):
            continue
        if conf < args.min_confidence:
            continue

        rec = by_finding[fid]
        merged = {"attribution": att, "backtrace": rec}
        selected.append(merged)

    enriched_rows: list[dict[str, Any]] = []
    trace_rows: list[dict[str, Any]] = []

    cause_counter: Counter[str] = Counter()
    cause_by_cwe: dict[str, Counter[str]] = defaultdict(Counter)
    cwe_total: Counter[str] = Counter()

    for item in selected:
        att = item["attribution"]
        rec = item["backtrace"]

        fid = str(att.get("finding_id", ""))
        primary = str(att.get("primary_cause", "insufficient_evidence"))
        if primary not in CAUSES:
            primary = "insufficient_evidence"

        cause_counter[primary] += 1

        risk = rec.get("risk") or {}
        cwes = [c for c in (risk.get("cwe") or []) if isinstance(c, str) and c.startswith("CWE-")]
        if not cwes:
            cwes = ["CWE-UNKNOWN"]

        for cwe in cwes:
            cause_by_cwe[cwe][primary] += 1
            cwe_total[cwe] += 1

        assistant_idx = (((rec.get("assistant_context") or {}).get("message_index")) or 0)
        try:
            assistant_idx = int(assistant_idx)
        except (TypeError, ValueError):
            assistant_idx = 0

        chat_path = Path(str(rec.get("chat_path", "")))
        kws = extract_keywords(rec)
        trace = trace_chat_turns(chat_path, assistant_idx, kws)

        trace_row = {
            "finding_id": fid,
            "candidate_id": rec.get("candidate_id"),
            "chat_id": rec.get("chat_id"),
            "primary_cause": primary,
            "confidence": float(att.get("confidence", 0.0) or 0.0),
            "assistant_risk_turn": assistant_idx,
            "first_mention_turn": trace["first_mention_turn"],
            "first_concretization_turn": trace["first_concretization_turn"],
            "first_persistence_turn": trace["first_persistence_turn"],
            "trace_note": trace["trace_note"],
            "nearest_user_excerpt": short(((rec.get("nearest_user") or {}).get("text")) or "", 180),
            "assistant_excerpt": short(((rec.get("assistant_context") or {}).get("candidate_text")) or "", 180),
        }
        trace_rows.append(trace_row)

        enriched_rows.append(
            {
                "finding_id": fid,
                "candidate_id": rec.get("candidate_id"),
                "chat_id": rec.get("chat_id"),
                "severity": risk.get("severity"),
                "risk_confidence": risk.get("confidence"),
                "primary_cause": primary,
                "secondary_cause": att.get("secondary_cause"),
                "attribution_confidence": float(att.get("confidence", 0.0) or 0.0),
                "is_user_driven": bool(att.get("is_user_driven", False)),
                "is_assistant_driven": bool(att.get("is_assistant_driven", False)),
                "needs_human_review": bool(att.get("needs_human_review", False)),
                "cwe": "|".join(cwes),
                "trace_first_mention_turn": trace["first_mention_turn"],
                "trace_first_concretization_turn": trace["first_concretization_turn"],
                "trace_first_persistence_turn": trace["first_persistence_turn"],
            }
        )

    cwe_rows: list[dict[str, Any]] = []
    for cwe, total in sorted(cwe_total.items(), key=lambda x: (-x[1], x[0])):
        row: dict[str, Any] = {"cwe": cwe, "total": total}
        for cause in CAUSES:
            cnt = cause_by_cwe[cwe][cause]
            row[cause] = cnt
            row[f"{cause}_ratio"] = round(cnt / total, 4) if total else 0.0
        cwe_rows.append(row)

    summary = {
        "num_backtrace_rows": len(backtrace_rows),
        "num_attribution_rows": len(attribution_rows),
        "num_joined_rows": len(selected),
        "filters": {
            "min_confidence": args.min_confidence,
            "only_high_confidence": args.only_high_confidence,
        },
        "attribution_distribution": {
            cause: {
                "count": cause_counter[cause],
                "ratio": round(cause_counter[cause] / len(selected), 4) if selected else 0.0,
            }
            for cause in CAUSES
        },
        "trace_coverage": {
            "has_first_mention": sum(1 for r in trace_rows if r["first_mention_turn"] is not None),
            "has_first_concretization": sum(1 for r in trace_rows if r["first_concretization_turn"] is not None),
            "has_first_persistence": sum(1 for r in trace_rows if r["first_persistence_turn"] is not None),
        },
        "top_cwe": [
            {"cwe": cwe, "count": count}
            for cwe, count in sorted(cwe_total.items(), key=lambda x: (-x[1], x[0]))[:15]
        ],
    }

    write_csv(
        args.out_dir / "attribution_enriched.csv",
        enriched_rows,
        [
            "finding_id",
            "candidate_id",
            "chat_id",
            "severity",
            "risk_confidence",
            "primary_cause",
            "secondary_cause",
            "attribution_confidence",
            "is_user_driven",
            "is_assistant_driven",
            "needs_human_review",
            "cwe",
            "trace_first_mention_turn",
            "trace_first_concretization_turn",
            "trace_first_persistence_turn",
        ],
    )

    write_csv(
        args.out_dir / "conversation_tracing.csv",
        trace_rows,
        [
            "finding_id",
            "candidate_id",
            "chat_id",
            "primary_cause",
            "confidence",
            "assistant_risk_turn",
            "first_mention_turn",
            "first_concretization_turn",
            "first_persistence_turn",
            "trace_note",
            "nearest_user_excerpt",
            "assistant_excerpt",
        ],
    )

    cwe_fields = ["cwe", "total"] + [x for c in CAUSES for x in (c, f"{c}_ratio")]
    write_csv(args.out_dir / "cwe_attribution.csv", cwe_rows, cwe_fields)

    (args.out_dir / "summary.json").write_bytes(orjson.dumps(summary, option=orjson.OPT_INDENT_2))

    print(f"Backtrace rows: {len(backtrace_rows)}")
    print(f"Attribution rows: {len(attribution_rows)}")
    print(f"Joined rows: {len(selected)}")
    print(f"Output dir: {args.out_dir}")


if __name__ == "__main__":
    main()
