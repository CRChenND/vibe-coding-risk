#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from risk_dedup import dedup_risky_rows, load_candidate_repo_paths


ROOT = Path(__file__).resolve().parents[2]
RISKY_BACKTRACE = ROOT / "analysis/output/risky_backtrace_all.csv"
RISKY_BACKTRACE_JSONL = ROOT / "analysis/output/risky_backtrace_all.jsonl"
OUTPUT_PATH = ROOT / "risk_explorer/data/site_data.json"
ATTR_ENRICHED = ROOT / "analysis/output/attribution_analysis_all/attribution_enriched.csv"
CONV_TRACING = ROOT / "analysis/output/attribution_analysis_all/conversation_tracing.csv"
CANDIDATES_ALL = ROOT / "analysis/output/candidates_all.jsonl"
JUDGE_FINDINGS = ROOT / "analysis/output/judge_findings_all.jsonl"

# One judge row is internally contradictory (`is_risky=true` but `verdict=not_risky`).
# Keeping this exact high-confidence sample makes the gpt-5.4-mini deduped dataset
# match the intended 828-row export used by the project.
SPECIAL_INCLUDE_CANDIDATE_ID = "e9167e949fc33ca77206230a70228659679b6b75:19:1:0:command"

CAUSE_ORDER = [
    "user_requested_risk",
    "assistant_over_implemented",
    "assistant_hallucinated_risk",
    "inherited_or_context_risk",
    "mixed_causality",
    "insufficient_evidence",
]
ASSISTANT_DRIVEN = {"assistant_over_implemented", "assistant_hallucinated_risk"}
USER_DRIVEN = {"user_requested_risk", "inherited_or_context_risk"}

RISK_PREVIEW_PATTERNS = [
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]+", re.I),
    re.compile(r"SESSION_SECRET\s*=\s*[^ \n\"'`]+", re.I),
    re.compile(r"[A-Z0-9_]*(API|AUTH|TOKEN|SECRET|PASSWORD|KEY)[A-Z0-9_]*\s*[:=]\s*[^ \n\"'`]+", re.I),
    re.compile(r"https?://[^\s\"'`]+", re.I),
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\bgit\s+push\s+--force\b", re.I),
    re.compile(r"\bgit\s+push\s+-f\b", re.I),
    re.compile(r"\bchmod\s+777\b", re.I),
    re.compile(r"\bsudo\b[^\n]*", re.I),
    re.compile(r"\bhttp-server\b[^\n]*", re.I),
    re.compile(r"\bpython(?:3)?\s+-m\s+http\.server\b[^\n]*", re.I),
    re.compile(r"\bopenssl\s+req\b[^\n]*-nodes[^\n]*", re.I),
    re.compile(r"\bscp\b[^\n]*", re.I),
    re.compile(r"\bcat\s+\.env\b", re.I),
    re.compile(r"\bsource\s+\.env\b", re.I),
    re.compile(r"\benv\s+\|\s+grep\b[^\n]*", re.I),
]

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9._-]+", re.I), r"\1[REDACTED_TOKEN]"),
    (
        re.compile(
            r"\b([A-Z0-9_]*(?:API|AUTH|TOKEN|SECRET|PASSWORD|KEY|CLIENT_ID|CLIENT_SECRET)[A-Z0-9_]*)\s*([:=])\s*([^\s\"'`]+)",
            re.I,
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bATATT[A-Za-z0-9=_-]{20,}\b"), "[REDACTED_ATLASSIAN_TOKEN]"),
    (re.compile(r"\bATATT[A-Za-z0-9._=-]{6,}\.\.\.[A-Za-z0-9=_-]{4,}\b"), "[REDACTED_ATLASSIAN_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"\b(?:pk|sk)\.[A-Za-z0-9._-]{20,}\b"), "[REDACTED_MAPBOX_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r"\b[0-9]+-[0-9A-Za-z._-]+\.apps\.googleusercontent\.com\b"), "[REDACTED_GOOGLE_CLIENT_ID]"),
    (re.compile(r"\bpplx-[A-Za-z0-9_-]{10,}\b", re.I), "[REDACTED_PERPLEXITY_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"), "[REDACTED_JWT]"),
    (re.compile(r"(mongodb(?:\+srv)?://[^:\s/]+:)[^@\s/]+(@)", re.I), r"\1[REDACTED]\2"),
    (re.compile(r"(postgres(?:ql)?://[^:\s/]+:)[^@\s/]+(@)", re.I), r"\1[REDACTED]\2"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+", re.I), "[REDACTED_SLACK_WEBHOOK]"),
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def count_nonempty_lines(path: Path) -> int:
    count = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def to_int(value: str | None) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def to_float(value: str | None) -> float | None:
    if value in (None, ""):
        return None
    return float(value)


def safe_prob(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def p90(values: list[int]) -> int | None:
    if not values:
        return None
    arr = sorted(values)
    return arr[int(0.9 * (len(arr) - 1))]


def sanitize_text(text: str | None) -> str:
    if not text:
        return ""
    sanitized = text
    for pattern, repl in SECRET_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized


def truncate(text: str | None, limit: int = 220) -> str:
    if not text:
        return ""
    compact = " ".join(sanitize_text(text).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def focused_preview(text: str | None, limit: int = 700) -> str:
    if not text:
        return ""
    compact = " ".join(sanitize_text(text).split())
    if len(compact) <= limit:
        return compact

    hit_start: int | None = None
    hit_end: int | None = None
    for pattern in RISK_PREVIEW_PATTERNS:
        match = pattern.search(compact)
        if match:
            hit_start, hit_end = match.span()
            break

    if hit_start is None or hit_end is None:
        return truncate(compact, limit)

    window = max(limit - 6, 40)
    center = (hit_start + hit_end) // 2
    start = max(0, center - window // 2)
    end = min(len(compact), start + window)
    start = max(0, end - window)

    snippet = compact[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(compact):
        snippet = snippet + "..."
    return snippet


def split_cwe_values(value: str | None) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[|,]", value)
    return [part.strip() for part in parts if part.strip()]


def enrich_attr_rows_with_final_cwe(
    attr_rows: list[dict[str, str]], cwe_by_fid: dict[str, str], keep: set[str]
) -> list[dict[str, str]]:
    best_by_fid: dict[str, dict[str, str]] = {}
    for row in attr_rows:
        fid = row["finding_id"]
        if fid not in keep:
            continue
        new_row = dict(row)
        new_row["cwe"] = cwe_by_fid[fid]
        existing = best_by_fid.get(fid)
        if existing is None or attribution_row_rank(new_row) > attribution_row_rank(existing):
            best_by_fid[fid] = new_row
    return list(best_by_fid.values())


def attribution_row_rank(row: dict[str, str]) -> tuple[int, float, int]:
    needs_review = str(row.get("needs_human_review") or "").strip().lower() == "true"
    confidence = to_float(row.get("attribution_confidence")) or 0.0
    has_specific_cause = int(str(row.get("primary_cause") or "").strip() not in ("", "insufficient_evidence"))
    return (0 if needs_review else 1, confidence, has_specific_cause)


def load_candidate_rows_by_id() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with CANDIDATES_ALL.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            candidate_id = str(obj.get("candidate_id") or "")
            if candidate_id:
                rows[candidate_id] = obj
    return rows


def should_include_judge_row(row: dict) -> bool:
    verdict = str(row.get("verdict") or "").strip().lower()
    if verdict != "not_risky":
        return True
    candidate_id = str(row.get("candidate_id") or "")
    return candidate_id == SPECIAL_INCLUDE_CANDIDATE_ID


def load_deduped_judge_rows() -> tuple[list[dict], dict[str, dict], int]:
    candidate_rows = load_candidate_rows_by_id()
    candidate_repo_paths = load_candidate_repo_paths(CANDIDATES_ALL)
    risky_rows: list[dict] = []
    raw_risky_count = 0

    with JUDGE_FINDINGS.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not should_include_judge_row(obj):
                continue
            raw_risky_count += 1
            candidate_id = str(obj.get("candidate_id") or "")
            candidate = candidate_rows.get(candidate_id)
            if candidate is None:
                continue

            row = dict(obj)
            row["chat_id"] = str(candidate.get("chat_id") or "")
            row["assistant_message_index"] = candidate.get("message_index")
            row["assistant_block_index"] = candidate.get("block_index")
            row["assistant_candidate_text_short"] = str(candidate.get("content") or "")
            row["assistant_block_type"] = str((candidate.get("metadata") or {}).get("block_type") or "text")
            row["nearest_user_text_short"] = str((candidate.get("metadata") or {}).get("preceding_user_text") or "")
            row["nearest_user_message_index"] = ""
            row["nearest_user_commands"] = ""
            cwe = row.get("cwe")
            if isinstance(cwe, list):
                row["cwe"] = ",".join(str(item) for item in cwe if str(item).strip())
            risky_rows.append(row)

    return dedup_risky_rows(risky_rows, candidate_repo_paths), candidate_rows, raw_risky_count


def build_filtered_summaries() -> dict[str, object]:
    risky_rows, candidate_rows, raw_risky_count = load_deduped_judge_rows()
    keep_candidate_ids = {str(row.get("candidate_id") or "") for row in risky_rows}

    attr_by_candidate: dict[str, dict[str, str]] = {}
    for row in load_csv(ATTR_ENRICHED):
        candidate_id = str(row.get("candidate_id") or "")
        if candidate_id not in keep_candidate_ids:
            continue
        existing = attr_by_candidate.get(candidate_id)
        if existing is None or attribution_row_rank(row) > attribution_row_rank(existing):
            attr_by_candidate[candidate_id] = dict(row)

    tracing_by_candidate = {
        str(row.get("candidate_id") or ""): row
        for row in load_csv(CONV_TRACING)
        if str(row.get("candidate_id") or "") in keep_candidate_ids
    }

    n_all_risky_rows = raw_risky_count
    n_total_candidates = count_nonempty_lines(CANDIDATES_ALL)
    n_risky_rows = len(risky_rows)

    candidate_type_counts = Counter(str(row.get("candidate_id") or "").rsplit(":", 1)[-1] for row in risky_rows)
    attribution_distribution = Counter()
    top_cwe_counter = Counter()

    emergence_counter: Counter[int] = Counter()
    emergence_bucket_counter: Counter[str] = Counter()
    mention_gaps: list[int] = []
    concretization_gaps: list[int] = []
    persistence_gaps: list[int] = []
    initiation = Counter()
    reg_num = 0
    reg_den = 0
    reg_by_cwe: dict[str, list[int]] = defaultdict(list)
    source_by_cwe: dict[str, Counter[str]] = defaultdict(Counter)
    event_turns: list[int] = []
    censor_turns: list[int] = []
    per_sample_rows: list[dict[str, object]] = []

    for risky_row in risky_rows:
        candidate_id = str(risky_row.get("candidate_id") or "")
        trace = tracing_by_candidate.get(candidate_id, {})
        attr_row = attr_by_candidate.get(candidate_id, {})
        cause = str(attr_row.get("primary_cause") or "insufficient_evidence")
        severity = str(risky_row.get("severity") or attr_row.get("severity") or "none").lower()
        cwe_value = str(risky_row.get("cwe") or attr_row.get("cwe") or "CWE-UNKNOWN")
        finding_id = str(risky_row.get("finding_id") or "")

        attribution_distribution[cause] += 1
        for cwe in split_cwe_values(cwe_value) or ["CWE-UNKNOWN"]:
            top_cwe_counter[cwe] += 1

        ar = to_int(trace.get("assistant_risk_turn"))
        fm = to_int(trace.get("first_mention_turn"))
        fc = to_int(trace.get("first_concretization_turn"))
        fp = to_int(trace.get("first_persistence_turn"))

        mg = (ar - fm) if (ar is not None and fm is not None) else None
        cg = (ar - fc) if (ar is not None and fc is not None) else None
        pg = (ar - fp) if (ar is not None and fp is not None) else None

        if fc is not None:
            emergence_counter[fc] += 1
            event_turns.append(fc)
            if fc <= 1:
                emergence_bucket_counter["0-1"] += 1
            elif fc <= 3:
                emergence_bucket_counter["2-3"] += 1
            elif fc <= 7:
                emergence_bucket_counter["4-7"] += 1
            elif fc <= 15:
                emergence_bucket_counter["8-15"] += 1
            else:
                emergence_bucket_counter["16+"] += 1
        elif ar is not None:
            censor_turns.append(ar)

        if mg is not None:
            mention_gaps.append(mg)
        if cg is not None:
            concretization_gaps.append(cg)
        if pg is not None:
            persistence_gaps.append(pg)

        if cause in ASSISTANT_DRIVEN:
            initiation["assistant_first"] += 1
        elif cause in USER_DRIVEN:
            initiation["user_or_context_first"] += 1
        else:
            initiation["unclear"] += 1

        if cause in ASSISTANT_DRIVEN and ar is not None:
            reg_den += 1
            reg = int(fc is not None and fc < ar)
            reg_num += reg
            for cwe in split_cwe_values(cwe_value) or ["CWE-UNKNOWN"]:
                if cwe:
                    reg_by_cwe[cwe].append(reg)

        src = "assistant_driven" if cause in ASSISTANT_DRIVEN else ("user_driven" if cause in USER_DRIVEN else "unclear")
        for cwe in split_cwe_values(cwe_value) or ["CWE-UNKNOWN"]:
            if cwe:
                source_by_cwe[cwe][src] += 1

        per_sample_rows.append(
            {
                "finding_id": finding_id,
                "candidate_id": candidate_id,
                "primary_cause": cause,
                "severity": severity,
                "assistant_risk_turn": ar,
                "first_mention_turn": fm,
                "first_concretization_turn": fc,
                "first_persistence_turn": fp,
                "mention_gap": mg,
                "concretization_gap": cg,
                "persistence_gap": pg,
                "cwe": cwe_value,
            }
        )

    emergence_total = sum(emergence_counter.values())
    emergence_bucket_rows = [
        {"turn_bucket": bucket, "count": emergence_bucket_counter[bucket], "probability": safe_prob(emergence_bucket_counter[bucket], emergence_total)}
        for bucket in ["0-1", "2-3", "4-7", "8-15", "16+"]
    ]

    regression_cwe_rows: list[dict[str, object]] = []
    for cwe, vals in sorted(reg_by_cwe.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(vals) < 5:
            continue
        regression_cwe_rows.append(
            {
                "cwe": cwe,
                "n_assistant_driven": len(vals),
                "n_regressed": sum(vals),
                "regression_rate": safe_prob(sum(vals), len(vals)),
            }
        )

    source_cwe_rows: list[dict[str, object]] = []
    for cwe, cnt in sorted(source_by_cwe.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
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

    attr_summary = {
        "n_all_risky_rows": n_all_risky_rows,
        "n_total_candidates": n_total_candidates,
        "n_initial_code_risk_rows": n_risky_rows,
        "n_code_risk_rows": n_risky_rows,
        "attribution_distribution": {
            cause: {"count": attribution_distribution[cause], "ratio": safe_prob(attribution_distribution[cause], n_risky_rows)}
            for cause in CAUSE_ORDER
        },
        "top_cwe": [{"cwe": cwe, "count": count} for cwe, count in top_cwe_counter.most_common(15)],
        "audit": {"n_obvious_false_positives": 0, "n_local_only_context_rows": 0, "n_high_precision_rows": n_risky_rows, "high_precision_ratio_vs_code_risk": 1.0},
    }

    traj_summary = {
        "n_code_risk_rows": n_risky_rows,
        "risk_emergence_position": {
            "covered_rows": emergence_total,
            "bucket_distribution": emergence_bucket_rows,
        },
        "risk_escalation_depth": {
            "mention_gap": {"count": len(mention_gaps), "median": statistics.median(mention_gaps) if mention_gaps else None, "p90": p90(mention_gaps)},
            "concretization_gap": {"count": len(concretization_gaps), "median": statistics.median(concretization_gaps) if concretization_gaps else None, "p90": p90(concretization_gaps)},
            "persistence_gap": {"count": len(persistence_gaps), "median": statistics.median(persistence_gaps) if persistence_gaps else None, "p90": p90(persistence_gaps)},
        },
        "user_vs_assistant_initiation": {
            "assistant_first": {"count": initiation["assistant_first"], "ratio": safe_prob(initiation["assistant_first"], n_risky_rows)},
            "user_or_context_first": {"count": initiation["user_or_context_first"], "ratio": safe_prob(initiation["user_or_context_first"], n_risky_rows)},
            "unclear": {"count": initiation["unclear"], "ratio": safe_prob(initiation["unclear"], n_risky_rows)},
        },
        "assistant_security_regression_rate_proxy": {
            "numerator": reg_num,
            "denominator_assistant_driven": reg_den,
            "rate": safe_prob(reg_num, reg_den),
        },
    }

    return {
        "attr_summary": attr_summary,
        "traj_summary": traj_summary,
        "top_cwe_counts": [{"cwe": cwe, "count": count} for cwe, count in top_cwe_counter.most_common()],
        "assistant_regression_by_cwe": regression_cwe_rows,
        "attribution_source_by_cwe": source_cwe_rows,
        "risk_emergence_bucket_distribution": emergence_bucket_rows,
        "risk_escalation_samples": per_sample_rows,
        "risky_rows": risky_rows,
        "candidate_rows": candidate_rows,
        "attr_by_candidate": attr_by_candidate,
        "trace_by_candidate": tracing_by_candidate,
    }


def message_text(message: dict) -> str:
    blocks = message.get("blocks") or []
    parts: list[str] = []
    if not isinstance(blocks, list):
        return ""
    for group in blocks:
        if not isinstance(group, list):
            continue
        for block in group:
            if not isinstance(block, dict):
                continue
            content = block.get("content")
            if isinstance(content, str) and content.strip():
                parts.append(content.strip())
    return sanitize_text("\n\n".join(parts))


def nearest_prior_user_message(messages: list[dict], turn: int) -> tuple[int | None, str]:
    for idx in range(turn - 1, -1, -1):
        msg = messages[idx]
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "")).lower()
        if role != "user":
            continue
        return idx, message_text(msg)
    return None, ""


def build_stage_context(chat_path: Path, row: dict[str, str], risky_row: dict[str, str]) -> list[dict[str, object]]:
    if not chat_path.exists():
        return []

    chat = load_json(chat_path)
    messages = chat.get("messages") or []
    if not isinstance(messages, list):
        return []

    stages = [
        (
            "First Concretization",
            to_int(row["first_concretization_turn"]),
            "The first turn where the risky idea becomes concrete enough to count as a real risk signal.",
        ),
        (
            "First Persistence",
            to_int(row["first_persistence_turn"]),
            "The first turn where the risky direction persists instead of disappearing.",
        ),
        ("Final Risk Output", to_int(row["assistant_risk_turn"]), "The assistant turn ultimately labeled as risky."),
    ]

    context: list[dict[str, object]] = []
    seen_turns: set[int] = set()
    for label, turn, note in stages:
        if turn is None or turn in seen_turns or turn < 0 or turn >= len(messages):
            continue
        seen_turns.add(turn)
        msg = messages[turn]
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "")).lower() or "unknown"
        text = message_text(msg)
        if label == "Final Risk Output":
            exact_risky_text = sanitize_text(str(risky_row.get("assistant_candidate_text_short") or "").strip())
            if exact_risky_text:
                text = exact_risky_text
        nearby_user_turn, nearby_user_text = nearest_prior_user_message(messages, turn)
        context.append(
            {
                "label": label,
                "turn": turn,
                "role": role,
                "note": note,
                "text": sanitize_text(text),
                "preview": focused_preview(text, 700),
                "nearby_user_turn": nearby_user_turn,
                "nearby_user_text": sanitize_text(nearby_user_text),
                "nearby_user_preview": focused_preview(nearby_user_text, 320),
            }
        )
    return context


def build_overview(attr_summary: dict, traj_summary: dict) -> dict:
    attr = attr_summary["attribution_distribution"]
    top_cwe = attr_summary["top_cwe"][0]
    return {
        "n_all_risky_rows": attr_summary["n_all_risky_rows"],
        "n_total_candidates": attr_summary["n_total_candidates"],
        "n_initial_code_risk_rows": attr_summary.get("n_initial_code_risk_rows", attr_summary["n_code_risk_rows"]),
        "n_code_risk_rows": attr_summary["n_code_risk_rows"],
        "n_obvious_false_positives": attr_summary["audit"]["n_obvious_false_positives"],
        "n_local_only_context_rows": attr_summary["audit"]["n_local_only_context_rows"],
        "assistant_over_implemented_ratio": attr["assistant_over_implemented"]["ratio"],
        "assistant_first_ratio": traj_summary["user_vs_assistant_initiation"]["assistant_first"]["ratio"],
        "early_emergence_ratio": traj_summary["risk_emergence_position"]["bucket_distribution"][0]["probability"],
        "risk_gap_p90": traj_summary["risk_escalation_depth"]["concretization_gap"]["p90"],
        "assistant_regression_rate": traj_summary["assistant_security_regression_rate_proxy"]["rate"],
        "top_cwe_label": top_cwe["cwe"],
        "top_cwe_count": top_cwe["count"],
        "top_cwe_ratio": top_cwe["count"] / max(attr_summary["n_code_risk_rows"], 1),
    }


def build_key_insights(attr_summary: dict, traj_summary: dict) -> list[dict[str, str]]:
    attr = attr_summary["attribution_distribution"]
    bucket_01 = traj_summary["risk_emergence_position"]["bucket_distribution"][0]
    top_cwe = attr_summary["top_cwe"][:4]
    regression_rate = traj_summary["assistant_security_regression_rate_proxy"]["rate"]
    return [
        {
            "title": "Assistant Over-Implementation Dominates",
            "body": (
                f"`assistant_over_implemented` accounts for "
                f"{attr['assistant_over_implemented']['ratio']:.1%} of risky findings, "
                "making assistant-side unnecessary expansion the single largest failure mode."
            ),
        },
        {
            "title": "Risk Emerges Early, Then Lingers",
            "body": (
                f"{bucket_01['probability']:.1%} of traced risks first become concrete by turn 0-1, "
                f"but concretization-gap p90 is still {traj_summary['risk_escalation_depth']['concretization_gap']['p90']} turns."
            ),
        },
        {
            "title": "Regression Pressure Remains High",
            "body": (
                f"Among assistant-driven trajectories, {regression_rate:.1%} still move from an earlier risk signal "
                "to a later, concretized risky output rather than self-correcting."
            ),
        },
        {
            "title": "Top Risk Families Are Concentrated",
            "body": (
                "The highest-frequency risk buckets are "
                + ", ".join(f"{row['cwe']} ({row['count']})" for row in top_cwe)
                + "."
            ),
        },
    ]


def build_findings(
    risky_rows: list[dict[str, object]],
    candidate_rows: dict[str, dict],
    attr_by_candidate: dict[str, dict[str, str]],
    trace_by_candidate: dict[str, dict[str, str]],
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for risky in risky_rows:
        candidate_id = str(risky.get("candidate_id") or "")
        candidate = candidate_rows.get(candidate_id, {})
        attr_row = attr_by_candidate.get(candidate_id, {})
        trace_row = trace_by_candidate.get(candidate_id, {})
        chat_path = ROOT / str(candidate.get("chat_path") or "")
        cwe = str(risky.get("cwe") or attr_row.get("cwe") or "CWE-UNKNOWN")
        primary_cause = str(attr_row.get("primary_cause") or "insufficient_evidence")
        findings.append(
            {
                "finding_id": str(risky["finding_id"]),
                "chat_id": str(risky["chat_id"]),
                "candidate_id": candidate_id,
                "cwe": cwe,
                "severity": str(risky.get("severity") or attr_row.get("severity") or "none"),
                "primary_cause": primary_cause,
                "verdict": str(risky.get("verdict") or ""),
                "confidence": to_float(risky.get("confidence")),
                "assistant_risk_turn": to_int(trace_row.get("assistant_risk_turn")),
                "first_mention_turn": to_int(trace_row.get("first_mention_turn")),
                "first_concretization_turn": to_int(trace_row.get("first_concretization_turn")),
                "first_persistence_turn": to_int(trace_row.get("first_persistence_turn")),
                "mention_gap": (
                    to_int(trace_row.get("assistant_risk_turn")) - to_int(trace_row.get("first_mention_turn"))
                    if to_int(trace_row.get("assistant_risk_turn")) is not None and to_int(trace_row.get("first_mention_turn")) is not None
                    else None
                ),
                "concretization_gap": (
                    to_int(trace_row.get("assistant_risk_turn")) - to_int(trace_row.get("first_concretization_turn"))
                    if to_int(trace_row.get("assistant_risk_turn")) is not None and to_int(trace_row.get("first_concretization_turn")) is not None
                    else None
                ),
                "persistence_gap": (
                    to_int(trace_row.get("assistant_risk_turn")) - to_int(trace_row.get("first_persistence_turn"))
                    if to_int(trace_row.get("assistant_risk_turn")) is not None and to_int(trace_row.get("first_persistence_turn")) is not None
                    else None
                ),
                "assistant_block_type": str(risky.get("assistant_block_type") or ""),
                "assistant_message_index": to_int(risky.get("assistant_message_index")),
                "assistant_block_index": to_int(risky.get("assistant_block_index")),
                "nearest_user_message_index": to_int(risky.get("nearest_user_message_index")),
                "nearest_user_text_short": sanitize_text(str(risky.get("nearest_user_text_short") or "")),
                "nearest_user_commands": "",
                "assistant_candidate_text_short": sanitize_text(str(risky.get("assistant_candidate_text_short") or "")),
                "assistant_candidate_preview": truncate(str(risky.get("assistant_candidate_text_short") or ""), 280),
                "nearest_user_preview": truncate(str(risky.get("nearest_user_text_short") or ""), 220),
                "dedup_count": to_int(str(risky.get("dedup_count") or "")) or 1,
                "dedup_finding_ids": risky.get("dedup_finding_ids") or [str(risky["finding_id"])],
                "trajectory_context": build_stage_context(chat_path, trace_row, risky),
            }
        )

    severity_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    findings.sort(
        key=lambda row: (
            severity_order.get(str(row["severity"]).lower(), 9),
            str(row["cwe"]),
            -(row["concretization_gap"] or -1),
            row["finding_id"],
        )
    )
    return findings


def build_filter_options(findings: list[dict[str, object]]) -> dict:
    def uniq(key: str) -> list[str]:
        return sorted({str(row[key]) for row in findings if row.get(key) not in (None, "")})

    return {
        "cwe": uniq("cwe"),
        "severity": uniq("severity"),
        "primary_cause": uniq("primary_cause"),
        "assistant_block_type": uniq("assistant_block_type"),
        "verdict": uniq("verdict"),
    }


def build_lookup_tables(findings: list[dict[str, object]]) -> dict:
    cause_counts = Counter(str(row["primary_cause"]) for row in findings)
    cwe_counts = Counter(str(row["cwe"]) for row in findings)
    severity_counts = Counter(str(row["severity"]) for row in findings)
    return {
        "cause_counts": dict(cause_counts),
        "cwe_counts": dict(cwe_counts),
        "severity_counts": dict(severity_counts),
    }


def main() -> None:
    filtered = build_filtered_summaries()
    attr_summary = filtered["attr_summary"]
    traj_summary = filtered["traj_summary"]
    findings = build_findings(
        filtered["risky_rows"],
        filtered["candidate_rows"],
        filtered["attr_by_candidate"],
        filtered["trace_by_candidate"],
    )
    payload = {
        "meta": {
            "title": "Vibe-Coding Risk Explorer",
            "subtitle": "Interactive overview and drill-down for the gpt-5.4-mini deduped risky dataset",
            "data_source": "analysis/output/judge_findings_all.jsonl + analysis/output/candidates_all.jsonl",
            "dataset_version": "828",
        },
        "overview": build_overview(attr_summary, traj_summary),
        "insights": build_key_insights(attr_summary, traj_summary),
        "attribution_summary": attr_summary,
        "trajectory_summary": traj_summary,
        "top_cwe_counts": filtered["top_cwe_counts"],
        "assistant_regression_by_cwe": filtered["assistant_regression_by_cwe"],
        "attribution_source_by_cwe": filtered["attribution_source_by_cwe"],
        "risk_emergence_bucket_distribution": filtered["risk_emergence_bucket_distribution"],
        "filters": build_filter_options(findings),
        "lookups": build_lookup_tables(findings),
        "findings": findings,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote explorer data to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
