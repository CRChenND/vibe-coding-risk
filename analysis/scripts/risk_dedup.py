from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_candidate_repo_paths(candidates_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not candidates_path.exists():
        return out
    with candidates_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            candidate_id = str(obj.get("candidate_id") or "")
            repo_context = obj.get("repo_context") or {}
            search_match_path = str(repo_context.get("search_match_path") or "").strip()
            if candidate_id:
                out[candidate_id] = search_match_path
    return out


def _to_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _split_cwes(value: Any) -> list[str]:
    raw = str(value or "")
    return [part.strip() for part in raw.replace("|", ",").split(",") if part.strip()]


def _join_cwes(values: list[str]) -> str:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ",".join(ordered)


def _candidate_type(candidate_id: str) -> str:
    return candidate_id.rsplit(":", 1)[-1] if ":" in candidate_id else "unknown"


def _candidate_rank(candidate_id: str) -> int:
    ctype = _candidate_type(candidate_id)
    if ctype == "code_snippet":
        return 3
    if ctype == "command":
        return 2
    if ctype == "security_advice":
        return 1
    return 0


def _severity_rank(value: Any) -> int:
    severity = str(value or "").lower()
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}
    return order.get(severity, 0)


def _dedup_scope(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("chat_id") or ""), str(row.get("_repo_path") or ""))


def _same_text(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ta = str(a.get("_norm_text") or "")
    tb = str(b.get("_norm_text") or "")
    if not ta or not tb:
        return False
    return ta == tb or ta in tb or tb in ta


def _cwe_overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return bool(set(a.get("_cwes") or []) & set(b.get("_cwes") or []))


def _is_near_duplicate(a: dict[str, Any], b: dict[str, Any]) -> bool:
    scope_a = _dedup_scope(a)
    scope_b = _dedup_scope(b)
    if scope_a != scope_b:
        return False
    if not scope_a[1]:
        return False

    msg_a = _to_int(a.get("assistant_message_index"))
    msg_b = _to_int(b.get("assistant_message_index"))
    blk_a = _to_int(a.get("assistant_block_index"))
    blk_b = _to_int(b.get("assistant_block_index"))

    msg_gap = None if msg_a is None or msg_b is None else abs(msg_a - msg_b)
    blk_gap = None if blk_a is None or blk_b is None else abs(blk_a - blk_b)

    same_text = _same_text(a, b)
    cwe_overlap = _cwe_overlap(a, b)
    same_block = msg_gap == 0 and blk_gap == 0
    same_message_near_block = msg_gap == 0 and blk_gap is not None and blk_gap <= 6
    nearby_message = msg_gap is not None and msg_gap <= 2

    if same_block:
        return True
    if same_message_near_block and (same_text or cwe_overlap):
        return True
    if nearby_message and same_text:
        return True
    return False


def _representative_score(row: dict[str, Any]) -> tuple[int, int, float, int]:
    return (
        _candidate_rank(str(row.get("candidate_id") or "")),
        _severity_rank(row.get("severity")),
        _to_float(row.get("confidence")),
        len(str(row.get("assistant_candidate_text_short") or row.get("risk_snippets_content") or "")),
    )


def dedup_risky_rows(rows: list[dict[str, Any]], candidate_repo_paths: dict[str, str]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for row in rows:
        new_row = dict(row)
        new_row["_repo_path"] = candidate_repo_paths.get(str(row.get("candidate_id") or ""), "")
        new_row["_norm_text"] = _normalize_text(
            row.get("assistant_candidate_text_short") or row.get("risk_snippets_content") or ""
        )
        new_row["_cwes"] = _split_cwes(row.get("cwe"))
        prepared.append(new_row)

    prepared.sort(
        key=lambda row: (
            str(row.get("chat_id") or ""),
            str(row.get("_repo_path") or ""),
            _to_int(row.get("assistant_message_index")) if _to_int(row.get("assistant_message_index")) is not None else 10**9,
            _to_int(row.get("assistant_block_index")) if _to_int(row.get("assistant_block_index")) is not None else 10**9,
            str(row.get("candidate_id") or ""),
        )
    )

    clusters: list[list[dict[str, Any]]] = []
    for row in prepared:
        placed = False
        for cluster in clusters[::-1][:8]:
            if _is_near_duplicate(cluster[-1], row):
                cluster.append(row)
                placed = True
                break
        if not placed:
            clusters.append([row])

    deduped: list[dict[str, Any]] = []
    for cluster in clusters:
        representative = max(cluster, key=_representative_score)
        merged = dict(representative)
        merged["cwe"] = _join_cwes([cwe for row in cluster for cwe in row.get("_cwes") or []])
        merged["dedup_count"] = len(cluster)
        merged["dedup_finding_ids"] = [str(row.get("finding_id") or "") for row in cluster]
        deduped.append(merged)

    for row in deduped:
        row.pop("_repo_path", None)
        row.pop("_norm_text", None)
        row.pop("_cwes", None)
    return deduped
