#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson

from cwe_reference import load_full_catalog_cache, search_full_catalog, split_cwe_values


PATTERN_RULES: list[dict[str, Any]] = [
    {
        "cwes": ["CWE-89", "CWE-943", "CWE-20"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "php", "java", "sql"},
        "patterns": [
            r"\bselect\b.+\+",
            r"\bexecute\([^)]*%",
            r"\bexecute\([^)]*f[\"']",
            r"\bquery\([^)]*\+",
            r"\$\{[^}]+\}.*\b(select|insert|update|delete)\b",
        ],
        "reason": "Query text appears to be constructed with interpolation or concatenation.",
    },
    {
        "cwes": ["CWE-78", "CWE-88"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "bash", "shell", "sh"},
        "patterns": [r"shell\s*=\s*true", r"\bos\.system\(", r"\bsubprocess\.[^(]+\([^)]*\+", r"\beval\s+\"\$\("],
        "reason": "Shell command construction or shell execution may include untrusted data.",
    },
    {
        "cwes": ["CWE-798", "CWE-259", "CWE-321"],
        "languages": None,
        "patterns": [
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}",
            r"sk-[A-Za-z0-9_-]{20,}",
            r"(?i)bearer\s+[A-Za-z0-9._-]{20,}",
        ],
        "reason": "Credential-like value appears directly in generated code or command text.",
    },
    {
        "cwes": ["CWE-502"],
        "languages": {"python", "py", "java", "javascript", "js", "typescript", "ts", "yaml", "yml"},
        "patterns": [r"\bpickle\.loads?\(", r"\byaml\.load\(", r"\bObjectInputStream\b", r"\bunserialize\("],
        "reason": "Unsafe deserialization API appears in the candidate.",
    },
    {
        "cwes": ["CWE-295", "CWE-319"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "go", "java"},
        "patterns": [r"verify\s*=\s*False", r"rejectUnauthorized\s*:\s*false", r"InsecureSkipVerify\s*:\s*true"],
        "reason": "TLS certificate verification or transport protection appears disabled.",
    },
    {
        "cwes": ["CWE-732", "CWE-266"],
        "languages": {"bash", "shell", "sh", "yaml", "yml", "json", "terraform", "hcl"},
        "patterns": [r"chmod\s+777", r'Action"\s*:\s*"\*"', r'Principal"\s*:\s*"\*"', r"\ballUsers\b"],
        "reason": "Permission or access-control configuration appears overly broad.",
    },
    {
        "cwes": ["CWE-79", "CWE-80", "CWE-116"],
        "languages": {"html", "javascript", "js", "typescript", "ts", "jsx", "tsx", "vue", "php"},
        "patterns": [r"dangerouslySetInnerHTML", r"\.innerHTML\s*=", r"\bv-html\b", r"\bdocument\.write\("],
        "reason": "Untrusted content may be inserted into HTML without proper neutralization.",
    },
    {
        "cwes": ["CWE-22", "CWE-73"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "php", "java", "go", "ruby"},
        "patterns": [r"\bopen\([^)]*\+", r"\breadFileSync\([^)]*\+", r"\bsend_file\(", r"\.\./"],
        "reason": "Filesystem path construction may be influenced by external input.",
    },
    {
        "cwes": ["CWE-200", "CWE-532"],
        "languages": None,
        "patterns": [r"console\.log\([^)]*(password|token|secret|key)", r"print\([^)]*(password|token|secret|key)", r"logger\.[^(]+\([^)]*(password|token|secret|key)"],
        "reason": "Sensitive values appear to be logged or exposed.",
    },
]


ABSTRACTION_PREFERENCE = {"Variant": 0, "Base": 1, "Class": 2, "Pillar": 3, "Category": 4, "": 5}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build constrained CWE candidate options for each extracted candidate.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--semgrep-findings", type=Path, default=None)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--catalog-cache", type=Path, default=Path("analysis/output/cwe_catalog_full.json"))
    p.add_argument("--mitre-top-k", type=int, default=5)
    p.add_argument("--max-options", type=int, default=12)
    p.add_argument("--limit", type=int, default=0)
    return p.parse_args()


def load_jsonl(path: Path | None, limit: int = 0) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(orjson.loads(line))
            if limit > 0 and len(rows) >= limit:
                break
    return rows


def normalize_lang(value: Any) -> str:
    return str(value or "").strip().lower().split(":", 1)[0]


def candidate_query(candidate: dict[str, Any]) -> str:
    parts = [
        str(candidate.get("candidate_type") or ""),
        str(candidate.get("language_hint") or ""),
        str(candidate.get("content") or ""),
    ]
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    parts.append(str(metadata.get("preceding_user_text") or ""))
    return "\n".join(parts)


def catalog_by_cwe(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(entry.get("cwe")): entry for entry in catalog.get("entries") or [] if entry.get("cwe")}


def add_option(
    options: dict[str, dict[str, Any]],
    cwe: str,
    *,
    source: str,
    reason: str,
    catalog_entries: dict[str, dict[str, Any]],
    score: float = 0.0,
) -> None:
    if not re.fullmatch(r"CWE-\d+", cwe):
        return
    entry = catalog_entries.get(cwe, {})
    option = options.setdefault(
        cwe,
        {
            "cwe": cwe,
            "name": entry.get("name") or "",
            "title": entry.get("title") or entry.get("name") or cwe,
            "abstraction": entry.get("abstraction") or "",
            "description": entry.get("description") or "",
            "url": entry.get("url") or "",
            "sources": [],
            "reasons": [],
            "score": 0.0,
        },
    )
    if source not in option["sources"]:
        option["sources"].append(source)
    if reason and reason not in option["reasons"]:
        option["reasons"].append(reason)
    option["score"] = round(max(float(option.get("score") or 0.0), score), 4)


def semgrep_by_candidate(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cid = str(row.get("candidate_id") or "")
        if cid:
            out[cid].append(row)
    return out


def add_semgrep_options(
    options: dict[str, dict[str, Any]],
    semgrep_rows: list[dict[str, Any]],
    catalog_entries: dict[str, dict[str, Any]],
) -> None:
    for row in semgrep_rows:
        rule_id = str(row.get("rule_id") or "")
        for cwe in split_cwe_values(row.get("cwe", [])):
            add_option(
                options,
                cwe,
                source="semgrep",
                reason=f"Semgrep finding {rule_id or row.get('finding_id') or ''}".strip(),
                catalog_entries=catalog_entries,
                score=20.0,
            )


def add_pattern_options(
    options: dict[str, dict[str, Any]],
    candidate: dict[str, Any],
    catalog_entries: dict[str, dict[str, Any]],
) -> None:
    lang = normalize_lang(candidate.get("language_hint"))
    content = str(candidate.get("content") or "")
    for rule in PATTERN_RULES:
        languages = rule["languages"]
        if languages is not None and lang not in languages:
            continue
        if any(re.search(pattern, content, flags=re.I | re.S) for pattern in rule["patterns"]):
            for cwe in rule["cwes"]:
                add_option(
                    options,
                    cwe,
                    source="pattern",
                    reason=rule["reason"],
                    catalog_entries=catalog_entries,
                    score=12.0,
                )


def add_mitre_search_options(
    options: dict[str, dict[str, Any]],
    candidate: dict[str, Any],
    catalog: dict[str, Any],
    catalog_entries: dict[str, dict[str, Any]],
    top_k: int,
) -> None:
    if not catalog.get("entries") or top_k <= 0:
        return
    preferred = list(options)
    for result in search_full_catalog(catalog, candidate_query(candidate), top_k=top_k, prefer_cwes=preferred):
        cwe = str(result.get("cwe") or "")
        add_option(
            options,
            cwe,
            source="mitre_search",
            reason="MITRE catalog keyword search matched candidate content/context.",
            catalog_entries=catalog_entries,
            score=float(result.get("score") or 0.0),
        )


def sorted_options(options: dict[str, dict[str, Any]], max_options: int) -> list[dict[str, Any]]:
    rows = list(options.values())
    rows.sort(
        key=lambda row: (
            -float(row.get("score") or 0.0),
            ABSTRACTION_PREFERENCE.get(str(row.get("abstraction") or ""), 5),
            str(row.get("cwe") or ""),
        )
    )
    out: list[dict[str, Any]] = []
    for row in rows[:max_options]:
        fixed = dict(row)
        fixed["sources"] = sorted(fixed.get("sources") or [])
        fixed["reasons"] = list(fixed.get("reasons") or [])[:3]
        out.append(fixed)
    return out


def main() -> None:
    args = parse_args()
    candidates = load_jsonl(args.candidates, args.limit)
    semgrep = semgrep_by_candidate(load_jsonl(args.semgrep_findings))
    catalog = load_full_catalog_cache(args.catalog_cache)
    entries = catalog_by_cwe(catalog)
    counts: Counter[str] = Counter()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("wb") as wf:
        for candidate in candidates:
            cid = str(candidate.get("candidate_id") or "")
            options: dict[str, dict[str, Any]] = {}
            semgrep_rows = semgrep.get(cid, [])
            add_semgrep_options(options, semgrep_rows, entries)
            add_pattern_options(options, candidate, entries)
            add_mitre_search_options(options, candidate, catalog, entries, args.mitre_top_k)
            candidate_options = sorted_options(options, args.max_options)
            if semgrep_rows:
                counts["semgrep_matched_candidates"] += 1
            if candidate_options:
                counts["with_options"] += 1
            else:
                counts["without_options"] += 1
            row = {
                "candidate_id": cid,
                "chat_id": candidate.get("chat_id"),
                "turn_index": candidate.get("turn_index", candidate.get("message_index")),
                "semgrep_matched": bool(semgrep_rows),
                "candidate_cwe_options": candidate_options,
            }
            wf.write(orjson.dumps(row) + b"\n")

    print(f"Candidates seen: {len(candidates)}")
    print(f"With CWE options: {counts['with_options']}")
    print(f"Without CWE options: {counts['without_options']}")
    print(f"Semgrep matched candidates: {counts['semgrep_matched_candidates']}")
    print(f"Catalog cache used: {args.catalog_cache if catalog.get('entries') else 'none'}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
