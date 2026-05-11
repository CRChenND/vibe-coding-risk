#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm


LANG_EXT = {
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "css": ".css",
    "dart": ".dart",
    "dockerfile": ".Dockerfile",
    "go": ".go",
    "html": ".html",
    "java": ".java",
    "javascript": ".js",
    "js": ".js",
    "json": ".json",
    "jsonc": ".json",
    "jsx": ".jsx",
    "kotlin": ".kt",
    "php": ".php",
    "python": ".py",
    "py": ".py",
    "ruby": ".rb",
    "rust": ".rs",
    "shell": ".sh",
    "bash": ".sh",
    "sh": ".sh",
    "sql": ".sql",
    "swift": ".swift",
    "ts": ".ts",
    "tsx": ".tsx",
    "typescript": ".ts",
    "vue": ".vue",
    "xml": ".xml",
    "yaml": ".yaml",
    "yml": ".yaml",
}

SKIP_LANGS = {"diff", "markdown", "md", "plaintext", None}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Semgrep directly on extracted code_snippet candidates.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--summary-out", type=Path, default=None)
    p.add_argument("--semgrep-config", type=str, default="auto")
    p.add_argument("--limit", type=int, default=0, help="Limit input candidate lines before filtering.")
    p.add_argument("--timeout-sec", type=int, default=120)
    p.add_argument("--batch-size", type=int, default=1000, help="Unique snippets per Semgrep invocation.")
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clip(s: str, n: int = 240) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def has_cmd(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True, text=True).returncode == 0


def severity_to_schema(sev: str | None) -> str:
    x = (sev or "").lower()
    if x in {"critical"}:
        return "critical"
    if x in {"error", "high"}:
        return "high"
    if x in {"warning", "medium"}:
        return "medium"
    if x in {"info", "low"}:
        return "low"
    return "medium"


def extract_cwe(obj: Any) -> list[str]:
    out: set[str] = set()
    if isinstance(obj, str):
        out.update(re.findall(r"CWE-\d+", obj))
    elif isinstance(obj, list):
        for item in obj:
            out.update(extract_cwe(item))
    elif isinstance(obj, dict):
        for value in obj.values():
            out.update(extract_cwe(value))
    return sorted(out)


def lang_ext(language_hint: str | None) -> str | None:
    lang = (language_hint or "").lower().split(":", 1)[0] or None
    if lang in SKIP_LANGS:
        return None
    return LANG_EXT.get(lang)


def load_candidates(path: Path, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for i, line in enumerate(f):
            if limit > 0 and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            rows.append(orjson.loads(line))
    return rows


def parse_semgrep(stdout: str) -> list[dict[str, Any]]:
    data = json.loads(stdout)
    findings: list[dict[str, Any]] = []
    for result in data.get("results", []) or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        findings.append(
            {
                "rule_id": str(result.get("check_id") or "SEMGREP"),
                "severity": severity_to_schema(extra.get("severity")),
                "confidence": 0.8,
                "cwe": extract_cwe(metadata.get("cwe") or metadata),
                "quote": clip(str(extra.get("message") or result.get("check_id") or "Semgrep finding")),
                "reason": clip(f"Semgrep finding in {result.get('path') or 'candidate snippet'}", 300),
                "path": str(result.get("path") or ""),
                "raw": result,
            }
        )
    return findings


def run_semgrep_path(path: Path, config: str, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet", str(path)]
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        if stdout.strip().startswith("{"):
            try:
                return parse_semgrep(stdout), None
            except Exception:
                pass
        return [], f"semgrep_failed:{clip((exc.stderr or exc.stdout or '').strip())}"
    except subprocess.TimeoutExpired:
        return [], "semgrep_timeout"

    try:
        return parse_semgrep(proc.stdout), None
    except Exception as exc:  # noqa: BLE001
        return [], f"semgrep_json_failed:{exc}"


def run_semgrep(content: str, ext: str, config: str, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    with tempfile.TemporaryDirectory(prefix="vibe-semgrep-candidate-") as td:
        suffix = ".Dockerfile" if ext == ".Dockerfile" else ext
        path = Path(td) / f"snippet{suffix}"
        path.write_text(content, encoding="utf-8")
        return run_semgrep_path(path, config, timeout_sec)


def iter_batches(items: list[tuple[tuple[str, str], list[dict[str, Any]]]], batch_size: int):
    size = max(1, batch_size)
    for start in range(0, len(items), size):
        yield items[start : start + size]


def run_semgrep_batch(
    items: list[tuple[tuple[str, str], list[dict[str, Any]]]],
    config: str,
    timeout_sec: int,
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], str | None]:
    findings_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    with tempfile.TemporaryDirectory(prefix="vibe-semgrep-candidate-batch-") as td:
        root = Path(td)
        path_to_key: dict[str, tuple[str, str]] = {}
        for idx, (key, grouped_candidates) in enumerate(items):
            _, ext = key
            suffix = ".Dockerfile" if ext == ".Dockerfile" else ext
            path = root / f"snippet_{idx:06d}{suffix}"
            path.write_text(str(grouped_candidates[0].get("content") or ""), encoding="utf-8")
            path_to_key[path.name] = key

        findings, err = run_semgrep_path(root, config, timeout_sec)
        if err:
            return findings_by_key, err

        for finding in findings:
            key = path_to_key.get(Path(finding.get("path") or "").name)
            if key is not None:
                findings_by_key[key].append(finding)
    return findings_by_key, None


def finding_location(item: dict[str, Any]) -> str:
    raw = item.get("raw") or {}
    start = raw.get("start") or {}
    end = raw.get("end") or {}
    return ":".join(
        str(part)
        for part in (
            Path(item.get("path") or "").name,
            start.get("line"),
            start.get("col"),
            end.get("line"),
            end.get("col"),
        )
        if part not in {None, ""}
    )


def finding_id_for_item(candidate_id: str, item: dict[str, Any]) -> str:
    return "semgrep-candidate:" + sha256_text(
        f"{candidate_id}\n{item['rule_id']}\n{item['quote']}\n{finding_location(item)}"
    )[:24]


def build_finding(candidate: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidate_id") or "")
    return {
        "finding_id": finding_id_for_item(candidate_id, item),
        "candidate_id": candidate_id,
        "analyzer": "static_rule",
        "is_risky": True,
        "is_actionable": True,
        "actionability_reason": "Semgrep matched this extracted code snippet.",
        "severity": item["severity"],
        "confidence": item["confidence"],
        "cwe": item["cwe"],
        "evidence": [{"quote": item["quote"], "reason": item["reason"]}],
        "verdict": "possible",
        "rule_id": f"semgrep:{item['rule_id']}",
        "details": {
            "engine": "semgrep",
            "candidate_type": candidate.get("candidate_type"),
            "language_hint": candidate.get("language_hint"),
            "content_hash": candidate.get("content_hash"),
            "semgrep_location": finding_location(item),
        },
    }


def main() -> None:
    args = parse_args()
    if not has_cmd("semgrep"):
        raise SystemExit("semgrep command not found. Install Semgrep before running this script.")

    candidates = load_candidates(args.candidates, args.limit)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    counts = Counter()

    for candidate in candidates:
        counts["candidates_seen"] += 1
        if candidate.get("candidate_type") != "code_snippet":
            counts["skipped_non_code_snippet"] += 1
            continue
        content = str(candidate.get("content") or "").strip()
        ext = lang_ext(candidate.get("language_hint"))
        if not content or ext is None:
            counts["skipped_unsupported_language"] += 1
            continue
        content_hash = str(candidate.get("content_hash") or sha256_text(content))
        groups[(content_hash, ext)].append(candidate)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    summary_path = args.summary_out
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)

    group_items = list(groups.items())
    with args.out.open("wb") as wf:
        for batch in tqdm(list(iter_batches(group_items, args.batch_size)), desc="semgrep-candidate-batches"):
            findings_by_key, err = run_semgrep_batch(batch, args.semgrep_config, args.timeout_sec)
            if err:
                counts[err.split(":", 1)[0]] += 1
                continue
            for key, grouped_candidates in batch:
                findings = findings_by_key.get(key, [])
                if not findings:
                    counts["semgrep_clean"] += len(grouped_candidates)
                    continue
                counts["semgrep_matched"] += len(grouped_candidates)
                for candidate in grouped_candidates:
                    for item in findings:
                        wf.write(orjson.dumps(build_finding(candidate, item)) + b"\n")

    summary = {
        "candidates_seen": counts["candidates_seen"],
        "unique_snippets_scanned": len(groups),
        "batch_size": args.batch_size,
        "skipped_non_code_snippet": counts["skipped_non_code_snippet"],
        "skipped_unsupported_language": counts["skipped_unsupported_language"],
        "semgrep_matched_candidates": counts["semgrep_matched"],
        "semgrep_clean_candidates": counts["semgrep_clean"],
        "errors": {k: v for k, v in counts.items() if k.startswith("semgrep_") and k not in {"semgrep_matched", "semgrep_clean"}},
        "out": str(args.out),
    }
    if summary_path is not None:
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
