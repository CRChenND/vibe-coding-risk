#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx
import orjson
from dotenv import load_dotenv
from tqdm import tqdm

from cwe_reference import build_reference_pack, split_cwe_values


DEFAULT_VERIFY_PROMPT = Path("analysis/prompts/cwe_verify_v1.md")
DEFAULT_CATALOG_CACHE = Path("analysis/output/cwe_catalog_full.json")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run LLM-as-a-judge via OpenRouter.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--prompt", type=Path, default=Path("analysis/prompts/judge_v1.md"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--model", type=str, default="openai/gpt-5.4-mini")
    p.add_argument("--limit", type=int, default=0, help="0 means no limit")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=1400)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--sleep", type=float, default=0.0, help="sleep seconds between requests")
    p.add_argument("--verify-prompt", type=Path, default=DEFAULT_VERIFY_PROMPT)
    p.add_argument("--catalog-cache", "--mitre-cache", dest="catalog_cache", type=Path, default=DEFAULT_CATALOG_CACHE)
    p.add_argument("--mitre-max-examples", type=int, default=2)
    p.add_argument("--baseline", type=Path, default=None, help="Optional baseline findings JSONL to attach old_result comparison data.")
    p.add_argument("--cwe-candidates", type=Path, default=None, help="Optional constrained CWE options JSONL from build_cwe_candidates.py.")
    p.add_argument("--workers", type=int, default=1, help="Number of concurrent judge workers.")
    p.add_argument("--verify-cwe", dest="verify_cwe", action="store_true", default=True)
    p.add_argument("--no-verify-cwe", dest="verify_cwe", action="store_false")
    p.add_argument("--resume", dest="resume", action="store_true", default=True, help="Resume from existing output.")
    p.add_argument("--no-resume", dest="resume", action="store_false", help="Do not resume; overwrite output.")
    p.add_argument("--retry-failures", action="store_true", help="When resuming, retry prior fallback/error rows instead of treating them as done.")
    p.add_argument("--judge-all", action="store_true", help="Judge all candidates, including those without risk signals. By default, only candidates with risk signals are judged.")
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clip_text(s: str, n: int = 220) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def maybe_strip_code_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```") and t.endswith("```"):
        lines = t.splitlines()
        if len(lines) >= 2:
            return "\n".join(lines[1:-1]).strip()
    if t.startswith("```json") and t.endswith("```"):
        lines = t.splitlines()
        if len(lines) >= 2:
            return "\n".join(lines[1:-1]).strip()
    return t


def parse_judge_json(text: str) -> dict[str, Any]:
    raw = maybe_strip_code_fence(text)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            return json.loads(raw[start : end + 1])
        raise


def is_failure_row(obj: dict[str, Any]) -> bool:
    details = obj.get("details") if isinstance(obj.get("details"), dict) else {}
    return bool(details.get("error") or details.get("attribution_error"))


def load_done_candidate_ids(out_file: Path, retry_failures: bool = False) -> set[str]:
    done: set[str] = set()
    if not out_file.exists():
        return done
    with out_file.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if retry_failures and is_failure_row(obj):
                continue
            cid = obj.get("candidate_id")
            if isinstance(cid, str) and cid:
                done.add(cid)
    return done


def write_jsonl_row(wf: Any, row: dict[str, Any]) -> None:
    wf.write(orjson.dumps(row) + b"\n")
    wf.flush()


def compact_resume_output(out_file: Path) -> None:
    if not out_file.exists():
        return
    rows_by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    with out_file.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            candidate_id = str(obj.get("candidate_id") or "")
            if not candidate_id or is_failure_row(obj):
                continue
            if candidate_id not in rows_by_id:
                order.append(candidate_id)
            rows_by_id[candidate_id] = obj
    with out_file.open("wb") as wf:
        for candidate_id in order:
            wf.write(orjson.dumps(rows_by_id[candidate_id]) + b"\n")


def load_finding_rows(path: Path | None) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if path is None or not path.exists():
        return rows
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            candidate_id = str(obj.get("candidate_id") or "")
            if candidate_id:
                rows[candidate_id] = obj
    return rows


def build_fallback(candidate_id: str, err: str) -> dict[str, Any]:
    return {
        "finding_id": sha256_text(f"llm_judge:{candidate_id}:{err}")[:24],
        "candidate_id": candidate_id,
        "analyzer": "llm_judge",
        "is_risky": False,
        "is_actionable": False,
        "actionability_reason": "Unavailable due to judge error.",
        "severity": "none",
        "confidence": 0.0,
        "cwe": [],
        "cwe_ids": [],
        "primary_cwe": None,
        "cwe_abstraction": None,
        "cwe_candidates_considered": [],
        "rejected_cwes": [],
        "cwe_confidence": 0.0,
        "cwe_specificity": "unmapped",
        "needs_human_cwe_review": False,
        "evidence": [
            {
                "quote": "",
                "reason": f"judge_error: {clip_text(err, 180)}",
            }
        ],
        "verdict": "not_risky",
        "rule_id": None,
        "details": {"error": err},
    }


def load_cwe_candidate_rows(path: Path | None) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if path is None or not path.exists():
        return rows
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

def has_nonempty_cwe_options(cwe_candidate_row: dict[str, Any] | None) -> bool:
    if not cwe_candidate_row:
        return False
    options = cwe_candidate_row.get("candidate_cwe_options") or cwe_candidate_row.get("cwe_options")
    return isinstance(options, list) and len(options) > 0


def has_risk_signal(candidate: dict[str, Any], cwe_candidate_row: dict[str, Any] | None) -> bool:
    """
    Decide whether this candidate is worth sending to the LLM judge.

    Default policy:
    - If no --cwe-candidates file is provided, do not filter, because we lack signal metadata.
    - If CWE candidate metadata is available, only judge candidates with at least one signal:
      Semgrep match, pattern match, risk tags, or non-empty CWE options.
    """
    if cwe_candidate_row is None:
        return True

    if bool(cwe_candidate_row.get("semgrep_matched")):
        return True

    if bool(cwe_candidate_row.get("pattern_matched")):
        return True

    risk_tags = cwe_candidate_row.get("risk_tags")
    if isinstance(risk_tags, list) and len(risk_tags) > 0:
        return True

    if has_nonempty_cwe_options(cwe_candidate_row):
        return True

    return False


def cwe_options_for_prompt(row: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not row:
        return []
    options = row.get("candidate_cwe_options") or row.get("cwe_options")
    if not isinstance(options, list):
        return []
    out: list[dict[str, Any]] = []
    for option in options:
        if not isinstance(option, dict):
            continue
        cwe = str(option.get("cwe") or "")
        if not cwe:
            continue
        out.append(
            {
                "cwe": cwe,
                "cwe_id": option.get("cwe_id") or cwe,
                "title": option.get("title") or option.get("name") or cwe,
                "abstraction": option.get("abstraction") or "",
                "description": clip_text(str(option.get("description") or ""), 400),
                "sources": option.get("sources") or option.get("source") or [],
                "matched_terms": option.get("matched_terms") or [],
                "reasons": option.get("reasons") or [],
            }
        )
    return out


def allowed_cwes(cwe_candidate_row: dict[str, Any] | None) -> set[str]:
    return {
        str(option.get("cwe"))
        for option in cwe_options_for_prompt(cwe_candidate_row)
        if option.get("cwe")
    }


def candidate_abstraction(cwe: str | None, cwe_candidate_row: dict[str, Any] | None) -> str | None:
    if not cwe:
        return None
    for option in cwe_options_for_prompt(cwe_candidate_row):
        if option.get("cwe") == cwe:
            abstraction = str(option.get("abstraction") or "")
            return abstraction or None
    return None


def constrained_cwes(parsed: dict[str, Any], cwe_candidate_row: dict[str, Any] | None) -> tuple[list[str], bool]:
    raw_values: list[Any] = []
    primary = parsed.get("primary_cwe")
    if isinstance(primary, str):
        raw_values.append(primary)
    raw_values.extend(split_cwe_values(parsed.get("cwe_ids", [])))
    raw_values.extend(split_cwe_values(parsed.get("cwe", [])))
    proposed = split_cwe_values(raw_values)
    if cwe_candidate_row is None:
        return proposed, False
    allowed = allowed_cwes(cwe_candidate_row)
    if not allowed:
        return [], bool(proposed)
    filtered = [cwe for cwe in proposed if cwe in allowed]
    return filtered, bool(set(proposed) - allowed)


def normalize_rejected_cwes(raw: Any, cwe_candidate_row: dict[str, Any] | None) -> list[dict[str, str]]:
    allowed = allowed_cwes(cwe_candidate_row)
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        cwe_values = split_cwe_values(item.get("cwe"))
        if not cwe_values:
            continue
        cwe = cwe_values[0]
        if allowed and cwe not in allowed:
            continue
        out.append({"cwe": cwe, "reason": clip_text(str(item.get("reason") or ""), 300)})
    return out


def normalize_finding(
    candidate_id: str,
    parsed: dict[str, Any],
    model: str,
    cwe_candidate_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    severity = str(parsed.get("severity", "none")).lower()
    if severity not in {"none", "low", "medium", "high", "critical"}:
        severity = "none"

    verdict = str(parsed.get("verdict", "possible")).lower()
    if verdict not in {"possible", "likely", "confirmed", "not_risky"}:
        verdict = "possible"

    confidence = parsed.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    cwe, rejected_out_of_set = constrained_cwes(parsed, cwe_candidate_row)
    primary_cwe = cwe[0] if cwe else None
    primary_cwe_abstraction = candidate_abstraction(primary_cwe, cwe_candidate_row)

    cwe_confidence = parsed.get("cwe_confidence", parsed.get("confidence", 0.0))
    try:
        cwe_confidence = float(cwe_confidence)
    except (TypeError, ValueError):
        cwe_confidence = 0.0
    cwe_confidence = max(0.0, min(1.0, cwe_confidence))

    # Normalize CWE specificity from the selected CWE abstraction instead of
    # trusting the model's free-form specificity judgment.
    if primary_cwe is None:
        cwe_specificity = "unmapped"
    elif len(cwe) > 1:
        cwe_specificity = "ambiguous"
    elif primary_cwe_abstraction in {"Class", "Pillar", "Category"}:
        cwe_specificity = "broad"
    elif primary_cwe_abstraction in {"Base", "Variant"}:
        cwe_specificity = "specific"
    else:
        # If abstraction is unavailable, fall back to the model output but keep
        # it within the allowed vocabulary.
        cwe_specificity = str(parsed.get("cwe_specificity") or "ambiguous").lower()
        if cwe_specificity not in {"specific", "broad", "ambiguous", "unmapped"}:
            cwe_specificity = "ambiguous"

    evidence = parsed.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []

    fixed_evidence: list[dict[str, str]] = []
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        quote = str(ev.get("quote", "")).strip()
        reason = str(ev.get("reason", "")).strip()
        if quote or reason:
            fixed_evidence.append(
                {
                    "quote": clip_text(quote, 240),
                    "reason": clip_text(reason, 300),
                }
            )

    if not fixed_evidence:
        fixed_evidence = [{"quote": "", "reason": "No evidence provided by judge."}]

    is_risky = bool(parsed.get("is_risky", False))
    is_actionable = bool(parsed.get("is_actionable", False))
    actionability_reason = str(parsed.get("actionability_reason", "")).strip()
    reasoning = str(parsed.get("reasoning", "")).strip()

    # Keep top-level risk fields internally consistent even if the model emits
    # contradictory combinations such as is_risky=true with verdict=not_risky.
    if not is_actionable:
        is_risky = False

    if verdict == "not_risky" or severity == "none":
        is_risky = False

    if not is_risky:
        severity = "none"
        verdict = "not_risky"
        cwe = []
        primary_cwe = None
        primary_cwe_abstraction = None
        cwe_confidence = 0.0
        cwe_specificity = "unmapped"

    # If the candidate is risky but no in-set CWE survives the constraint,
    # mark it as unmapped and request human review.
    if is_risky and not cwe:
        primary_cwe = None
        primary_cwe_abstraction = None
        cwe_confidence = 0.0
        cwe_specificity = "unmapped"

    needs_human_cwe_review = bool(parsed.get("needs_human_cwe_review", False))
    if rejected_out_of_set or (is_risky and not cwe):
        needs_human_cwe_review = True

    return {
        "finding_id": sha256_text(f"llm_judge:{candidate_id}:{model}")[:24],
        "candidate_id": candidate_id,
        "analyzer": "llm_judge",
        "is_risky": is_risky,
        "is_actionable": is_actionable,
        "actionability_reason": clip_text(actionability_reason, 300),
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "cwe_ids": cwe,
        "primary_cwe": primary_cwe,
        "cwe_abstraction": primary_cwe_abstraction,
        "cwe_candidates_considered": sorted(allowed_cwes(cwe_candidate_row)),
        "rejected_cwes": normalize_rejected_cwes(parsed.get("rejected_cwes", []), cwe_candidate_row),
        "cwe_confidence": cwe_confidence,
        "cwe_specificity": cwe_specificity,
        "needs_human_cwe_review": needs_human_cwe_review,
        "evidence": fixed_evidence,
        "verdict": verdict,
        "rule_id": None,
        "details": {
            "model": model,
            "reasoning": reasoning,
            "cwe_candidate_options": cwe_options_for_prompt(cwe_candidate_row),
            "cwe_constraint": {
                "enabled": cwe_candidate_row is not None,
                "rejected_out_of_set": rejected_out_of_set,
                "semgrep_matched": bool((cwe_candidate_row or {}).get("semgrep_matched")),
            },
        },
    }

def summarize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    details = finding.get("details") or {}
    return {
        "finding_id": finding.get("finding_id"),
        "candidate_id": finding.get("candidate_id"),
        "analyzer": finding.get("analyzer"),
        "is_risky": finding.get("is_risky"),
        "is_actionable": finding.get("is_actionable"),
        "actionability_reason": finding.get("actionability_reason"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "cwe": finding.get("cwe", []),
        "primary_cwe": finding.get("primary_cwe"),
        "cwe_abstraction": finding.get("cwe_abstraction"),
        "cwe_confidence": finding.get("cwe_confidence"),
        "cwe_specificity": finding.get("cwe_specificity"),
        "needs_human_cwe_review": finding.get("needs_human_cwe_review"),
        "verdict": finding.get("verdict"),
        "reasoning": details.get("reasoning", ""),
    }


def candidate_query_text(candidate: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("content", "candidate_type", "language_hint"):
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    metadata = candidate.get("metadata")
    if isinstance(metadata, dict):
        for key in ("preceding_user_text", "block_type"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value)
    repo_context = candidate.get("repo_context")
    if isinstance(repo_context, dict):
        value = repo_context.get("search_match_path")
        if isinstance(value, str) and value.strip():
            parts.append(value)
    return "\n".join(parts)


def build_verification_prompt(
    template: str,
    candidate_json: str,
    draft_finding: dict[str, Any],
    cwe_reference_pack: dict[str, dict[str, Any]],
    cwe_candidate_options: list[dict[str, Any]],
) -> str:
    return (
        template.replace("{{candidate_record_json}}", candidate_json)
        .replace("{{draft_finding_json}}", json.dumps(summarize_finding(draft_finding), ensure_ascii=False, indent=2))
        .replace("{{mitre_reference_pack_json}}", json.dumps(cwe_reference_pack, ensure_ascii=False, indent=2))
        .replace("{{candidate_cwe_options_json}}", json.dumps(cwe_candidate_options, ensure_ascii=False, indent=2))
    )


def judge_candidate(
    candidate: dict[str, Any],
    *,
    api_key: str,
    base_url: str,
    model: str,
    template: str,
    verify_template: str,
    verify_prompt_path: Path,
    temperature: float,
    max_tokens: int,
    retries: int,
    verify_cwe: bool,
    catalog_cache: Path,
    mitre_max_examples: int,
    baseline_rows: dict[str, dict[str, Any]],
    cwe_candidate_rows: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    candidate_id = str(candidate.get("candidate_id", "unknown"))
    cwe_candidate_row = cwe_candidate_rows.get(candidate_id)
    candidate_json = orjson.dumps(candidate, option=orjson.OPT_INDENT_2).decode("utf-8")
    query_text = candidate_query_text(candidate)
    cwe_options = cwe_options_for_prompt(cwe_candidate_row)
    prompt_text = (
        template.replace("{{candidate_record_json}}", candidate_json)
        .replace("{{candidate_cwe_options_json}}", json.dumps(cwe_options, ensure_ascii=False, indent=2))
    )
    last_err: Exception | None = None

    with httpx.Client(base_url=base_url, timeout=120.0) as client:
        for attempt in range(1, retries + 1):
            try:
                text = call_openrouter(
                    client=client,
                    api_key=api_key,
                    model=model,
                    prompt_text=prompt_text,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                parsed = parse_judge_json(text)
                draft_finding = normalize_finding(candidate_id, parsed, model, cwe_candidate_row)

                verification_payload: dict[str, Any] | None = None
                final_parsed = parsed
                if verify_cwe and draft_finding["verdict"] != "not_risky":
                    draft_cwes = draft_finding["cwe"]
                    reference_pack = build_reference_pack(
                        draft_cwes,
                        catalog_cache_path=catalog_cache,
                        max_examples=max(1, mitre_max_examples),
                        query_text=query_text + "\n" + str(draft_finding.get("details", {}).get("reasoning", "")),
                        top_k=8,
                    ) if draft_cwes else {}
                    verify_prompt = build_verification_prompt(
                        verify_template,
                        candidate_json,
                        draft_finding,
                        reference_pack,
                        cwe_options,
                    )
                    verify_text = call_openrouter(
                        client=client,
                        api_key=api_key,
                        model=model,
                        prompt_text=verify_prompt,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                    verified = parse_judge_json(verify_text)
                    final_parsed = verified
                    verification_payload = {
                        "mode": "mitre_cwe_verify",
                        "draft": summarize_finding(draft_finding),
                        "reference_pack": reference_pack,
                        "verify_prompt": str(verify_prompt_path),
                        "revised": split_cwe_values(verified.get("cwe", [])) != draft_finding["cwe"],
                    }

                finding = normalize_finding(candidate_id, final_parsed, model, cwe_candidate_row)
                if verification_payload is not None:
                    finding["details"]["verification"] = verification_payload
                    finding["details"]["draft"] = summarize_finding(draft_finding)
                comparison: dict[str, Any] = {
                    "new_result": summarize_finding(finding),
                    "is_actionable": finding["is_actionable"],
                }
                baseline_row = baseline_rows.get(candidate_id)
                if baseline_row:
                    comparison["old_result"] = summarize_finding(baseline_row)
                finding["details"]["comparison"] = comparison
                return finding, True
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if attempt < retries:
                    time.sleep(min(1.5 * attempt, 5.0))

    fallback = build_fallback(candidate_id, str(last_err))
    fallback["details"]["model"] = model
    return fallback, False


def call_openrouter(
    client: httpx.Client,
    api_key: str,
    model: str,
    prompt_text: str,
    temperature: float,
    max_tokens: int,
) -> str:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    referer = os.getenv("OPENROUTER_HTTP_REFERER")
    title = os.getenv("OPENROUTER_APP_TITLE")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title

    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt_text}],
    }

    resp = client.post("/chat/completions", headers=headers, json=payload)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("OpenRouter returned no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: list[str] = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                txt = c.get("text")
                if isinstance(txt, str):
                    parts.append(txt)
        if parts:
            return "\n".join(parts)

    raise ValueError("OpenRouter response has no text content")


def main() -> None:
    args = parse_args()
    load_dotenv()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("Missing OPENROUTER_API_KEY in environment/.env")

    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    template = args.prompt.read_text(encoding="utf-8")
    verify_template = args.verify_prompt.read_text(encoding="utf-8") if args.verify_cwe else ""

    raw_lines = args.candidates.read_bytes().splitlines()
    if args.limit and args.limit > 0:
        raw_lines = raw_lines[: args.limit]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.resume and args.retry_failures:
        compact_resume_output(args.out)
    done_ids = load_done_candidate_ids(args.out, retry_failures=args.retry_failures) if args.resume else set()
    baseline_rows = load_finding_rows(args.baseline)
    cwe_candidate_rows = load_cwe_candidate_rows(args.cwe_candidates)

    count_ok = 0
    count_err = 0
    count_skip = 0
    count_skip_no_signal = 0

    mode = "ab" if args.resume else "wb"

    pending_candidates: list[dict[str, Any]] = []
    for line in raw_lines:
        if not line.strip():
            continue

        candidate = orjson.loads(line)
        candidate_id = str(candidate.get("candidate_id", "unknown"))

        if candidate_id in done_ids:
            count_skip += 1
            continue

        cwe_candidate_row = cwe_candidate_rows.get(candidate_id)

        if not args.judge_all and not has_risk_signal(candidate, cwe_candidate_row):
            count_skip_no_signal += 1
            continue

        pending_candidates.append(candidate)

    with args.out.open(mode) as wf:
        if max(1, args.workers) == 1:
            for candidate in tqdm(pending_candidates, desc="llm-judge"):
                finding, ok = judge_candidate(
                    candidate,
                    api_key=api_key,
                    base_url=base_url,
                    model=args.model,
                    template=template,
                    verify_template=verify_template,
                    verify_prompt_path=args.verify_prompt,
                    temperature=args.temperature,
                    max_tokens=args.max_tokens,
                    retries=args.retries,
                    verify_cwe=args.verify_cwe,
                    catalog_cache=args.catalog_cache,
                    mitre_max_examples=args.mitre_max_examples,
                    baseline_rows=baseline_rows,
                    cwe_candidate_rows=cwe_candidate_rows,
                )
                write_jsonl_row(wf, finding)
                done_ids.add(str(candidate.get("candidate_id", "unknown")))
                if ok:
                    count_ok += 1
                else:
                    count_err += 1
                if args.sleep > 0:
                    time.sleep(args.sleep)
        else:
            with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
                futures = {
                    executor.submit(
                        judge_candidate,
                        candidate,
                        api_key=api_key,
                        base_url=base_url,
                        model=args.model,
                        template=template,
                        verify_template=verify_template,
                        verify_prompt_path=args.verify_prompt,
                        temperature=args.temperature,
                        max_tokens=args.max_tokens,
                        retries=args.retries,
                        verify_cwe=args.verify_cwe,
                        catalog_cache=args.catalog_cache,
                        mitre_max_examples=args.mitre_max_examples,
                        baseline_rows=baseline_rows,
                        cwe_candidate_rows=cwe_candidate_rows,
                    ): str(candidate.get("candidate_id", "unknown"))
                    for candidate in pending_candidates
                }
                for future in tqdm(as_completed(futures), total=len(futures), desc="llm-judge"):
                    candidate_id = futures[future]
                    finding, ok = future.result()
                    write_jsonl_row(wf, finding)
                    done_ids.add(candidate_id)
                    if ok:
                        count_ok += 1
                    else:
                        count_err += 1
                    if args.sleep > 0:
                        time.sleep(args.sleep)

    print(f"Candidates seen: {len(raw_lines)}")
    print(f"Candidates skipped(resume): {count_skip}")
    print(f"Candidates skipped(no risk signal): {count_skip_no_signal}")
    print(f"Candidates pending for judge: {len(pending_candidates)}")
    print(f"Judge success: {count_ok}")
    print(f"Judge fallback(errors): {count_err}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
