#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
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
    p.add_argument("--max-tokens", type=int, default=900)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--sleep", type=float, default=0.0, help="sleep seconds between requests")
    p.add_argument("--verify-prompt", type=Path, default=DEFAULT_VERIFY_PROMPT)
    p.add_argument("--catalog-cache", "--mitre-cache", dest="catalog_cache", type=Path, default=DEFAULT_CATALOG_CACHE)
    p.add_argument("--mitre-max-examples", type=int, default=2)
    p.add_argument("--verify-cwe", dest="verify_cwe", action="store_true", default=True)
    p.add_argument("--no-verify-cwe", dest="verify_cwe", action="store_false")
    p.add_argument("--resume", dest="resume", action="store_true", default=True, help="Resume from existing output.")
    p.add_argument("--no-resume", dest="resume", action="store_false", help="Do not resume; overwrite output.")
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


def load_done_candidate_ids(out_file: Path) -> set[str]:
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
            cid = obj.get("candidate_id")
            if isinstance(cid, str) and cid:
                done.add(cid)
    return done


def build_fallback(candidate_id: str, err: str) -> dict[str, Any]:
    return {
        "finding_id": sha256_text(f"llm_judge:{candidate_id}:{err}")[:24],
        "candidate_id": candidate_id,
        "analyzer": "llm_judge",
        "is_risky": False,
        "severity": "none",
        "confidence": 0.0,
        "cwe": [],
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


def normalize_finding(candidate_id: str, parsed: dict[str, Any], model: str) -> dict[str, Any]:
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

    cwe = split_cwe_values(parsed.get("cwe", []))

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
            fixed_evidence.append({"quote": clip_text(quote, 240), "reason": clip_text(reason, 300)})

    if not fixed_evidence:
        fixed_evidence = [{"quote": "", "reason": "No evidence provided by judge."}]

    is_risky = bool(parsed.get("is_risky", False))
    reasoning = str(parsed.get("reasoning", "")).strip()

    return {
        "finding_id": sha256_text(f"llm_judge:{candidate_id}:{model}")[:24],
        "candidate_id": candidate_id,
        "analyzer": "llm_judge",
        "is_risky": is_risky,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "evidence": fixed_evidence,
        "verdict": verdict,
        "rule_id": None,
        "details": {
            "model": model,
            "reasoning": reasoning,
        },
    }


def summarize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    details = finding.get("details") or {}
    return {
        "finding_id": finding.get("finding_id"),
        "candidate_id": finding.get("candidate_id"),
        "analyzer": finding.get("analyzer"),
        "is_risky": finding.get("is_risky"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "cwe": finding.get("cwe", []),
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
) -> str:
    return (
        template.replace("{{candidate_record_json}}", candidate_json)
        .replace("{{draft_finding_json}}", json.dumps(summarize_finding(draft_finding), ensure_ascii=False, indent=2))
        .replace("{{mitre_reference_pack_json}}", json.dumps(cwe_reference_pack, ensure_ascii=False, indent=2))
    )


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
    done_ids = load_done_candidate_ids(args.out) if args.resume else set()

    count_ok = 0
    count_err = 0
    count_skip = 0

    mode = "ab" if args.resume else "wb"

    with httpx.Client(base_url=base_url, timeout=120.0) as client:
        with args.out.open(mode) as wf:
            for line in tqdm(raw_lines, desc="llm-judge"):
                if not line.strip():
                    continue
                candidate = orjson.loads(line)
                candidate_id = str(candidate.get("candidate_id", "unknown"))
                if candidate_id in done_ids:
                    count_skip += 1
                    continue
                candidate_json = orjson.dumps(candidate, option=orjson.OPT_INDENT_2).decode("utf-8")
                query_text = candidate_query_text(candidate)
                prompt_text = template.replace("{{candidate_record_json}}", candidate_json)

                last_err: Exception | None = None
                for attempt in range(1, args.retries + 1):
                    try:
                        text = call_openrouter(
                            client=client,
                            api_key=api_key,
                            model=args.model,
                            prompt_text=prompt_text,
                            temperature=args.temperature,
                            max_tokens=args.max_tokens,
                        )
                        parsed = parse_judge_json(text)
                        draft_finding = normalize_finding(candidate_id, parsed, args.model)

                        verification_payload: dict[str, Any] | None = None
                        final_parsed = parsed
                        if args.verify_cwe and draft_finding["verdict"] != "not_risky":
                            reference_pack = build_reference_pack(
                                draft_finding["cwe"],
                                catalog_cache_path=args.catalog_cache,
                                max_examples=max(1, args.mitre_max_examples),
                                query_text=query_text + "\n" + str(draft_finding.get("details", {}).get("reasoning", "")),
                                top_k=8,
                            )
                            verify_prompt = build_verification_prompt(
                                verify_template,
                                candidate_json,
                                draft_finding,
                                reference_pack,
                            )
                            verify_text = call_openrouter(
                                client=client,
                                api_key=api_key,
                                model=args.model,
                                prompt_text=verify_prompt,
                                temperature=args.temperature,
                                max_tokens=args.max_tokens,
                            )
                            verified = parse_judge_json(verify_text)
                            final_parsed = verified
                            verification_payload = {
                                "mode": "mitre_cwe_verify",
                                "draft": summarize_finding(draft_finding),
                                "reference_pack": reference_pack,
                                "verify_prompt": str(args.verify_prompt),
                            }
                            if split_cwe_values(verified.get("cwe", [])) != draft_finding["cwe"]:
                                verification_payload["revised"] = True
                            else:
                                verification_payload["revised"] = False

                        finding = normalize_finding(candidate_id, final_parsed, args.model)
                        if verification_payload is not None:
                            finding["details"]["verification"] = verification_payload
                            finding["details"]["draft"] = summarize_finding(draft_finding)
                        wf.write(orjson.dumps(finding) + b"\n")
                        count_ok += 1
                        done_ids.add(candidate_id)
                        last_err = None
                        break
                    except Exception as exc:  # noqa: BLE001
                        last_err = exc
                        if attempt < args.retries:
                            time.sleep(min(1.5 * attempt, 5.0))

                if last_err is not None:
                    count_err += 1
                    fallback = build_fallback(candidate_id, str(last_err))
                    fallback["details"]["model"] = args.model
                    wf.write(orjson.dumps(fallback) + b"\n")
                    done_ids.add(candidate_id)

                if args.sleep > 0:
                    time.sleep(args.sleep)

    print(f"Candidates seen: {len(raw_lines)}")
    print(f"Candidates skipped(resume): {count_skip}")
    print(f"Judge success: {count_ok}")
    print(f"Judge fallback(errors): {count_err}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
