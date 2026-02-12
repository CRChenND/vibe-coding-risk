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

CAUSES = {
    "user_requested_risk",
    "assistant_over_implemented",
    "assistant_hallucinated_risk",
    "inherited_or_context_risk",
    "mixed_causality",
    "insufficient_evidence",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run attribution judge via OpenRouter on risky backtrace JSONL.")
    p.add_argument("--input", type=Path, default=Path("analysis/output/risky_backtrace_all.jsonl"))
    p.add_argument("--prompt", type=Path, default=Path("analysis/prompts/attribution_judge_v1.md"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--model", type=str, default="google/gemini-2.5-flash-lite")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=700)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--sleep", type=float, default=0.0)
    p.add_argument("--limit", type=int, default=0, help="0 means no limit")
    p.add_argument("--resume", dest="resume", action="store_true", default=True)
    p.add_argument("--no-resume", dest="resume", action="store_false")
    p.add_argument(
        "--retry-errors",
        action="store_true",
        default=False,
        help="When resuming, re-run rows that previously only have judge_error fallback.",
    )
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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


def parse_json(text: str) -> dict[str, Any]:
    raw = maybe_strip_code_fence(text)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            return json.loads(raw[start : end + 1])
        raise


def load_done_ids(out_file: Path, *, include_error_rows: bool) -> set[str]:
    done: set[str] = set()
    if not out_file.exists():
        return done
    with out_file.open("rb") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            fid = obj.get("finding_id")
            if isinstance(fid, str) and fid:
                if not include_error_rows:
                    judge = obj.get("judge")
                    if isinstance(judge, dict) and isinstance(judge.get("error"), str):
                        # Keep prior error rows eligible for retry during resume.
                        continue
                done.add(fid)
    return done


def to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"true", "1", "yes"}:
            return True
        if s in {"false", "0", "no"}:
            return False
    return default


def clamp_conf(v: Any) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        x = 0.0
    return max(0.0, min(1.0, x))


def normalize(
    finding_id: str,
    candidate_id: str,
    chat_id: str,
    model: str,
    parsed: dict[str, Any],
    raw_text: str,
) -> dict[str, Any]:
    primary = str(parsed.get("primary_cause", "insufficient_evidence")).strip()
    if primary not in CAUSES:
        primary = "insufficient_evidence"

    secondary_raw = parsed.get("secondary_cause")
    secondary: str | None
    if secondary_raw is None:
        secondary = None
    else:
        secondary = str(secondary_raw).strip()
        if secondary == "null" or secondary not in CAUSES:
            secondary = None

    evidence_in = parsed.get("evidence", [])
    evidence: list[dict[str, str]] = []
    if isinstance(evidence_in, list):
        for item in evidence_in:
            if not isinstance(item, dict):
                continue
            span = str(item.get("span", "")).strip()
            why = str(item.get("why", "")).strip()
            if span or why:
                evidence.append({"span": span[:240], "why": why[:320]})

    return {
        "attribution_id": sha256_text(f"attribution:{finding_id}:{model}")[:24],
        "finding_id": finding_id,
        "candidate_id": candidate_id,
        "chat_id": chat_id,
        "primary_cause": primary,
        "secondary_cause": secondary,
        "confidence": clamp_conf(parsed.get("confidence", 0.0)),
        "is_user_driven": to_bool(parsed.get("is_user_driven"), default=False),
        "is_assistant_driven": to_bool(parsed.get("is_assistant_driven"), default=False),
        "reasoning": str(parsed.get("reasoning", "")).strip()[:600],
        "evidence": evidence,
        "needs_human_review": to_bool(parsed.get("needs_human_review"), default=False),
        "judge": {"model": model, "raw": raw_text[:2000]},
    }


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


def compact_record(rec: dict[str, Any]) -> dict[str, Any]:
    # Keep prompt payload small and focused on attribution-relevant fields.
    out = {
        "finding_id": rec.get("finding_id"),
        "candidate_id": rec.get("candidate_id"),
        "chat_id": rec.get("chat_id"),
        "risk": rec.get("risk"),
        "nearest_user": rec.get("nearest_user"),
        "assistant_context": rec.get("assistant_context"),
        "lookback_users": rec.get("lookback_users"),
        "meta": rec.get("meta"),
    }
    return out


def main() -> None:
    args = parse_args()
    load_dotenv()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("Missing OPENROUTER_API_KEY in environment/.env")

    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    template = args.prompt.read_text(encoding="utf-8")

    raw_lines = args.input.read_bytes().splitlines()
    if args.limit and args.limit > 0:
        raw_lines = raw_lines[: args.limit]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    done_ids = (
        load_done_ids(args.out, include_error_rows=not args.retry_errors)
        if args.resume
        else set()
    )

    mode = "ab" if args.resume else "wb"
    count_ok = 0
    count_err = 0
    count_skip = 0

    with httpx.Client(base_url=base_url, timeout=120.0) as client:
        with args.out.open(mode) as wf:
            for raw in tqdm(raw_lines, desc="attribution-judge"):
                if not raw.strip():
                    continue
                rec = orjson.loads(raw)
                finding_id = str(rec.get("finding_id", ""))
                candidate_id = str(rec.get("candidate_id", ""))
                chat_id = str(rec.get("chat_id", ""))

                if not finding_id:
                    continue
                if finding_id in done_ids:
                    count_skip += 1
                    continue

                compact_json = orjson.dumps(compact_record(rec), option=orjson.OPT_INDENT_2).decode("utf-8")
                prompt_text = template.replace("{{risky_backtrace_record_json}}", compact_json)

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
                        parsed = parse_json(text)
                        row = normalize(finding_id, candidate_id, chat_id, args.model, parsed, text)
                        wf.write(orjson.dumps(row) + b"\n")
                        done_ids.add(finding_id)
                        count_ok += 1
                        last_err = None
                        break
                    except Exception as exc:  # noqa: BLE001
                        last_err = exc
                        if attempt < args.retries:
                            time.sleep(min(1.5 * attempt, 5.0))

                if last_err is not None:
                    err_row = {
                        "attribution_id": sha256_text(f"attribution_error:{finding_id}")[:24],
                        "finding_id": finding_id,
                        "candidate_id": candidate_id,
                        "chat_id": chat_id,
                        "primary_cause": "insufficient_evidence",
                        "secondary_cause": None,
                        "confidence": 0.0,
                        "is_user_driven": False,
                        "is_assistant_driven": False,
                        "reasoning": f"judge_error: {last_err}",
                        "evidence": [],
                        "needs_human_review": True,
                        "judge": {"model": args.model, "error": str(last_err)},
                    }
                    wf.write(orjson.dumps(err_row) + b"\n")
                    done_ids.add(finding_id)
                    count_err += 1

                if args.sleep > 0:
                    time.sleep(args.sleep)

    print(f"Input rows: {len(raw_lines)}")
    print(f"Written rows (ok): {count_ok}")
    print(f"Written rows (error-fallback): {count_err}")
    print(f"Skipped via resume: {count_skip}")
    print(f"Resume mode: {args.resume}")
    print(f"Retry previous error rows: {args.retry_errors}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
