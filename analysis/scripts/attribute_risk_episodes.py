#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import orjson
from dotenv import load_dotenv
from tqdm import tqdm


ALLOWED = {
    "interaction_stage": {
        "initial_generation",
        "repair_debugging",
        "optimization_refactor",
        "feature_expansion",
        "dependency_installation",
        "deployment_configuration",
        "security_fix",
        "unknown",
    },
    "risk_origin": {
        "user_induced",
        "agent_induced",
        "repair_induced",
        "context_loss_induced",
        "tool_or_retrieval_induced",
        "ambiguity_induced",
        "mixed",
        "unknown",
    },
    "mechanism": {
        "validation_removal",
        "unsafe_default",
        "hardcoded_secret",
        "insecure_deserialization",
        "raw_query_construction",
        "command_injection_pattern",
        "disabled_tls_or_auth",
        "overbroad_permission",
        "dangerous_shell_command",
        "hallucinated_secure_api",
        "unsafe_dependency_recommendation",
        "partial_fix",
        "security_requirement_omission",
        "unknown",
    },
    "risk_evolution": {
        "introduced",
        "persisted",
        "amplified",
        "partially_fixed",
        "fully_fixed",
        "reintroduced",
        "propagated",
        "unknown",
    },
    "user_reaction": {
        "accepted_without_questioning",
        "questioned_security",
        "requested_fix",
        "executed_or_planned_execution",
        "ignored",
        "unknown",
    },
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Assign interaction-level attribution labels to risk episodes."
    )
    p.add_argument("--episodes", type=Path, required=True)
    p.add_argument("--chats-dir", type=Path, required=True)
    p.add_argument("--prompt", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--model", type=str, default="openai/gpt-5.4-mini")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=1200)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--sleep", type=float, default=0.0)
    p.add_argument("--resume", dest="resume", action="store_true", default=True)
    p.add_argument("--no-resume", dest="resume", action="store_false")
    p.add_argument(
        "--retry-failures",
        action="store_true",
        help="When resuming, retry prior attribution_error rows instead of treating them as done.",
    )
    p.add_argument(
        "--fallback-wide",
        action="store_true",
        help="Run a second attribution call with a wider chat window when needed.",
    )
    p.add_argument("--fallback-window-before", type=int, default=8)
    p.add_argument("--fallback-window-after", type=int, default=4)
    p.add_argument(
        "--fallback-unknown-fields",
        type=str,
        default="interaction_stage,risk_origin,mechanism",
        help="Comma-separated attribution fields that trigger wide fallback when unknown.",
    )
    p.add_argument("--fallback-min-evidence-quotes", type=int, default=1)
    p.add_argument(
        "--fallback-max",
        type=int,
        default=0,
        help="Maximum wide fallback calls; 0 means no cap.",
    )
    return p.parse_args()


def clip(s: str, n: int = 1200) -> str:
    s = str(s or "").strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def load_jsonl(path: Path, limit: int = 0) -> list[dict[str, Any]]:
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
        role = str(msg.get("role") or "tool").strip().lower()
        if role == "user":
            role = "user"
        elif role == "assistant":
            role = "assistant"
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


def is_failure_row(obj: dict[str, Any]) -> bool:
    details = obj.get("details") if isinstance(obj.get("details"), dict) else {}
    return bool(details.get("attribution_error") or details.get("error"))


def load_done_episode_ids(out_file: Path, retry_failures: bool = False) -> set[str]:
    done: set[str] = set()
    if not out_file.exists():
        return done
    with out_file.open("rb") as f:
        for line in f:
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if retry_failures and is_failure_row(obj):
                continue
            episode_id = obj.get("episode_id")
            if isinstance(episode_id, str) and episode_id:
                done.add(episode_id)
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
            episode_id = str(obj.get("episode_id") or "")
            if not episode_id or is_failure_row(obj):
                continue
            if episode_id not in rows_by_id:
                order.append(episode_id)
            rows_by_id[episode_id] = obj
    with out_file.open("wb") as wf:
        for episode_id in order:
            wf.write(orjson.dumps(rows_by_id[episode_id]) + b"\n")


def maybe_strip_code_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```") and t.endswith("```"):
        lines = t.splitlines()
        if len(lines) >= 2:
            return "\n".join(lines[1:-1]).strip()
    return t


def parse_json_response(text: str) -> dict[str, Any]:
    raw = maybe_strip_code_fence(text)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            return json.loads(raw[start : end + 1])
        raise


def conversation_window(episode: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "turn_index": ev.get("turn_index"),
            "role": ev.get("role"),
            "quote": clip(str(ev.get("quote") or ""), 1000),
            "why_relevant": ev.get("why_relevant"),
        }
        for ev in episode.get("evidence_quotes", [])
        if isinstance(ev, dict)
    ]


def expand_episode_window(
    episode: dict[str, Any],
    chats_dir: Path,
    window_before: int,
    window_after: int,
) -> dict[str, Any]:
    chat_id = str(episode.get("chat_id") or "")
    turns = load_chat_turns(chats_dir, chat_id)
    if not turns:
        return episode

    try:
        risk_turn = int(episode.get("risk_turn_index", 0))
    except (TypeError, ValueError):
        risk_turn = 0
    start_turn = max(0, risk_turn - max(0, window_before))
    max_turn = max((int(turn["turn_index"]) for turn in turns), default=risk_turn)
    end_turn = min(max_turn, risk_turn + max(0, window_after))

    evidence_quotes: list[dict[str, Any]] = []
    for turn in turns:
        idx = int(turn["turn_index"])
        if idx < start_turn or idx > end_turn:
            continue
        text = clip(str(turn.get("text") or ""), 1000)
        if not text:
            continue
        why = "risk candidate turn" if idx == risk_turn else "wide fallback context"
        evidence_quotes.append(
            {
                "turn_index": idx,
                "role": turn["role"],
                "quote": text,
                "why_relevant": why,
            }
        )

    out = dict(episode)
    out["episode_window"] = {"start_turn": start_turn, "end_turn": end_turn}
    out["evidence_turns"] = list(range(start_turn, end_turn + 1))
    out["evidence_quotes"] = evidence_quotes
    details = dict(out.get("details") or {})
    details["wide_fallback_context"] = {
        "window_before": window_before,
        "window_after": window_after,
        "source_episode_window": episode.get("episode_window"),
    }
    out["details"] = details
    return out


def build_prompt(template: str, episode: dict[str, Any]) -> str:
    episode_payload = {
        key: episode.get(key)
        for key in (
            "episode_id",
            "chat_id",
            "finding_ids",
            "candidate_ids",
            "risk_lineage_id",
            "lineage_role",
            "risk_turn_index",
            "episode_window",
            "confidence_tier",
            "cwe_ids",
            "primary_cwe",
            "cwe_abstraction",
            "cwe_specificity",
            "needs_human_cwe_review",
            "risk_summary",
            "details",
        )
    }
    return template.replace(
        "{{episode_json}}",
        json.dumps(episode_payload, ensure_ascii=False, indent=2),
    ).replace(
        "{{conversation_window_json}}",
        json.dumps(conversation_window(episode), ensure_ascii=False, indent=2),
    )


def call_openrouter(
    client: httpx.Client,
    api_key: str,
    model: str,
    prompt_text: str,
    temperature: float,
    max_tokens: int,
) -> str:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    referer = os.getenv("OPENROUTER_HTTP_REFERER")
    title = os.getenv("OPENROUTER_APP_TITLE")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title

    resp = client.post(
        "/chat/completions",
        headers=headers,
        json={
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt_text}],
        },
    )
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("OpenRouter returned no choices")
    content = (choices[0].get("message") or {}).get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    raise ValueError("OpenRouter response has no text content")


def normalize_attribution(parsed: dict[str, Any], episode: dict[str, Any]) -> dict[str, Any]:
    out = dict(episode)
    for key, values in ALLOWED.items():
        value = str(parsed.get(key) or "unknown")
        out[key] = value if value in values else "unknown"

    summary = str(parsed.get("risk_summary") or episode.get("risk_summary") or "").strip()
    out["risk_summary"] = clip(summary, 700) or "No attribution summary provided."

    evidence_turns = parsed.get("evidence_turns", episode.get("evidence_turns", []))
    if not isinstance(evidence_turns, list):
        evidence_turns = []
    fixed_turns: list[int] = []
    for value in evidence_turns:
        try:
            fixed_turns.append(max(0, int(value)))
        except (TypeError, ValueError):
            continue
    out["evidence_turns"] = sorted(set(fixed_turns))

    quotes = parsed.get("evidence_quotes")
    parsed_evidence_quote_count = len(quotes) if isinstance(quotes, list) else 0
    used_episode_quotes_fallback = not isinstance(quotes, list)
    if used_episode_quotes_fallback:
        quotes = episode.get("evidence_quotes", [])
    fixed_quotes: list[dict[str, Any]] = []
    for ev in quotes:
        if not isinstance(ev, dict):
            continue
        try:
            turn_index = max(0, int(ev.get("turn_index")))
        except (TypeError, ValueError):
            continue
        role = str(ev.get("role") or "tool").lower()
        if role not in {"user", "assistant", "tool"}:
            role = "tool"
        fixed_quotes.append(
            {
                "turn_index": turn_index,
                "role": role,
                "quote": clip(str(ev.get("quote") or ""), 500),
                "why_relevant": clip(str(ev.get("why_relevant") or ""), 300),
            }
        )
    out["evidence_quotes"] = fixed_quotes
    out["details"] = dict(out.get("details") or {})
    out["details"]["attribution"] = {
        "model": parsed.get("_model"),
        "raw_labels": {key: parsed.get(key) for key in ALLOWED},
        "parsed_evidence_quote_count": parsed_evidence_quote_count,
        "used_episode_quotes_fallback": used_episode_quotes_fallback,
    }
    return out


def fallback_reasons(
    row: dict[str, Any],
    unknown_fields: set[str],
    min_evidence_quotes: int,
) -> list[str]:
    reasons: list[str] = []
    for field in sorted(unknown_fields):
        if field in ALLOWED and row.get(field) == "unknown":
            reasons.append(f"{field}=unknown")
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    attribution = details.get("attribution") if isinstance(details.get("attribution"), dict) else {}
    evidence_quote_count = attribution.get("parsed_evidence_quote_count")
    if not isinstance(evidence_quote_count, int):
        evidence_quotes = row.get("evidence_quotes")
        evidence_quote_count = len(evidence_quotes) if isinstance(evidence_quotes, list) else 0
    if evidence_quote_count < min_evidence_quotes:
        reasons.append(f"evidence_quotes<{min_evidence_quotes}")
    if details.get("attribution_error"):
        reasons.append("attribution_error")
    return reasons


def attribute_episode(
    episode: dict[str, Any],
    *,
    client: httpx.Client,
    api_key: str,
    model: str,
    template: str,
    temperature: float,
    max_tokens: int,
    retries: int,
    chats_dir: Path | None = None,
    fallback_wide: bool = False,
    fallback_window_before: int = 8,
    fallback_window_after: int = 4,
    fallback_unknown_fields: set[str] | None = None,
    fallback_min_evidence_quotes: int = 1,
) -> dict[str, Any]:
    fallback_unknown_fields = fallback_unknown_fields or set()
    prompt_text = build_prompt(template, episode)
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            text = call_openrouter(client, api_key, model, prompt_text, temperature, max_tokens)
            parsed = parse_json_response(text)
            parsed["_model"] = model
            first = normalize_attribution(parsed, episode)
            reasons = fallback_reasons(first, fallback_unknown_fields, fallback_min_evidence_quotes)
            if fallback_wide and reasons and chats_dir is not None:
                wide_episode = expand_episode_window(
                    episode,
                    chats_dir,
                    fallback_window_before,
                    fallback_window_after,
                )
                if wide_episode.get("evidence_quotes") != episode.get("evidence_quotes"):
                    wide_text = call_openrouter(
                        client,
                        api_key,
                        model,
                        build_prompt(template, wide_episode),
                        temperature,
                        max_tokens,
                    )
                    wide_parsed = parse_json_response(wide_text)
                    wide_parsed["_model"] = model
                    second = normalize_attribution(wide_parsed, wide_episode)
                    details = dict(second.get("details") or {})
                    details["attribution_fallback"] = {
                        "triggered": True,
                        "reasons": reasons,
                        "default_labels": {key: first.get(key) for key in ALLOWED},
                        "default_model_evidence_quote_count": (
                            (first.get("details") or {})
                            .get("attribution", {})
                            .get("parsed_evidence_quote_count")
                        ),
                        "wide_window": wide_episode.get("episode_window"),
                    }
                    second["details"] = details
                    return second

            details = dict(first.get("details") or {})
            details["attribution_fallback"] = {"triggered": False, "reasons": reasons}
            first["details"] = details
            return first
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            if attempt < retries:
                time.sleep(min(1.5 * attempt, 5.0))

    fallback = dict(episode)
    fallback["details"] = dict(fallback.get("details") or {})
    fallback["details"]["attribution_error"] = str(last_err)
    return fallback


def main() -> None:
    args = parse_args()
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit("Missing OPENROUTER_API_KEY in environment/.env")

    episodes = load_jsonl(args.episodes, args.limit)
    fallback_unknown_fields = {
        field.strip()
        for field in args.fallback_unknown_fields.split(",")
        if field.strip()
    }
    template = args.prompt.read_text(encoding="utf-8")
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    if args.resume and args.retry_failures:
        compact_resume_output(args.out)
    done_ids = (
        load_done_episode_ids(args.out, retry_failures=args.retry_failures)
        if args.resume
        else set()
    )
    pending = [ep for ep in episodes if str(ep.get("episode_id") or "") not in done_ids]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    mode = "ab" if args.resume else "wb"
    with httpx.Client(base_url=base_url, timeout=120.0) as client, args.out.open(mode) as wf:
        fallback_used = 0
        for episode in tqdm(pending, desc="risk-attribution"):
            use_fallback = args.fallback_wide and (
                args.fallback_max <= 0 or fallback_used < args.fallback_max
            )
            row = attribute_episode(
                episode,
                client=client,
                api_key=api_key,
                model=args.model,
                template=template,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                retries=args.retries,
                chats_dir=args.chats_dir,
                fallback_wide=use_fallback,
                fallback_window_before=args.fallback_window_before,
                fallback_window_after=args.fallback_window_after,
                fallback_unknown_fields=fallback_unknown_fields,
                fallback_min_evidence_quotes=args.fallback_min_evidence_quotes,
            )
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            fallback_info = (
                details.get("attribution_fallback")
                if isinstance(details.get("attribution_fallback"), dict)
                else {}
            )
            if fallback_info.get("triggered"):
                fallback_used += 1
            write_jsonl_row(wf, row)
            if args.sleep > 0:
                time.sleep(args.sleep)

    print(f"Episodes seen: {len(episodes)}")
    print(f"Episodes skipped(resume): {len(episodes) - len(pending)}")
    print(f"Episodes attributed: {len(pending)}")
    if args.fallback_wide:
        print(f"Wide fallback max: {args.fallback_max or 'uncapped'}")
        print(f"Wide fallback used: {fallback_used}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
