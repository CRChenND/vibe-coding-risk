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
    p = argparse.ArgumentParser(description="Assign interaction-level attribution labels to risk episodes.")
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


def load_done_episode_ids(out_file: Path) -> set[str]:
    done: set[str] = set()
    if not out_file.exists():
        return done
    with out_file.open("rb") as f:
        for line in f:
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            episode_id = obj.get("episode_id")
            if isinstance(episode_id, str) and episode_id:
                done.add(episode_id)
    return done


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
    if not isinstance(quotes, list):
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
    }
    return out


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
) -> dict[str, Any]:
    prompt_text = build_prompt(template, episode)
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            text = call_openrouter(client, api_key, model, prompt_text, temperature, max_tokens)
            parsed = parse_json_response(text)
            parsed["_model"] = model
            return normalize_attribution(parsed, episode)
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
    template = args.prompt.read_text(encoding="utf-8")
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    done_ids = load_done_episode_ids(args.out) if args.resume else set()
    pending = [ep for ep in episodes if str(ep.get("episode_id") or "") not in done_ids]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    mode = "ab" if args.resume else "wb"
    with httpx.Client(base_url=base_url, timeout=120.0) as client, args.out.open(mode) as wf:
        for episode in tqdm(pending, desc="risk-attribution"):
            row = attribute_episode(
                episode,
                client=client,
                api_key=api_key,
                model=args.model,
                template=template,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                retries=args.retries,
            )
            wf.write(orjson.dumps(row) + b"\n")
            if args.sleep > 0:
                time.sleep(args.sleep)

    print(f"Episodes seen: {len(episodes)}")
    print(f"Episodes skipped(resume): {len(episodes) - len(pending)}")
    print(f"Episodes attributed: {len(pending)}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
