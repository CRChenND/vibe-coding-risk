#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm

CODE_FENCE_RE = re.compile(r"```([a-zA-Z0-9_+\-]*)\n(.*?)```", re.DOTALL)
SECURITY_TERMS_RE = re.compile(
    r"(?i)\b(auth|authentication|authorization|xss|csrf|sql injection|rce|"
    r"command injection|path traversal|ssrf|secret|token|password|encrypt|tls|ssl)\b"
)
LOG_LIKE_RE = re.compile(r"(?i)(build succeeded|stack trace|exception|cannot find path|\bps\s+[A-Z]:\\)")
COPIED_LIKE_RE = re.compile(r"(?i)(file:///|read file:|listed directory|grep search for)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract analyzable assistant candidates from chat JSON files.")
    p.add_argument("--chats-dir", type=Path, required=True)
    p.add_argument("--searches-file", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--limit", type=int, default=0, help="0 means no limit")
    return p.parse_args()


def load_json(path: Path) -> Any:
    return orjson.loads(path.read_bytes())


def normalize_text(s: str) -> str:
    return s.replace("\r\n", "\n").strip()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def short_text(s: str, max_len: int = 300) -> str:
    s = normalize_text(s)
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def load_repo_index(searches_file: Path) -> dict[str, dict[str, str | None]]:
    raw = load_json(searches_file)
    index: dict[str, dict[str, str | None]] = {}
    for item in raw:
        sha = item.get("sha")
        if not isinstance(sha, str):
            continue
        if sha in index:
            continue
        repo = item.get("repository") or {}
        index[sha] = {
            "repo_full_name": repo.get("full_name"),
            "repo_url": repo.get("html_url"),
            "search_match_path": item.get("path"),
        }
    return index


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


def detect_attribution(candidate_type: str, source_block_type: str, content: str) -> str:
    txt = content.strip()
    if source_block_type == "unknown" or LOG_LIKE_RE.search(txt):
        return "execution_log"
    if COPIED_LIKE_RE.search(txt):
        return "copied_from_repo"
    if candidate_type in {"command", "code_snippet", "security_advice"} and source_block_type in {
        "bash",
        "text",
    }:
        return "generated"
    return "unclear"


def build_candidate(
    *,
    chat_id: str,
    chat_path: Path,
    platform: str | None,
    timestamp: str | None,
    message_index: int,
    block_index: int,
    candidate_idx: int,
    candidate_type: str,
    language_hint: str | None,
    content: str,
    block_type: str,
    preceding_user_text: str | None,
    repo_ctx: dict[str, str | None],
) -> dict[str, Any]:
    cleaned = normalize_text(content)
    digest = sha256_text(cleaned)
    candidate_id = f"{chat_id}:{message_index}:{block_index}:{candidate_idx}:{candidate_type}"
    attribution = detect_attribution(candidate_type, block_type, cleaned)
    return {
        "candidate_id": candidate_id,
        "chat_id": chat_id,
        "chat_path": str(chat_path),
        "platform": platform,
        "timestamp": timestamp,
        "message_index": message_index,
        "block_index": block_index,
        "candidate_type": candidate_type,
        "language_hint": language_hint,
        "content": cleaned,
        "content_hash": digest,
        "attribution": attribution,
        "repo_context": {
            "repo_full_name": repo_ctx.get("repo_full_name"),
            "repo_url": repo_ctx.get("repo_url"),
            "search_match_path": repo_ctx.get("search_match_path"),
        },
        "metadata": {
            "block_type": block_type,
            "preceding_user_text": short_text(preceding_user_text or "") or None,
            "assistant_text_len": len(cleaned),
        },
    }


def extract_from_chat(chat_path: Path, repo_index: dict[str, dict[str, str | None]]) -> list[dict[str, Any]]:
    data = load_json(chat_path)
    messages = data.get("messages") or []
    platform = data.get("platform")
    timestamp = data.get("timestamp")
    chat_id = chat_path.name.replace(".md.json", "")
    repo_ctx = repo_index.get(
        chat_id,
        {"repo_full_name": None, "repo_url": None, "search_match_path": None},
    )

    candidates: list[dict[str, Any]] = []
    last_user_text: str | None = None

    for mi, msg in enumerate(messages):
        role = str(msg.get("role", "")).strip().lower()
        blocks = flatten_blocks(msg.get("blocks"))

        if role == "user":
            texts: list[str] = []
            for b in blocks:
                if b.get("type") == "text" and isinstance(b.get("content"), str):
                    texts.append(b["content"])
            if texts:
                last_user_text = "\n".join(texts)
            continue

        if role != "assistant":
            continue

        for bi, blk in enumerate(blocks):
            block_type = str(blk.get("type", ""))
            content = blk.get("content")
            if not isinstance(content, str):
                continue

            local_idx = 0
            if block_type == "bash":
                candidates.append(
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="command",
                        language_hint="shell",
                        content=content,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                        repo_ctx=repo_ctx,
                    )
                )
                continue

            if block_type != "text":
                continue

            text = normalize_text(content)

            for m in CODE_FENCE_RE.finditer(text):
                lang = m.group(1).strip() or None
                snippet = m.group(2)
                candidates.append(
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="code_snippet",
                        language_hint=lang,
                        content=snippet,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                        repo_ctx=repo_ctx,
                    )
                )
                local_idx += 1

            if SECURITY_TERMS_RE.search(text):
                candidates.append(
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="security_advice",
                        language_hint=None,
                        content=text,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                        repo_ctx=repo_ctx,
                    )
                )

    return candidates


def main() -> None:
    args = parse_args()
    chat_files = sorted(args.chats_dir.glob("*.md.json"))
    if args.limit and args.limit > 0:
        chat_files = chat_files[: args.limit]

    repo_index = load_repo_index(args.searches_file)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    total_candidates = 0
    with args.out.open("wb") as f:
        for chat_file in tqdm(chat_files, desc="extract"):
            try:
                candidates = extract_from_chat(chat_file, repo_index)
            except Exception as exc:  # noqa: BLE001
                err = {
                    "candidate_id": f"error:{chat_file.name}",
                    "chat_id": chat_file.name,
                    "chat_path": str(chat_file),
                    "platform": None,
                    "timestamp": None,
                    "message_index": 0,
                    "block_index": 0,
                    "candidate_type": "security_advice",
                    "language_hint": None,
                    "content": f"PARSE_ERROR: {exc}",
                    "content_hash": sha256_text(str(exc)),
                    "attribution": "unclear",
                    "repo_context": {
                        "repo_full_name": None,
                        "repo_url": None,
                        "search_match_path": None,
                    },
                    "metadata": {"error": True},
                }
                f.write(orjson.dumps(err) + b"\n")
                total_candidates += 1
                continue

            for c in candidates:
                f.write(orjson.dumps(c) + b"\n")
            total_candidates += len(candidates)

    print(f"Processed chats: {len(chat_files)}")
    print(f"Extracted candidates: {total_candidates}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
