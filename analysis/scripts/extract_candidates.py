#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm

CODE_FENCE_RE = re.compile(r"```([a-zA-Z0-9_+\-]*)\n(.*?)```", re.DOTALL)
EMPTY_DIFF_RE = re.compile(r"^(?:[-+]\s*)+$")
LOG_LIKE_RE = re.compile(r"(?i)(build succeeded|stack trace|exception|cannot find path|\bps\s+[A-Z]:\\)")
COPIED_LIKE_RE = re.compile(r"(?i)(file:///|read file:|listed directory|grep search for)")
COMMAND_BLOCK_TYPES = {"bash", "sh", "shell", "zsh", "powershell", "ps1", "cmd", "terminal"}
SKIP_BLOCK_TYPES = {"details", "read-file", "tool-use", "think", "unknown"}
CODE_BLOCK_TYPES = {
    "c",
    "cpp",
    "csharp",
    "css",
    "dart",
    "diff",
    "dockerfile",
    "elixir",
    "go",
    "html",
    "java",
    "javascript",
    "js",
    "json",
    "jsonc",
    "jsx",
    "kotlin",
    "lua",
    "markdown",
    "md",
    "php",
    "plaintext",
    "python",
    "py",
    "ruby",
    "rust",
    "sql",
    "swift",
    "toml",
    "ts",
    "tsx",
    "typescript",
    "vue",
    "xml",
    "yaml",
    "yml",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract analyzable assistant candidates from chat JSON files.")
    p.add_argument("--chats-dir", type=Path, required=True)
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


def language_hint_from_block_type(block_type: str) -> str | None:
    base = block_type.strip().lower().split(":", 1)[0]
    if base in CODE_BLOCK_TYPES:
        return base
    return None


def detect_attribution(candidate_type: str, source_block_type: str, content: str) -> str:
    txt = content.strip()
    source_block_type_norm = source_block_type.strip().lower()
    if source_block_type_norm == "unknown" or LOG_LIKE_RE.search(txt):
        return "execution_log"
    if COPIED_LIKE_RE.search(txt):
        return "copied_from_repo"
    if candidate_type in {"command", "code_snippet"} and (
        source_block_type_norm in COMMAND_BLOCK_TYPES
        or source_block_type_norm == "text"
        or language_hint_from_block_type(source_block_type) is not None
    ):
        return "generated"
    return "unclear"


def build_candidate(
    *,
    chat_id: str,
    chat_path: Path,
    platform: str | None,
    timestamp: str | None,
    message_index: int,
    turn_index: int,
    message_id: str,
    role: str,
    parent_chat_id: str | None,
    block_index: int,
    candidate_idx: int,
    candidate_type: str,
    language_hint: str | None,
    content: str,
    block_type: str,
    preceding_user_text: str | None,
) -> dict[str, Any] | None:
    cleaned = normalize_text(content)
    if not cleaned:
        return None
    if candidate_type == "code_snippet" and language_hint == "diff" and EMPTY_DIFF_RE.fullmatch(cleaned):
        return None
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
        "turn_index": turn_index,
        "message_id": message_id,
        "role": role,
        "parent_chat_id": parent_chat_id,
        "block_index": block_index,
        "candidate_type": candidate_type,
        "language_hint": language_hint,
        "content": cleaned,
        "content_hash": digest,
        "attribution": attribution,
        "metadata": {
            "block_type": block_type,
            "preceding_user_text": short_text(preceding_user_text or "") or None,
            "assistant_text_len": len(cleaned),
        },
    }


def append_candidate(candidates: list[dict[str, Any]], candidate: dict[str, Any] | None) -> None:
    if candidate is not None:
        candidates.append(candidate)


def extract_from_chat(chat_path: Path) -> list[dict[str, Any]]:
    data = load_json(chat_path)
    messages = data.get("messages") or []
    platform = data.get("platform")
    timestamp = data.get("timestamp")
    parent_chat_id = data.get("parent_chat_id") or data.get("parent_id")
    if parent_chat_id is not None:
        parent_chat_id = str(parent_chat_id)
    chat_id = chat_path.name.replace(".md.json", "")

    candidates: list[dict[str, Any]] = []
    last_user_text: str | None = None

    for mi, msg in enumerate(messages):
        role = str(msg.get("role", "")).strip().lower()
        message_id = str(msg.get("id") or msg.get("message_id") or f"{chat_id}:{mi}")
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
            block_type_norm = block_type.strip().lower()
            if block_type_norm in SKIP_BLOCK_TYPES:
                continue

            if block_type_norm in COMMAND_BLOCK_TYPES:
                append_candidate(
                    candidates,
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        turn_index=mi,
                        message_id=message_id,
                        role=role,
                        parent_chat_id=parent_chat_id,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="command",
                        language_hint="shell",
                        content=content,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                    ),
                )
                continue

            language_hint = language_hint_from_block_type(block_type)
            if language_hint is not None:
                append_candidate(
                    candidates,
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        turn_index=mi,
                        message_id=message_id,
                        role=role,
                        parent_chat_id=parent_chat_id,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="code_snippet",
                        language_hint=language_hint,
                        content=content,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                    ),
                )
                continue

            if block_type_norm != "text":
                continue

            text = normalize_text(content)

            for m in CODE_FENCE_RE.finditer(text):
                lang = m.group(1).strip() or None
                snippet = m.group(2)
                append_candidate(
                    candidates,
                    build_candidate(
                        chat_id=chat_id,
                        chat_path=chat_path,
                        platform=platform,
                        timestamp=timestamp,
                        message_index=mi,
                        turn_index=mi,
                        message_id=message_id,
                        role=role,
                        parent_chat_id=parent_chat_id,
                        block_index=bi,
                        candidate_idx=local_idx,
                        candidate_type="code_snippet",
                        language_hint=lang,
                        content=snippet,
                        block_type=block_type,
                        preceding_user_text=last_user_text,
                    ),
                )
                local_idx += 1

    return candidates


def main() -> None:
    args = parse_args()
    chat_files = sorted(args.chats_dir.glob("*.md.json"))
    if args.limit and args.limit > 0:
        chat_files = chat_files[: args.limit]

    args.out.parent.mkdir(parents=True, exist_ok=True)

    total_candidates = 0
    type_counts: Counter[str] = Counter()
    with args.out.open("wb") as f:
        for chat_file in tqdm(chat_files, desc="extract"):
            try:
                candidates = extract_from_chat(chat_file)
            except Exception as exc:  # noqa: BLE001
                type_counts["parse_error"] += 1
                continue

            for c in candidates:
                f.write(orjson.dumps(c) + b"\n")
                type_counts[str(c.get("candidate_type") or "unknown")] += 1
            total_candidates += len(candidates)

    print(f"Processed chats: {len(chat_files)}")
    print(f"Extracted candidates: {total_candidates}")
    print(f"Candidate types: {dict(sorted(type_counts.items()))}")
    print(f"Output: {args.out}")


if __name__ == "__main__":
    main()
