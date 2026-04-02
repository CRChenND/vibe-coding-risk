#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm

CODE_FENCE_RE = re.compile(r"```([a-zA-Z0-9_+\-]*)\n(.*?)```", re.DOTALL)
INLINE_CODE_RE = re.compile(r"`([^`\n]{2,200})`")

COMMAND_HEADS = {
    "git", "npm", "pnpm", "yarn", "bun", "pip", "pip3", "python", "python3", "node", "npx",
    "docker", "kubectl", "curl", "wget", "bash", "sh", "zsh", "pwsh", "powershell",
    "go", "java", "javac", "mvn", "gradle", "make", "cmake", "gcc", "g++", "clang", "clang++",
    "uv", "uvx", "pytest", "brew", "apt", "apt-get", "yum", "dnf", "chmod", "chown", "rm", "mv",
    "cp", "ls", "cat", "sed", "awk", "grep", "find", "ssh", "scp", "rsync", "codeql", "semgrep",
    "gitleaks", "detect-secrets", "bandit", "gosec", "cppcheck", "shellcheck", "eslint", "spotbugs",
}

SHELL_LANGS = {"bash", "sh", "shell", "zsh", "pwsh", "powershell", "cmd", "console"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Backtrace risky judge findings to nearest user prompts/commands.")
    p.add_argument("--judge-findings", type=Path, required=True)
    p.add_argument("--chats-dir", type=Path, default=Path("data/chats"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--csv-out", type=Path, default=None)
    p.add_argument("--lookback-users", type=int, default=3)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--only-risky", dest="only_risky", action="store_true", default=True)
    p.add_argument("--all-findings", dest="only_risky", action="store_false")
    return p.parse_args()


def parse_candidate_id(candidate_id: str) -> tuple[str, int, int, int, str] | None:
    # format: chat_id:message_index:block_index:candidate_index:candidate_type
    parts = candidate_id.rsplit(":", 4)
    if len(parts) != 5:
        return None
    chat_id, mi, bi, ci, ctype = parts
    try:
        return chat_id, int(mi), int(bi), int(ci), ctype
    except ValueError:
        return None


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


def user_text_from_message(msg: dict[str, Any]) -> str:
    texts: list[str] = []
    for blk in flatten_blocks(msg.get("blocks")):
        if blk.get("type") == "text" and isinstance(blk.get("content"), str):
            texts.append(blk["content"])
    return "\n".join(texts).strip()


def assistant_block_text(msg: dict[str, Any], block_index: int) -> tuple[str | None, str]:
    blocks = flatten_blocks(msg.get("blocks"))
    if block_index < 0 or block_index >= len(blocks):
        return None, ""
    blk = blocks[block_index]
    btype = blk.get("type")
    content = blk.get("content")
    return (str(btype) if isinstance(btype, str) else None), (str(content) if isinstance(content, str) else "")


def extract_assistant_candidate_text(
    block_type: str | None,
    block_text: str,
    candidate_type: str,
    candidate_index: int,
) -> str:
    if not block_text:
        return ""
    if candidate_type == "command":
        return block_text.strip()
    if candidate_type == "security_advice":
        return block_text.strip()
    if candidate_type == "code_snippet":
        fences = list(CODE_FENCE_RE.finditer(block_text))
        if 0 <= candidate_index < len(fences):
            return (fences[candidate_index].group(2) or "").strip()
        # fallback if index mismatch
        if fences:
            return (fences[0].group(2) or "").strip()
    return block_text.strip()


def looks_like_command(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.startswith("$"):
        s = s[1:].strip()
    if s.startswith("sudo "):
        s = s[5:].strip()
    head = s.split()[0] if s.split() else ""
    return head in COMMAND_HEADS


def extract_commands(text: str) -> list[str]:
    cmds: list[str] = []

    # 1) fenced code blocks (shell-labeled or command-looking lines)
    for m in CODE_FENCE_RE.finditer(text):
        lang = (m.group(1) or "").strip().lower()
        body = m.group(2) or ""
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        if lang in SHELL_LANGS:
            cmds.extend(lines)
            continue
        for ln in lines:
            if looks_like_command(ln):
                cmds.append(ln)

    # 2) inline code fragments
    for m in INLINE_CODE_RE.finditer(text):
        frag = m.group(1).strip()
        if looks_like_command(frag):
            cmds.append(frag)

    # 3) plain lines
    for ln in text.splitlines():
        if looks_like_command(ln):
            cmds.append(ln.strip().lstrip("$").strip())

    # de-duplicate preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in cmds:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def short(s: str, n: int = 300) -> str:
    s = s.strip().replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def load_chat(chat_path: Path, cache: dict[Path, dict[str, Any]]) -> dict[str, Any] | None:
    if chat_path in cache:
        return cache[chat_path]
    if not chat_path.exists():
        return None
    try:
        obj = orjson.loads(chat_path.read_bytes())
    except Exception:  # noqa: BLE001
        return None
    cache[chat_path] = obj
    return obj


def iter_json_docs(raw: bytes) -> list[dict[str, Any]]:
    text = raw.decode("utf-8").strip()
    if not text:
        return []

    try:
        parsed = orjson.loads(text)
    except orjson.JSONDecodeError:
        pass
    else:
        return [parsed] if isinstance(parsed, dict) else []

    decoder = json.JSONDecoder()
    docs: list[dict[str, Any]] = []
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, next_idx = decoder.raw_decode(text, idx)
        if isinstance(obj, dict):
            docs.append(obj)
        idx = next_idx
    return docs


def main() -> None:
    args = parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.csv_out:
        args.csv_out.parent.mkdir(parents=True, exist_ok=True)

    rows = args.judge_findings.read_bytes().splitlines()
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]

    chat_cache: dict[Path, dict[str, Any]] = {}
    outputs: list[dict[str, Any]] = []

    for raw in tqdm(rows, desc="backtrace"):
        if not raw.strip():
            continue
        for finding in iter_json_docs(raw):
            if args.only_risky and not bool(finding.get("is_risky")):
                continue

            candidate_id = str(finding.get("candidate_id", ""))
            parsed = parse_candidate_id(candidate_id)
            if not parsed:
                continue
            chat_id, message_index, block_index, candidate_index, candidate_type = parsed

            chat_path = args.chats_dir / f"{chat_id}.md.json"
            chat = load_chat(chat_path, chat_cache)
            if not chat:
                continue

            messages = chat.get("messages") or []
            if not isinstance(messages, list):
                continue

            # nearest N previous user messages
            user_hits: list[dict[str, Any]] = []
            for mi in range(min(message_index - 1, len(messages) - 1), -1, -1):
                msg = messages[mi]
                role = str(msg.get("role", "")).strip().lower()
                if role != "user":
                    continue
                text = user_text_from_message(msg)
                cmds = extract_commands(text)
                user_hits.append(
                    {
                        "message_index": mi,
                        "text": text,
                        "commands": cmds,
                    }
                )
                if len(user_hits) >= args.lookback_users:
                    break

            nearest = user_hits[0] if user_hits else {"message_index": None, "text": "", "commands": []}
            assistant_msg = messages[message_index] if 0 <= message_index < len(messages) else {}
            ablock_type, ablock_text = assistant_block_text(assistant_msg, block_index)
            candidate_text = extract_assistant_candidate_text(
                block_type=ablock_type,
                block_text=ablock_text,
                candidate_type=candidate_type,
                candidate_index=candidate_index,
            )

            out = {
                "finding_id": finding.get("finding_id"),
                "candidate_id": candidate_id,
                "chat_id": chat_id,
                "chat_path": str(chat_path),
                "candidate": {
                    "message_index": message_index,
                    "block_index": block_index,
                    "candidate_index": candidate_index,
                    "candidate_type": candidate_type,
                },
                "risk": {
                    "is_risky": bool(finding.get("is_risky")),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "cwe": finding.get("cwe") or [],
                    "verdict": finding.get("verdict"),
                    "evidence": finding.get("evidence") or [],
                },
                "nearest_user": {
                    "message_index": nearest.get("message_index"),
                    "text": nearest.get("text", ""),
                    "commands": nearest.get("commands", []),
                },
                "assistant_context": {
                    "message_index": message_index,
                    "block_index": block_index,
                    "block_type": ablock_type,
                    "block_text": ablock_text,
                    "candidate_text": candidate_text,
                },
                "lookback_users": user_hits,
                "meta": {
                    "platform": chat.get("platform"),
                    "timestamp": chat.get("timestamp"),
                    "title": chat.get("title"),
                },
            }
            outputs.append(out)

    with args.out.open("wb") as f:
        for o in outputs:
            f.write(orjson.dumps(o) + b"\n")

    if args.csv_out:
        with args.csv_out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "finding_id",
                    "candidate_id",
                    "chat_id",
                    "severity",
                    "confidence",
                    "cwe",
                    "verdict",
                    "nearest_user_message_index",
                    "nearest_user_text_short",
                    "nearest_user_commands",
                    "assistant_message_index",
                    "assistant_block_index",
                    "assistant_block_type",
                    "assistant_candidate_text_short",
                ],
            )
            w.writeheader()
            for o in outputs:
                w.writerow(
                    {
                        "finding_id": o.get("finding_id"),
                        "candidate_id": o.get("candidate_id"),
                        "chat_id": o.get("chat_id"),
                        "severity": (o.get("risk") or {}).get("severity"),
                        "confidence": (o.get("risk") or {}).get("confidence"),
                        "cwe": ",".join((o.get("risk") or {}).get("cwe") or []),
                        "verdict": (o.get("risk") or {}).get("verdict"),
                        "nearest_user_message_index": (o.get("nearest_user") or {}).get("message_index"),
                        "nearest_user_text_short": short((o.get("nearest_user") or {}).get("text", ""), 280),
                        "nearest_user_commands": " | ".join((o.get("nearest_user") or {}).get("commands") or []),
                        "assistant_message_index": (o.get("assistant_context") or {}).get("message_index"),
                        "assistant_block_index": (o.get("assistant_context") or {}).get("block_index"),
                        "assistant_block_type": (o.get("assistant_context") or {}).get("block_type"),
                        "assistant_candidate_text_short": short(
                            (o.get("assistant_context") or {}).get("candidate_text", ""), 280
                        ),
                    }
                )

    print(f"Input findings lines: {len(rows)}")
    print(f"Output rows: {len(outputs)}")
    print(f"Output JSONL: {args.out}")
    if args.csv_out:
        print(f"Output CSV: {args.csv_out}")


if __name__ == "__main__":
    main()
