#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = ROOT / "analysis/output/risk_dataset_export_350"
DEFAULT_SITE_DATA = ROOT / "risk_explorer/data/site_data.json"
DEFAULT_RISKY_ROWS = ROOT / "analysis/output/risky_backtrace_all.csv"
DEFAULT_ATTRIBUTION = ROOT / "analysis/output/attribution_analysis_all/attribution_enriched.csv"
DEFAULT_TRACING = ROOT / "analysis/output/attribution_analysis_all/conversation_tracing.csv"
DEFAULT_BACKTRACE = ROOT / "analysis/output/risky_backtrace_all.jsonl"
DEFAULT_JUDGE_OUTPUT = ROOT / "analysis/output/judge_findings_all.jsonl"
DEFAULT_CHATS_DIR = ROOT / "data/chats"

CWE_EXPLANATIONS = {
    "CWE-312": "Sensitive information is written directly into code or configuration in plain text, which means anyone who sees the file can reuse it.",
    "CWE-79": "Untrusted content may be rendered as executable HTML or JavaScript, which can let attacker-controlled script run in a browser.",
    "CWE-200": "The snippet exposes information that should usually stay internal, such as secrets, config values, internal endpoints, or sensitive environment data.",
    "CWE-20": "The code or command accepts input too loosely, which can let malformed or malicious values reach sensitive behavior.",
    "CWE-327": "The security primitive is weak, placeholder-like, or not appropriate for protecting real systems.",
    "CWE-459": "Temporary or debug-oriented artifacts can stay around longer than intended, creating exposure or unsafe leftovers.",
    "CWE-522": "Credentials or key material are handled in a way that does not adequately protect them.",
    "CWE-78": "Shell execution or command composition is risky enough that user-controlled values could trigger unsafe system behavior.",
    "CWE-798": "A secret, password, token, or credential-like value is embedded directly in the snippet instead of being safely injected at runtime.",
    "CWE-321": "A cryptographic or session secret is hard-coded, so code exposure becomes key exposure.",
    "CWE-319": "Sensitive data is sent over plaintext or insecure transport, making interception easier.",
    "CWE-1104": "The command pulls in dependencies or packages in a way that raises supply-chain or provenance concerns.",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export the risky-row dataset to CSV plus per-row source files.")
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--site-data", type=Path, default=DEFAULT_SITE_DATA)
    p.add_argument("--risky-rows", "--high-precision", dest="risky_rows", type=Path, default=DEFAULT_RISKY_ROWS)
    p.add_argument("--attribution", type=Path, default=DEFAULT_ATTRIBUTION)
    p.add_argument("--tracing", type=Path, default=DEFAULT_TRACING)
    p.add_argument("--backtrace", type=Path, default=DEFAULT_BACKTRACE)
    p.add_argument("--judge-output", type=Path, default=DEFAULT_JUDGE_OUTPUT)
    p.add_argument("--chats-dir", type=Path, default=DEFAULT_CHATS_DIR)
    return p.parse_args()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_judge_output(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                decoder = json.JSONDecoder()
                obj, _ = decoder.raw_decode(line)
            candidate_id = str(obj.get("candidate_id", ""))
            if candidate_id:
                out[candidate_id] = obj
    return out


def read_raw_chat_bytes(chats_dir: Path, chat_id: str) -> bytes:
    chat_path = chats_dir / f"{chat_id}.md.json"
    if not chat_path.exists():
        raise FileNotFoundError(f"Missing source chat file: {chat_path}")
    return chat_path.read_bytes()


def first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return ""


def normalize_turn(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value)


def stringify_keep_zero(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def cwe_reason(cwe: str) -> str:
    if not cwe:
        return ""
    return CWE_EXPLANATIONS.get(cwe, "Concrete software security weakness used in the analysis.")


def main() -> None:
    args = parse_args()

    site_data = load_json(args.site_data)
    attribution_rows = load_csv(args.attribution)
    tracing_rows = load_csv(args.tracing)
    backtrace_rows = load_jsonl(args.backtrace)
    judge_rows = load_judge_output(args.judge_output)
    attribution_by_id = {
        row["finding_id"]: row
        for row in attribution_rows
        if row.get("finding_id")
    }

    findings_by_id = {
        str(row.get("finding_id")): row
        for row in site_data.get("findings", [])
        if isinstance(row, dict) and row.get("finding_id")
    }
    tracing_by_id = {
        row["finding_id"]: row
        for row in tracing_rows
        if row.get("finding_id")
    }
    backtrace_by_id = {
        str(row.get("finding_id")): row
        for row in backtrace_rows
        if row.get("finding_id")
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    source_dir = args.out_dir / "source_files"
    source_dir.mkdir(parents=True, exist_ok=True)

    csv_path = args.out_dir / "risk_dataset.csv"
    manifest_path = args.out_dir / "manifest.json"
    missing = {"site_data": 0, "backtrace": 0, "tracing": 0}
    manifest_rows: list[dict[str, Any]] = []

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "index",
                "cwe",
                "cwe_reason",
                "attribution_domain",
                "risk_snippets_content",
                "risk_snippets_appear_turn",
            ],
        )
        writer.writeheader()

        findings = [row for row in site_data.get("findings", []) if isinstance(row, dict)]

        for index, site_row in enumerate(findings, start=1):
            finding_id = str(site_row.get("finding_id", ""))
            candidate_id = str(site_row.get("candidate_id", ""))
            attr_row = attribution_by_id.get(finding_id, {})
            site_row = findings_by_id.get(finding_id) or dict(site_row)
            backtrace_row = backtrace_by_id.get(finding_id) or {}
            tracing_row = tracing_by_id.get(finding_id) or {}
            judge_row = judge_rows.get(candidate_id, {})

            if not site_row:
                missing["site_data"] += 1
            if not backtrace_row:
                missing["backtrace"] += 1
            if not tracing_row:
                missing["tracing"] += 1

            assistant_context = backtrace_row.get("assistant_context") if isinstance(backtrace_row, dict) else {}
            if not isinstance(assistant_context, dict):
                assistant_context = {}

            risk = backtrace_row.get("risk") if isinstance(backtrace_row, dict) else {}
            if not isinstance(risk, dict):
                risk = {}

            cwe = first_nonempty(
                site_row.get("cwe"),
                (judge_row.get("cwe") or [None])[0] if isinstance(judge_row.get("cwe"), list) and judge_row.get("cwe") else "",
                attr_row.get("cwe"),
                site_row.get("cwe"),
                risk.get("cwe")[0] if isinstance(risk.get("cwe"), list) and risk.get("cwe") else "",
            )
            attribution_domain = first_nonempty(attr_row.get("primary_cause"), site_row.get("primary_cause"))
            risk_snippet_content = first_nonempty(
                assistant_context.get("candidate_text"),
                site_row.get("assistant_candidate_preview"),
                site_row.get("assistant_candidate_text_short"),
            )
            judge_reasoning = str((judge_row.get("details") or {}).get("reasoning", "")).strip()
            risk_snippets_appear_turn = first_nonempty(
                site_row.get("assistant_risk_turn"),
                assistant_context.get("message_index"),
                tracing_row.get("assistant_risk_turn"),
                site_row.get("assistant_message_index"),
            )

            writer.writerow(
                {
                    "index": index,
                    "cwe": cwe,
                    "cwe_reason": judge_reasoning or cwe_reason(cwe),
                    "attribution_domain": attribution_domain,
                    "risk_snippets_content": risk_snippet_content,
                    "risk_snippets_appear_turn": normalize_turn(risk_snippets_appear_turn),
                }
            )

            manifest_rows.append(
                {
                    "index": index,
                    "finding_id": finding_id,
                    "candidate_id": candidate_id,
                    "chat_id": str(site_row.get("chat_id") or ""),
                    "severity": str(site_row.get("severity") or ""),
                    "confidence": str(site_row.get("confidence") or ""),
                    "cwe": cwe,
                    "cwe_reason": judge_reasoning or cwe_reason(cwe),
                    "attribution_domain": attribution_domain,
                    "risk_snippets_content": risk_snippet_content,
                    "risk_snippets_appear_turn": normalize_turn(risk_snippets_appear_turn),
                    "assistant_message_index": stringify_keep_zero(site_row.get("assistant_message_index")),
                    "assistant_block_index": stringify_keep_zero(site_row.get("assistant_block_index")),
                    "assistant_block_type": stringify_keep_zero(site_row.get("assistant_block_type")),
                    "nearest_user_message_index": stringify_keep_zero(site_row.get("nearest_user_message_index")),
                    "nearest_user_text_short": stringify_keep_zero(site_row.get("nearest_user_text_short")),
                    "assistant_candidate_text_short": stringify_keep_zero(site_row.get("assistant_candidate_text_short")),
                    "dedup_count": site_row.get("dedup_count") or 1,
                    "dedup_finding_ids": site_row.get("dedup_finding_ids") or [finding_id],
                    "source_file": f"source_files/{index}.json",
                }
            )

            source_bytes = read_raw_chat_bytes(args.chats_dir, str(site_row.get("chat_id") or ""))
            (source_dir / f"{index}.json").write_bytes(source_bytes)

    manifest_path.write_text(json.dumps(manifest_rows, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Exported {len(findings)} rows")
    print(f"CSV: {csv_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Source files: {source_dir}")
    print(f"Missing joins: {missing}")


if __name__ == "__main__":
    main()
