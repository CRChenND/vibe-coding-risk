#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RISKY_BACKTRACE = ROOT / "analysis/output/risky_backtrace_all.csv"
ATTR_ENRICHED = ROOT / "analysis/output/attribution_analysis_all/attribution_enriched.csv"
CONV_TRACING = ROOT / "analysis/output/attribution_analysis_all/conversation_tracing.csv"
EMPTY_CWE_REVIEW = ROOT / "analysis/output/empty_cwe_manual_review.csv"
OUT_DIR = ROOT / "analysis/output/code_risk_analysis"

ASSISTANT_DRIVEN = {"assistant_over_implemented", "assistant_hallucinated_risk"}
USER_DRIVEN = {"user_requested_risk", "inherited_or_context_risk"}
CAUSE_ORDER = [
    "user_requested_risk",
    "assistant_over_implemented",
    "assistant_hallucinated_risk",
    "inherited_or_context_risk",
    "mixed_causality",
    "insufficient_evidence",
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k) for k in fieldnames})


def safe_int(v: str | None) -> int | None:
    if v in (None, ""):
        return None
    return int(v)


def safe_prob(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def p90(values: list[int]) -> int | None:
    if not values:
        return None
    arr = sorted(values)
    return arr[int(0.9 * (len(arr) - 1))]


def candidate_type(candidate_id: str) -> str:
    return candidate_id.split(":")[-1] if ":" in candidate_id else "unknown"


def remap_reviewed_unknown(row: dict[str, str]) -> tuple[str | None, str]:
    rationale = row["manual_rationale"]
    text = row["assistant_text"]
    label = row["manual_label"]

    if label == "not_security_risk":
        return None, "exclude_not_security"

    if rationale == "manual_high_confidence_true_risk":
        if "Authorization: Bearer" in text:
            return "CWE-798", "review_true_risk_hardcoded_token"
        if "SESSION_SECRET" in text:
            return "CWE-321", "review_true_risk_hardcoded_secret"
        if "Quick Verify" in text or "6-digit code" in text or "Password: familia123" in text:
            return "CWE-287", "review_true_risk_auth_bypass_or_weak_auth"

    if rationale == "dependency_risk_pattern":
        return "CWE-1104", "review_conditional_dependency_risk"
    if rationale == "local_http_server_exposure":
        return "CWE-200", "review_conditional_local_http_exposure"
    if rationale == "public_tunnel_exposure":
        return "CWE-200", "review_conditional_public_tunnel_exposure"
    if rationale == "sensitive_data_access_pattern":
        return "CWE-200", "review_conditional_sensitive_data_access"
    if rationale == "plaintext_http_or_local_http":
        return "CWE-319", "review_conditional_plaintext_http"
    if rationale == "privileged_execution_pattern":
        return "CWE-250", "review_conditional_privileged_execution"
    if rationale == "private_key_operation_pattern":
        return "CWE-522", "review_conditional_private_key_operation"

    # Leave anything else unresolved rather than overclaiming a deterministic mapping.
    return "CWE-UNKNOWN", "review_unresolved"


def remap_unknown_code_row(text: str) -> tuple[str | None, str]:
    t = (text or "").strip()
    tl = t.lower()

    placeholder_markers = (
        "your_api_key",
        "your api key",
        "<your_token>",
        "<your-project-id>",
        "yourdomain.com",
        "your-super-secret-key-here",
        "your_password_here",
        "your_huggingface_token_here",
        "pk_test_placeholder",
        "your_actual_client_secret_here",
        "your_actual_client_id_here",
        "your-secure-development-jwt-secret",
        "your_password",
        "your token",
        "put your real id here",
        "your-key",
    )

    # Operational cleanup / setup commands are not code-security risks in this paper framing.
    nonsig_prefixes = (
        "remove-item ",
        "rmdir ",
        "rm -rf ",
        "rm -f ",
        "rm -r ",
        "pkill -f ",
        "fuser -k ",
        "git push -f ",
        "git push --force ",
        "cp .env.example .env",
        "find app -type f | sort",
        "sqlite3 ",
        "curl -l -o ",
    )
    if tl.startswith(nonsig_prefixes):
        return None, "heuristic_exclude_operational_cleanup"
    if "minsky session delete" in tl or "find . -name \"*.html\"" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "git reset --hard" in tl or "git reset --soft" in tl or "git push origin main --force" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "xargs kill -9" in tl or "drop table if exists" in tl or "mv date_feed_back/" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "remove-item -literalpath" in tl or "rm .cursor-rules/" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if any(marker in tl for marker in placeholder_markers):
        return None, "heuristic_exclude_placeholder_template"
    if "if directory doesn't exist" in tl or "missing input validation" in tl or "hardcoded github repository" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "merge 1:" in tl and "dangerous" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "market data (critical for live pricing)" in tl or "git init # 初始化本地仓库" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "claude sonnet steps" in tl or "koalastore/" in tl or "rails_development_hosts=" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "cross origin request detected" in tl or "self-destruct" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "git init" in tl and "git remote add origin" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if '"key": "api-key"' in tl or "export memory_read=0 memory_write=0" in tl:
        return None, "heuristic_exclude_descriptive_text"
    if "wc -l docs/" in tl or "xcodebuild -project " in tl or "python app.py --debug" in tl:
        return None, "heuristic_exclude_operational_query"
    if "python app.py --with-frontend --debug" in tl or "telnet localhost " in tl:
        return None, "heuristic_exclude_operational_query"
    if "ssh aliyun " in tl or "vim /etc/hosts" in tl:
        return None, "heuristic_exclude_operational_query"
    if "rm tailwind.config.ts" in tl or "rm vite.config.ts" in tl or "rm instance/zenai.db" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "rm .env.local" in tl or "git commit -m " in tl or "cp -r " in tl or tl.startswith("rm "):
        return None, "heuristic_exclude_operational_cleanup"
    if "curl -o libheif.js " in tl or "bash -c 'echo \"dump_zsh_state()" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "pnpm start -- --reset-cache" in tl or "fix_script.sh" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "rm -rf node_modules" in tl and "package-lock.json" in tl:
        return None, "heuristic_exclude_operational_cleanup"
    if "api.github.com/repos/" in tl and "/jobs" in tl:
        return None, "heuristic_exclude_operational_query"
    if "archive/refs/heads/master.zip" in tl:
        return None, "heuristic_exclude_project_download"
    if "curl https://tally-mcp.focuslab.workers.dev/" in tl or "https://pyp9.listudyarea.workers.dev/" in tl:
        return None, "heuristic_exclude_public_endpoint_reference"
    if "vercel.app/api/jobs/cleanup" in tl or "line-gemini-faq-bot" in tl:
        return None, "heuristic_exclude_public_endpoint_reference"
    if "airalo-get-packages" in tl or "airalo-install-instructions" in tl:
        return None, "heuristic_exclude_public_endpoint_reference"
    if "https://lcfsxxncgqrhjtbfmtig.su" in tl or "downloads.nordcdn.com/configs/archives/servers/ovpn.zip" in tl:
        return None, "heuristic_exclude_public_endpoint_reference"
    if "zapabob.github.io/liltoon-pcss-extension/index.json" in tl:
        return None, "heuristic_exclude_public_endpoint_reference"

    # Explicit hardcoded auth material.
    if "authorization: bearer eyj" in tl:
        return "CWE-798", "heuristic_hardcoded_bearer_token"
    if "session_secret=" in tl and "dev-secret" in tl:
        return "CWE-321", "heuristic_hardcoded_secret"
    if 'auth_secret="' in tl and 'your_' not in tl:
        return "CWE-321", "heuristic_hardcoded_secret"
    if "jsessionid" in tl or "cookies = {" in tl:
        return "CWE-798", "heuristic_hardcoded_session_cookie"
    if '"password":"password123"' in tl or '"password":"familia123"' in tl:
        return "CWE-798", "heuristic_hardcoded_password"
    if "authorization: bearer $" in tl or "authorization: bearer $token" in tl or "authorization: bearer $admin_token" in tl:
        return "CWE-522", "heuristic_variable_bearer_token"
    if "x-api-key: $" in tl:
        return "CWE-522", "heuristic_variable_api_key"
    if "?token=" in tl and "$" not in tl:
        return "CWE-798", "heuristic_hardcoded_token_in_url"
    if "postgresql://" in tl and "@" in tl and ":" in tl.split("postgresql://", 1)[1]:
        return "CWE-798", "heuristic_hardcoded_dsn_credentials"

    # Sensitive-data access / exposure patterns.
    if "ngrok-free.app" in tl or "cloudflared" in tl:
        return "CWE-200", "heuristic_public_tunnel_exposure"
    if "http-server" in tl or "http.server" in tl or "serve -s" in tl or "--host 0.0.0.0" in tl:
        return "CWE-200", "heuristic_local_http_server_exposure"
    if "cat config.json" in tl or "cat ~/.spendo/" in tl or "get-content .env" in tl:
        return "CWE-200", "heuristic_sensitive_file_access"
    if ("docker exec" in tl or "docker compose exec" in tl) and " env " in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "find . -name \".env" in tl or "wrangler secret list" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "echo '# supabase_project_ref" in tl or "resend_api_key" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "grep database_url .env" in tl or "dir /a .env" in tl or "dir /a \".env\"" in tl or "dir /a code/.env" in tl or "dir /a code\\.env" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "cat .env" in tl or "ls -la backend/.env" in tl or "nano .env" in tl or "source .env" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "env | grep " in tl or "bool(c.minimax_api_key)" in tl or "minimax_api_key" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "mklink code\\.env .env" in tl or "mklink code/.env .env" in tl:
        return "CWE-200", "heuristic_sensitive_env_access"
    if "cat > .env << 'eof'" in tl:
        return None, "heuristic_exclude_placeholder_template"
    if "cat ~/library/application\\ support/claude/claude_desktop_config.json" in tl or "cat ~/.cache/nyord-vpn/servers.json" in tl:
        return "CWE-200", "heuristic_sensitive_file_access"
    if "find ~/.local/share/chezmoi" in tl and ("1password" in tl or "op:" in tl):
        return "CWE-200", "heuristic_sensitive_file_access"
    if "cat /users/" in tl and (".yaml" in tl or ".json" in tl or "config" in tl):
        return "CWE-200", "heuristic_sensitive_file_access"
    if "cat mcp.json" in tl or "get-childitem -path $env:userprofile" in tl:
        return "CWE-200", "heuristic_sensitive_file_access"
    if "redis-cli info" in tl or "cut -d: -f1 /etc/passwd" in tl or "/sessions" in tl:
        return "CWE-200", "heuristic_sensitive_system_info_access"
    if "middleware: got token for admin route" in tl or "cross origin request detected" in tl:
        return "CWE-200", "heuristic_sensitive_system_info_access"
    if "supabase.co/functions/v1/airalo-webhook" in tl and "iccid" in tl:
        return "CWE-200", "heuristic_sensitive_system_info_access"
    if "scp -r root@" in tl and "/pcap_" in tl:
        return "CWE-200", "heuristic_sensitive_file_transfer"
    if "find .github -type f | xargs cat" in tl:
        return None, "heuristic_exclude_operational_query"

    # Transport and exposure patterns.
    if "http://" in tl:
        return "CWE-319", "heuristic_plaintext_http"

    # Dependency and privilege patterns.
    if "npm install" in tl or "pip install" in tl or "legacy-peer-deps" in tl or "break-system-packages" in tl:
        return "CWE-1104", "heuristic_dependency_risk"
    if tl.startswith("sudo ") or " sudo " in tl:
        return "CWE-250", "heuristic_privileged_execution"
    if "scp -i " in tl or "ssh-add ~/.ssh/id_rsa" in tl or "$home/.ssh" in tl:
        return "CWE-522", "heuristic_private_key_or_credential_access"
    if "openssl req -x509 -newkey" in tl and "-nodes" in tl:
        return "CWE-522", "heuristic_unencrypted_private_key_generation"

    return "CWE-UNKNOWN", "heuristic_unresolved"


def audit_obvious_false_positive(text: str) -> tuple[bool, str]:
    tl = (text or "").strip().lower()
    if not tl:
        return False, ""

    placeholder_markers = (
        "your_api_key",
        "your_api_key_here",
        "your_flightaware_key",
        "your_amadeus_client_id",
        "your_amadeus_client_secret",
        "your_custom_llm_endpoint",
        "your_auth_domain",
        "<your supabase api key>",
        "your_base64_image_string_here",
    )
    if any(marker in tl for marker in placeholder_markers):
        return True, "placeholder_secret_example"

    if ".ssh/id_ed25519.pub" in tl or ".ssh/id_rsa.pub" in tl:
        return True, "public_key_only"

    if "pkill -f " in tl:
        return True, "process_restart_operation"
    if "rm -rf .git && git init" in tl:
        return True, "git_repo_reinit_operation"
    if "service nginx reload" in tl:
        return True, "service_reload_operation"

    return False, ""


def audit_local_only_context(text: str) -> tuple[bool, str]:
    tl = (text or "").strip().lower()
    if not tl:
        return False, ""

    if "http://localhost" in tl or "http://127.0.0.1" in tl or "host.docker.internal" in tl:
        return True, "localhost_or_host_docker_internal"

    if "python -m http.server" in tl or "npx http-server" in tl:
        return True, "local_http_server"

    return False, ""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    risky_rows = load_csv(RISKY_BACKTRACE)

    reviewed_unknown_rows = [r for r in load_csv(EMPTY_CWE_REVIEW) if candidate_type(r["candidate_id"]) in {"code_snippet", "command"}]
    reviewed_unknown_map = {r["finding_id"]: remap_reviewed_unknown(r) for r in reviewed_unknown_rows}

    code_rows: list[dict[str, str]] = []
    reviewed_resolution_rows: list[dict[str, object]] = []
    all_unknown_resolution_rows: list[dict[str, object]] = []
    for r in risky_rows:
        if candidate_type(r["candidate_id"]) not in {"code_snippet", "command"}:
            continue

        new_row = dict(r)
        if r["finding_id"] in reviewed_unknown_map:
            new_cwe, action = reviewed_unknown_map[r["finding_id"]]
            reviewed_resolution_rows.append(
                {
                    "finding_id": r["finding_id"],
                    "candidate_id": r["candidate_id"],
                    "old_cwe": r["cwe"] or "CWE-UNKNOWN",
                    "new_cwe": new_cwe or "",
                    "action": action,
                }
            )
            all_unknown_resolution_rows.append(
                {
                    "finding_id": r["finding_id"],
                    "candidate_id": r["candidate_id"],
                    "old_cwe": r["cwe"] or "CWE-UNKNOWN",
                    "new_cwe": new_cwe or "",
                    "action": action,
                    "resolution_source": "manual_review",
                }
            )
            if new_cwe is None:
                continue
            new_row["cwe"] = new_cwe
        elif not r["cwe"]:
            new_cwe, action = remap_unknown_code_row(r["assistant_candidate_text_short"])
            all_unknown_resolution_rows.append(
                {
                    "finding_id": r["finding_id"],
                    "candidate_id": r["candidate_id"],
                    "old_cwe": "CWE-UNKNOWN",
                    "new_cwe": new_cwe or "",
                    "action": action,
                    "resolution_source": "heuristic",
                }
            )
            if new_cwe is None:
                continue
            new_row["cwe"] = new_cwe

        code_rows.append(new_row)

    resolution_by_fid = {row["finding_id"]: row for row in all_unknown_resolution_rows}
    audited_rows: list[dict[str, object]] = []
    high_precision_rows: list[dict[str, str]] = []
    obvious_fp_count = 0
    local_only_count = 0
    for r in code_rows:
        text = r["assistant_candidate_text_short"]
        is_obvious_fp, obvious_reason = audit_obvious_false_positive(text)
        is_local_only, local_reason = audit_local_only_context(text)
        resolution = resolution_by_fid.get(r["finding_id"])
        audited_rows.append(
            {
                "finding_id": r["finding_id"],
                "candidate_id": r["candidate_id"],
                "chat_id": r["chat_id"],
                "verdict": r["verdict"],
                "confidence": r["confidence"],
                "cwe": r["cwe"] or "CWE-UNKNOWN",
                "resolution_source": (resolution or {}).get("resolution_source", "original"),
                "resolution_action": (resolution or {}).get("action", "original"),
                "obvious_false_positive": is_obvious_fp,
                "obvious_false_positive_reason": obvious_reason,
                "local_only_context": is_local_only,
                "local_only_context_reason": local_reason,
                "assistant_candidate_text_short": text,
            }
        )
        if is_obvious_fp:
            obvious_fp_count += 1
            continue
        if is_local_only:
            local_only_count += 1
            continue
        high_precision_rows.append(r)

    code_fids = {r["finding_id"] for r in code_rows}
    code_cwe_by_fid = {r["finding_id"]: (r["cwe"] or "CWE-UNKNOWN") for r in code_rows}

    enriched_rows = []
    for r in load_csv(ATTR_ENRICHED):
        if r["finding_id"] not in code_fids:
            continue
        new_row = dict(r)
        new_row["cwe"] = code_cwe_by_fid[r["finding_id"]]
        enriched_rows.append(new_row)
    tracing_by_fid = {r["finding_id"]: r for r in load_csv(CONV_TRACING) if r["finding_id"] in code_fids}

    candidate_type_counts = Counter(candidate_type(r["candidate_id"]) for r in risky_rows)
    attribution_distribution = Counter(r["primary_cause"] for r in enriched_rows)

    top_cwe_counter = Counter((r["cwe"] or "CWE-UNKNOWN") for r in code_rows)

    # Which CWE labels become suspect in a code-risk-only framing because they are heavily driven by security_advice?
    split_candidates_counter: dict[str, Counter[str]] = defaultdict(Counter)
    for r in risky_rows:
        cwe = r["cwe"] or "CWE-UNKNOWN"
        split_candidates_counter[cwe][candidate_type(r["candidate_id"])] += 1

    split_candidate_rows: list[dict[str, object]] = []
    for cwe, cnt in sorted(split_candidates_counter.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
        total = sum(cnt.values())
        security_advice = cnt["security_advice"]
        share = security_advice / total if total else 0.0
        if total >= 20 and share >= 0.25:
            split_candidate_rows.append(
                {
                    "cwe": cwe,
                    "total": total,
                    "code_snippet": cnt["code_snippet"],
                    "command": cnt["command"],
                    "security_advice": security_advice,
                    "security_advice_share": round(share, 4),
                }
            )

    # Manual empty-CWE review restricted to code-risk subset.
    empty_review_rows = load_csv(EMPTY_CWE_REVIEW)
    empty_review_code_subset = [r for r in empty_review_rows if candidate_type(r["candidate_id"]) in {"code_snippet", "command"}]
    empty_review_counts = Counter(r["manual_label"] for r in empty_review_code_subset)
    reviewed_resolution_counts = Counter(row["action"] for row in reviewed_resolution_rows)
    all_unknown_resolution_counts = Counter(row["action"] for row in all_unknown_resolution_rows)

    # Recompute trajectory metrics on filtered subset.
    emergence_counter: Counter[int] = Counter()
    emergence_bucket_counter: Counter[str] = Counter()
    mention_gaps: list[int] = []
    concretization_gaps: list[int] = []
    persistence_gaps: list[int] = []
    initiation = Counter()
    reg_num = 0
    reg_den = 0
    reg_by_cwe: dict[str, list[int]] = defaultdict(list)
    source_by_cwe: dict[str, Counter[str]] = defaultdict(Counter)
    event_turns: list[int] = []
    censor_turns: list[int] = []
    severity_by_gap_bucket: dict[str, Counter[str]] = defaultdict(Counter)
    per_sample_rows: list[dict[str, object]] = []

    def gap_bucket(gap: int | None) -> str:
        if gap is None:
            return "missing"
        if gap <= 0:
            return "<=0"
        if gap == 1:
            return "1"
        if 2 <= gap <= 3:
            return "2-3"
        if 4 <= gap <= 7:
            return "4-7"
        if 8 <= gap <= 15:
            return "8-15"
        return "16+"

    for e in enriched_rows:
        fid = e["finding_id"]
        t = tracing_by_fid.get(fid, {})
        cause = e["primary_cause"]
        severity = (e.get("severity") or "none").lower()
        ar = safe_int(t.get("assistant_risk_turn"))
        fm = safe_int(t.get("first_mention_turn"))
        fc = safe_int(t.get("first_concretization_turn"))
        fp = safe_int(t.get("first_persistence_turn"))

        mg = (ar - fm) if (ar is not None and fm is not None) else None
        cg = (ar - fc) if (ar is not None and fc is not None) else None
        pg = (ar - fp) if (ar is not None and fp is not None) else None

        if fc is not None:
            emergence_counter[fc] += 1
            event_turns.append(fc)
            if fc <= 1:
                emergence_bucket_counter["0-1"] += 1
            elif fc <= 3:
                emergence_bucket_counter["2-3"] += 1
            elif fc <= 7:
                emergence_bucket_counter["4-7"] += 1
            elif fc <= 15:
                emergence_bucket_counter["8-15"] += 1
            else:
                emergence_bucket_counter["16+"] += 1
        elif ar is not None:
            censor_turns.append(ar)

        if mg is not None:
            mention_gaps.append(mg)
        if cg is not None:
            concretization_gaps.append(cg)
        if pg is not None:
            persistence_gaps.append(pg)

        if cause in ASSISTANT_DRIVEN:
            initiation["assistant_first"] += 1
        elif cause in USER_DRIVEN:
            initiation["user_or_context_first"] += 1
        else:
            initiation["unclear"] += 1

        if cause in ASSISTANT_DRIVEN and ar is not None:
            reg_den += 1
            reg = int(fc is not None and fc < ar)
            reg_num += reg
            for cwe in (e.get("cwe") or "").split("|"):
                if cwe:
                    reg_by_cwe[cwe].append(reg)

        src = "assistant_driven" if cause in ASSISTANT_DRIVEN else ("user_driven" if cause in USER_DRIVEN else "unclear")
        for cwe in (e.get("cwe") or "").split("|"):
            if cwe:
                source_by_cwe[cwe][src] += 1

        severity_by_gap_bucket[gap_bucket(mg)][severity] += 1
        per_sample_rows.append(
            {
                "finding_id": fid,
                "primary_cause": cause,
                "severity": severity,
                "assistant_risk_turn": ar,
                "first_mention_turn": fm,
                "first_concretization_turn": fc,
                "first_persistence_turn": fp,
                "mention_gap": mg,
                "concretization_gap": cg,
                "persistence_gap": pg,
                "cwe": e.get("cwe", ""),
            }
        )

    emergence_total = sum(emergence_counter.values())
    emergence_bucket_rows = [
        {"turn_bucket": bucket, "count": emergence_bucket_counter[bucket], "probability": safe_prob(emergence_bucket_counter[bucket], emergence_total)}
        for bucket in ["0-1", "2-3", "4-7", "8-15", "16+"]
    ]
    emergence_turn_rows = [
        {"turn": turn, "count": count, "probability": safe_prob(count, emergence_total)}
        for turn, count in sorted(emergence_counter.items())
    ]

    regression_cwe_rows: list[dict[str, object]] = []
    for cwe, vals in sorted(reg_by_cwe.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(vals) < 5:
            continue
        regression_cwe_rows.append(
            {
                "cwe": cwe,
                "n_assistant_driven": len(vals),
                "n_regressed": sum(vals),
                "regression_rate": safe_prob(sum(vals), len(vals)),
            }
        )

    source_cwe_rows: list[dict[str, object]] = []
    for cwe, cnt in sorted(source_by_cwe.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
        total = sum(cnt.values())
        source_cwe_rows.append(
            {
                "cwe": cwe,
                "total": total,
                "assistant_driven": cnt["assistant_driven"],
                "assistant_driven_ratio": safe_prob(cnt["assistant_driven"], total),
                "user_driven": cnt["user_driven"],
                "user_driven_ratio": safe_prob(cnt["user_driven"], total),
                "unclear": cnt["unclear"],
                "unclear_ratio": safe_prob(cnt["unclear"], total),
            }
        )

    # Temporal survival curve.
    max_turn = 0
    if event_turns:
        max_turn = max(max_turn, max(event_turns))
    if censor_turns:
        max_turn = max(max_turn, max(censor_turns))
    event_counter = Counter(event_turns)
    censor_counter = Counter(censor_turns)
    temporal_rows: list[dict[str, object]] = []
    survival = 1.0
    cumulative_events = 0
    total_rows = len(enriched_rows)
    for turn in range(max_turn + 1):
        at_risk = sum(1 for et in event_turns if et >= turn) + sum(1 for ct in censor_turns if ct >= turn)
        events = event_counter[turn]
        censored = censor_counter[turn]
        cumulative_events += events
        hazard = (events / at_risk) if at_risk else 0.0
        if at_risk and events:
            survival *= 1.0 - hazard
        temporal_rows.append(
            {
                "turn": turn,
                "at_risk": at_risk,
                "new_risk_events": events,
                "new_censored": censored,
                "risk_probability_turn": round(events / total_rows, 6) if total_rows else 0.0,
                "hazard": round(hazard, 6),
                "survival_remaining_secure": round(survival, 6),
                "cumulative_risk_probability": round(cumulative_events / total_rows, 6) if total_rows else 0.0,
            }
        )

    attribution_summary = {
        "n_all_risky_rows": len(risky_rows),
        "n_code_risk_rows": len(code_rows),
        "candidate_type_counts": dict(candidate_type_counts),
        "reviewed_unknown_resolution": {
            "n_reviewed_code_unknown_rows": len(reviewed_unknown_rows),
            "n_excluded_as_not_security": reviewed_resolution_counts["exclude_not_security"],
            "resolution_counts": dict(reviewed_resolution_counts),
        },
        "all_unknown_resolution": {
            "n_original_unknown_code_rows": len(all_unknown_resolution_rows),
            "n_excluded_as_not_security": sum(1 for row in all_unknown_resolution_rows if not row["new_cwe"]),
            "n_remapped_to_deterministic_cwe": sum(1 for row in all_unknown_resolution_rows if row["new_cwe"] and row["new_cwe"] != "CWE-UNKNOWN"),
            "n_residual_unknown": sum(1 for row in all_unknown_resolution_rows if row["new_cwe"] == "CWE-UNKNOWN"),
            "resolution_counts": dict(all_unknown_resolution_counts),
        },
        "attribution_distribution": {
            cause: {"count": attribution_distribution[cause], "ratio": safe_prob(attribution_distribution[cause], len(enriched_rows))}
            for cause in CAUSE_ORDER
        },
        "top_cwe": [{"cwe": cwe, "count": count} for cwe, count in top_cwe_counter.most_common(15)],
        "split_candidates": split_candidate_rows,
        "empty_cwe_review_code_subset": {
            "n_reviewed_rows": len(empty_review_code_subset),
            "true_security_risk": {"count": empty_review_counts["true_security_risk"], "ratio": safe_prob(empty_review_counts["true_security_risk"], len(empty_review_code_subset))},
            "conditional_security_risk": {"count": empty_review_counts["conditional_security_risk"], "ratio": safe_prob(empty_review_counts["conditional_security_risk"], len(empty_review_code_subset))},
            "not_security_risk": {"count": empty_review_counts["not_security_risk"], "ratio": safe_prob(empty_review_counts["not_security_risk"], len(empty_review_code_subset))},
        },
        "audit": {
            "n_obvious_false_positives": obvious_fp_count,
            "n_local_only_context_rows": local_only_count,
            "n_high_precision_rows": len(high_precision_rows),
            "high_precision_ratio_vs_code_risk": safe_prob(len(high_precision_rows), len(code_rows)),
        },
    }

    trajectory_summary = {
        "n_code_risk_rows": len(enriched_rows),
        "risk_emergence_position": {
            "covered_rows": emergence_total,
            "bucket_distribution": emergence_bucket_rows,
            "top_turns": sorted(emergence_turn_rows, key=lambda x: x["count"], reverse=True)[:25],
        },
        "risk_escalation_depth": {
            "mention_gap": {"count": len(mention_gaps), "median": statistics.median(mention_gaps) if mention_gaps else None, "p90": p90(mention_gaps)},
            "concretization_gap": {"count": len(concretization_gaps), "median": statistics.median(concretization_gaps) if concretization_gaps else None, "p90": p90(concretization_gaps)},
            "persistence_gap": {"count": len(persistence_gaps), "median": statistics.median(persistence_gaps) if persistence_gaps else None, "p90": p90(persistence_gaps)},
        },
        "user_vs_assistant_initiation": {k: {"count": v, "ratio": safe_prob(v, len(enriched_rows))} for k, v in initiation.items()},
        "assistant_security_regression_rate_proxy": {
            "numerator": reg_num,
            "denominator_assistant_driven": reg_den,
            "rate": safe_prob(reg_num, reg_den),
        },
        "temporal_security_degradation": {
            "covered_events": len(event_turns),
            "covered_censored": len(censor_turns),
            "max_turn_in_curve": max_turn,
            "final_survival_remaining_secure": temporal_rows[-1]["survival_remaining_secure"] if temporal_rows else None,
        },
    }

    (OUT_DIR / "attribution_summary.json").write_text(json.dumps(attribution_summary, indent=2), encoding="utf-8")
    (OUT_DIR / "trajectory_summary.json").write_text(json.dumps(trajectory_summary, indent=2), encoding="utf-8")
    write_csv(OUT_DIR / "top_cwe_counts.csv", [{"cwe": cwe, "count": count} for cwe, count in top_cwe_counter.most_common()], ["cwe", "count"])
    write_csv(OUT_DIR / "split_candidates.csv", split_candidate_rows, ["cwe", "total", "code_snippet", "command", "security_advice", "security_advice_share"])
    write_csv(OUT_DIR / "reviewed_unknown_resolution.csv", reviewed_resolution_rows, ["finding_id", "candidate_id", "old_cwe", "new_cwe", "action"])
    write_csv(OUT_DIR / "all_unknown_resolution.csv", all_unknown_resolution_rows, ["finding_id", "candidate_id", "old_cwe", "new_cwe", "action", "resolution_source"])
    write_csv(
        OUT_DIR / "code_risk_audit.csv",
        audited_rows,
        [
            "finding_id",
            "candidate_id",
            "chat_id",
            "verdict",
            "confidence",
            "cwe",
            "resolution_source",
            "resolution_action",
            "obvious_false_positive",
            "obvious_false_positive_reason",
            "local_only_context",
            "local_only_context_reason",
            "assistant_candidate_text_short",
        ],
    )
    write_csv(
        OUT_DIR / "high_precision_code_risk_rows.csv",
        high_precision_rows,
        list(code_rows[0].keys()) if code_rows else [],
    )
    write_csv(OUT_DIR / "risk_emergence_bucket_distribution.csv", emergence_bucket_rows, ["turn_bucket", "count", "probability"])
    write_csv(OUT_DIR / "risk_emergence_turn_distribution.csv", emergence_turn_rows, ["turn", "count", "probability"])
    write_csv(OUT_DIR / "assistant_regression_by_cwe.csv", regression_cwe_rows, ["cwe", "n_assistant_driven", "n_regressed", "regression_rate"])
    write_csv(OUT_DIR / "attribution_source_by_cwe.csv", source_cwe_rows, ["cwe", "total", "assistant_driven", "assistant_driven_ratio", "user_driven", "user_driven_ratio", "unclear", "unclear_ratio"])
    write_csv(OUT_DIR / "temporal_security_degradation_curve.csv", temporal_rows, ["turn", "at_risk", "new_risk_events", "new_censored", "risk_probability_turn", "hazard", "survival_remaining_secure", "cumulative_risk_probability"])
    write_csv(OUT_DIR / "risk_escalation_samples.csv", per_sample_rows, ["finding_id", "primary_cause", "severity", "assistant_risk_turn", "first_mention_turn", "first_concretization_turn", "first_persistence_turn", "mention_gap", "concretization_gap", "persistence_gap", "cwe"])

    print(f"Wrote code-risk analysis to {OUT_DIR}")


if __name__ == "__main__":
    main()
