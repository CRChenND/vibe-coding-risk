#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson
from tqdm import tqdm


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Static analysis: per-repo scan with CodeQL first, Semgrep fallback, plus secret scanners.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--summary-out", type=Path, default=None)
    p.add_argument(
        "--repos-root",
        type=Path,
        required=True,
        help="Local repo root. Supported layouts: owner/repo or owner__repo.",
    )
    p.add_argument("--codeql-db-root", type=Path, default=Path("analysis/output/codeql_dbs"))
    p.add_argument("--codeql-sarif-root", type=Path, default=Path("analysis/output/codeql_sarif"))
    p.add_argument(
        "--findsecbugs-jar",
        type=Path,
        default=Path("analysis/tools/findsecbugs/findsecbugs-plugin.jar"),
        help="Path to FindSecBugs plugin jar for SpotBugs.",
    )
    p.add_argument("--semgrep-config", type=str, default="auto")
    p.add_argument("--gitleaks-report-root", type=Path, default=Path("analysis/output/gitleaks_reports"))
    p.add_argument("--limit", type=int, default=0, help="Limit input candidate lines.")
    p.add_argument("--timeout-sec", type=int, default=300)
    p.add_argument("--resume", dest="resume", action="store_true", default=True, help="Resume from previous output.")
    p.add_argument("--no-resume", dest="resume", action="store_false", help="Do not resume; overwrite output.")
    p.add_argument(
        "--resume-state",
        type=Path,
        default=None,
        help="Optional repo checkpoint file. Default: <out>.repos_done.jsonl",
    )
    return p.parse_args()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clip(s: str, n: int = 240) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def has_cmd(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True, text=True).returncode == 0


def severity_from_level(level: str | None) -> str:
    lv = (level or "").lower()
    if lv in {"error"}:
        return "high"
    if lv in {"warning", "warn"}:
        return "medium"
    if lv in {"note", "info"}:
        return "low"
    return "medium"


def semgrep_severity_to_schema(sev: str | None) -> str:
    x = (sev or "").lower()
    if x in {"error", "high"}:
        return "high"
    if x in {"warning", "medium"}:
        return "medium"
    if x in {"info", "low"}:
        return "low"
    return "medium"


def extract_cwe(obj: Any) -> list[str]:
    def norm(token: str) -> str | None:
        m = re.search(r"CWE-\d+", token)
        return m.group(0) if m else None

    out: list[str] = []
    if isinstance(obj, str):
        if "CWE-" in obj:
            n = norm(obj)
            if n:
                out.append(n)
            for tok in obj.replace(",", " ").split():
                n = norm(tok)
                if n:
                    out.append(n)
    elif isinstance(obj, list):
        for it in obj:
            out.extend(extract_cwe(it))
    elif isinstance(obj, dict):
        for _, v in obj.items():
            out.extend(extract_cwe(v))
    return sorted(set(x.strip() for x in out if x.strip().startswith("CWE-")))


def load_candidates(path: Path, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("rb") as f:
        for i, line in enumerate(f):
            if limit > 0 and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            rows.append(orjson.loads(line))
    return rows


def default_resume_state_path(out_file: Path) -> Path:
    return Path(f"{out_file}.repos_done.jsonl")


def load_done_repos_from_state(path: Path) -> set[str]:
    done: set[str] = set()
    if not path.exists():
        return done
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            repo = obj.get("repo_full_name")
            if isinstance(repo, str) and repo:
                done.add(repo)
    return done


def load_done_repos_from_output(path: Path) -> set[str]:
    done: set[str] = set()
    if not path.exists():
        return done
    with path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
            except Exception:  # noqa: BLE001
                continue
            details = obj.get("details") or {}
            repo = details.get("repo_full_name")
            if isinstance(repo, str) and repo:
                done.add(repo)
    return done


def repo_path_from_full_name(repos_root: Path, full_name: str) -> Path | None:
    if "/" not in full_name:
        return None
    owner, repo = full_name.split("/", 1)
    cands = [
        repos_root / owner / repo,
        repos_root / f"{owner}__{repo}",
        repos_root / full_name,
    ]
    for p in cands:
        if p.exists() and p.is_dir():
            return p
    return None


def detect_repo_language(repo_path: Path) -> str | None:
    ext_counter: Counter[str] = Counter()
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        if ".git" in p.parts:
            continue
        ext = p.suffix.lower()
        if ext:
            ext_counter[ext] += 1

    ext_to_lang = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".java": "java",
        ".go": "go",
        ".cs": "csharp",
        ".c": "cpp",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".rb": "ruby",
    }
    lang_counter: Counter[str] = Counter()
    for ext, cnt in ext_counter.items():
        lang = ext_to_lang.get(ext)
        if lang:
            lang_counter[lang] += cnt
    if not lang_counter:
        return None
    return lang_counter.most_common(1)[0][0]


def detect_repo_languages(repo_path: Path) -> set[str]:
    exts: Counter[str] = Counter()
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        if ".git" in p.parts:
            continue
        if p.suffix:
            exts[p.suffix.lower()] += 1

    lang_set: set[str] = set()
    if any(ext in exts for ext in [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"]):
        lang_set.add("cpp")
    if any(ext in exts for ext in [".py"]):
        lang_set.add("python")
    if any(ext in exts for ext in [".go"]):
        lang_set.add("go")
    if any(ext in exts for ext in [".sh", ".bash", ".zsh", ".ksh"]):
        lang_set.add("shell")
    if any(ext in exts for ext in [".js", ".jsx", ".ts", ".tsx", ".vue"]):
        lang_set.add("javascript")
    if any(ext in exts for ext in [".java"]):
        lang_set.add("java")
    return lang_set


def codeql_suite_for_lang(lang: str) -> str | None:
    mapping = {
        "python": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "java": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-and-quality.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls",
    }
    return mapping.get(lang)


def parse_codeql_sarif(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = []
    for run in data.get("runs", []):
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rid = r.get("id")
            if isinstance(rid, str):
                rules[rid] = r

        for res in run.get("results", []) or []:
            rule_id = str(res.get("ruleId", "CODEQL"))
            level = res.get("level")
            message = (((res.get("message") or {}).get("text")) or "").strip()
            loc = ""
            locs = res.get("locations") or []
            if locs:
                art = ((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                if isinstance(art, str):
                    loc = art

            rule = rules.get(rule_id, {})
            cwe = extract_cwe(rule.get("properties") or {})
            if not cwe:
                cwe = extract_cwe((rule.get("properties") or {}).get("tags"))

            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": severity_from_level(level),
                    "confidence": 0.85,
                    "cwe": cwe,
                    "quote": clip(message or rule_id, 240),
                    "reason": clip(f"CodeQL finding in {loc}" if loc else "CodeQL finding", 300),
                }
            )
    return findings


def run_codeql(repo_path: Path, lang: str, db_root: Path, sarif_root: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    suite = codeql_suite_for_lang(lang)
    if not suite:
        return [], f"unsupported_language:{lang}"

    key = repo_path.name
    db_path = db_root / key
    sarif_path = sarif_root / f"{key}.sarif"
    db_root.mkdir(parents=True, exist_ok=True)
    sarif_root.mkdir(parents=True, exist_ok=True)

    create_cmd = [
        "codeql",
        "database",
        "create",
        str(db_path),
        "--overwrite",
        "--language",
        lang,
        "--source-root",
        str(repo_path),
    ]
    analyze_cmd = [
        "codeql",
        "database",
        "analyze",
        str(db_path),
        suite,
        "--format",
        "sarif-latest",
        "--output",
        str(sarif_path),
        "--rerun",
    ]

    try:
        subprocess.run(create_cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
        subprocess.run(analyze_cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or e.stdout or "").strip()
        return [], f"codeql_failed:{clip(stderr, 240)}"
    except subprocess.TimeoutExpired:
        return [], "codeql_timeout"

    if not sarif_path.exists():
        return [], "codeql_no_sarif"

    try:
        return parse_codeql_sarif(sarif_path), None
    except Exception as e:  # noqa: BLE001
        return [], f"codeql_parse_failed:{e}"


def parse_semgrep_json_output(stdout: str) -> list[dict[str, Any]]:
    data = json.loads(stdout)
    out: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        check_id = str(r.get("check_id", "SEMGREP"))
        extra = r.get("extra") or {}
        message = str(extra.get("message", check_id))
        meta = extra.get("metadata") or {}
        cwe = extract_cwe(meta.get("cwe") or meta)
        sev = semgrep_severity_to_schema(extra.get("severity"))
        path = str(r.get("path", ""))
        out.append(
            {
                "rule_id": check_id,
                "severity": sev,
                "confidence": 0.8,
                "cwe": cwe,
                "quote": clip(message, 240),
                "reason": clip(f"Semgrep finding in {path}" if path else "Semgrep finding", 300),
            }
        )
    return out


def run_semgrep_on_repo(repo_path: Path, config: str, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        str(repo_path),
    ]
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.CalledProcessError as e:
        # semgrep may return non-zero with findings; parse stdout if possible
        stdout = e.stdout or ""
        if stdout.strip().startswith("{"):
            try:
                return parse_semgrep_json_output(stdout), None
            except Exception:
                pass
        stderr = (e.stderr or e.stdout or "").strip()
        return [], f"semgrep_failed:{clip(stderr, 240)}"
    except subprocess.TimeoutExpired:
        return [], "semgrep_timeout"

    try:
        return parse_semgrep_json_output(proc.stdout), None
    except Exception as e:  # noqa: BLE001
        return [], f"semgrep_json_failed:{e}"


def semgrep_ext(language_hint: str | None) -> str:
    lang = (language_hint or "").lower()
    mapping = {
        "python": ".py",
        "javascript": ".js",
        "js": ".js",
        "typescript": ".ts",
        "ts": ".ts",
        "java": ".java",
        "go": ".go",
        "csharp": ".cs",
        "cpp": ".cpp",
        "c": ".c",
        "ruby": ".rb",
        "php": ".php",
        "rust": ".rs",
        "kotlin": ".kt",
        "swift": ".swift",
        "shell": ".sh",
        "bash": ".sh",
    }
    return mapping.get(lang, ".txt")


def run_semgrep_on_snippet(content: str, language_hint: str | None, config: str, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    ext = semgrep_ext(language_hint)
    with tempfile.TemporaryDirectory(prefix="vibe-semgrep-") as td:
        p = Path(td) / f"snippet{ext}"
        p.write_text(content, encoding="utf-8")
        cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet", str(p)]
        try:
            proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
        except subprocess.CalledProcessError as e:
            stdout = e.stdout or ""
            if stdout.strip().startswith("{"):
                try:
                    return parse_semgrep_json_output(stdout), None
                except Exception:
                    pass
            stderr = (e.stderr or e.stdout or "").strip()
            return [], f"semgrep_failed:{clip(stderr, 240)}"
        except subprocess.TimeoutExpired:
            return [], "semgrep_timeout"

        try:
            return parse_semgrep_json_output(proc.stdout), None
        except Exception as e:  # noqa: BLE001
            return [], f"semgrep_json_failed:{e}"


def run_gitleaks(repo_path: Path, report_root: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    report_root.mkdir(parents=True, exist_ok=True)
    report_path = report_root / f"{repo_path.name}.json"

    cmds = [
        [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",
            "--no-banner",
        ],
        [
            "gitleaks",
            "dir",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",
            "--no-banner",
        ],
    ]

    last_err = "gitleaks_no_result"
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_sec)
            if report_path.exists():
                break
        except subprocess.TimeoutExpired:
            return [], "gitleaks_timeout"

    if not report_path.exists():
        return [], last_err

    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [], f"gitleaks_parse_failed:{e}"

    if not isinstance(raw, list):
        return [], None

    findings: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("RuleID", "GITLEAKS"))
        desc = str(item.get("Description", rid))
        file_ = str(item.get("File", ""))
        line_ = str(item.get("StartLine", ""))
        quote = f"{rid}: {desc}"
        reason = f"Gitleaks secret finding in {file_}:{line_}" if file_ else "Gitleaks secret finding"
        findings.append(
            {
                "rule_id": f"gitleaks:{rid}",
                "severity": "high",
                "confidence": 0.9,
                "cwe": ["CWE-798", "CWE-200"],
                "quote": clip(quote, 240),
                "reason": clip(reason, 300),
            }
        )

    return findings, None


def run_detect_secrets(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = ["detect-secrets", "scan", "--all-files", str(repo_path)]
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or e.stdout or "").strip()
        return [], f"detect_secrets_failed:{clip(stderr, 240)}"
    except subprocess.TimeoutExpired:
        return [], "detect_secrets_timeout"

    txt = proc.stdout.strip()
    start = txt.find("{")
    if start < 0:
        return [], "detect_secrets_no_json"

    try:
        data = json.loads(txt[start:])
    except Exception as e:  # noqa: BLE001
        return [], f"detect_secrets_parse_failed:{e}"

    results = data.get("results") or {}
    if not isinstance(results, dict):
        return [], None

    findings: list[dict[str, Any]] = []
    for file_, arr in results.items():
        if not isinstance(arr, list):
            continue
        for hit in arr:
            if not isinstance(hit, dict):
                continue
            plugin = str(hit.get("type") or hit.get("plugin_name") or "detect-secrets")
            line_no = str(hit.get("line_number", ""))
            reason = f"detect-secrets finding in {file_}:{line_no}" if file_ else "detect-secrets finding"
            findings.append(
                {
                    "rule_id": f"detect-secrets:{plugin}",
                    "severity": "high",
                    "confidence": 0.85,
                    "cwe": ["CWE-798", "CWE-200"],
                    "quote": clip(plugin, 240),
                    "reason": clip(reason, 300),
                }
            )

    return findings, None


def run_bandit(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = ["bandit", "-r", str(repo_path), "-f", "json", "-q"]
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
        stdout = proc.stdout
    except subprocess.CalledProcessError as e:
        # Bandit commonly exits non-zero when findings exist.
        stdout = (e.stdout or "").strip()
        if not stdout:
            stderr = (e.stderr or "").strip()
            return [], f"bandit_failed:{clip(stderr, 240)}"
    except subprocess.TimeoutExpired:
        return [], "bandit_timeout"

    try:
        data = json.loads(stdout)
    except Exception as e:  # noqa: BLE001
        return [], f"bandit_parse_failed:{e}"

    out: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        issue_sev = str(r.get("issue_severity", "MEDIUM")).lower()
        sev = "medium"
        if issue_sev == "high":
            sev = "high"
        elif issue_sev == "low":
            sev = "low"

        cwe_data = r.get("issue_cwe")
        cwe: list[str] = []
        if isinstance(cwe_data, dict):
            cid = cwe_data.get("id")
            if isinstance(cid, int):
                cwe = [f"CWE-{cid}"]
            elif isinstance(cid, str) and cid.isdigit():
                cwe = [f"CWE-{cid}"]

        test_id = str(r.get("test_id", "BANDIT"))
        text = str(r.get("issue_text", test_id))
        file_ = str(r.get("filename", ""))
        line_ = str(r.get("line_number", ""))
        out.append(
            {
                "rule_id": f"bandit:{test_id}",
                "severity": sev,
                "confidence": 0.8,
                "cwe": cwe,
                "quote": clip(text, 240),
                "reason": clip(f"Bandit finding in {file_}:{line_}" if file_ else "Bandit finding", 300),
            }
        )
    return out, None


def run_gosec(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = ["gosec", "-fmt", "json", "./..."]
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(repo_path),
        )
        stdout = proc.stdout
    except subprocess.CalledProcessError as e:
        # gosec may return non-zero with findings
        stdout = (e.stdout or "").strip()
        if not stdout:
            stderr = (e.stderr or "").strip()
            return [], f"gosec_failed:{clip(stderr, 240)}"
    except subprocess.TimeoutExpired:
        return [], "gosec_timeout"

    try:
        data = json.loads(stdout)
    except Exception as e:  # noqa: BLE001
        return [], f"gosec_parse_failed:{e}"

    issues = data.get("Issues") or []
    if not isinstance(issues, list):
        return [], None

    out: list[dict[str, Any]] = []
    for it in issues:
        if not isinstance(it, dict):
            continue
        sev_txt = str(it.get("severity", "MEDIUM")).lower()
        sev = "medium"
        if sev_txt == "high":
            sev = "high"
        elif sev_txt == "low":
            sev = "low"
        rule_id = str(it.get("rule_id", "GOSEC"))
        details = str(it.get("details", rule_id))
        file_ = str(it.get("file", ""))
        line_ = str(it.get("line", ""))
        cwe = extract_cwe(it)
        out.append(
            {
                "rule_id": f"gosec:{rule_id}",
                "severity": sev,
                "confidence": 0.8,
                "cwe": cwe,
                "quote": clip(details, 240),
                "reason": clip(f"gosec finding in {file_}:{line_}" if file_ else "gosec finding", 300),
            }
        )
    return out, None


def run_cppcheck(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    cmd = [
        "cppcheck",
        "--enable=all",
        "--inconclusive",
        "--xml",
        "--xml-version=2",
        str(repo_path),
    ]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return [], "cppcheck_timeout"

    xml_text = (proc.stderr or "").strip()
    if not xml_text:
        return [], None
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:  # noqa: BLE001
        return [], f"cppcheck_parse_failed:{e}"

    out: list[dict[str, Any]] = []
    for err in root.findall(".//error"):
        rid = err.attrib.get("id", "CPPCHECK")
        sev_src = (err.attrib.get("severity") or "warning").lower()
        sev = "medium"
        if sev_src in {"error"}:
            sev = "high"
        elif sev_src in {"style", "information"}:
            sev = "low"
        msg = err.attrib.get("msg") or err.attrib.get("verbose") or rid
        cwe_raw = err.attrib.get("cwe")
        cwe = [f"CWE-{cwe_raw}"] if cwe_raw and cwe_raw.isdigit() else []
        loc = err.find("location")
        loc_s = ""
        if loc is not None:
            file_ = loc.attrib.get("file", "")
            line_ = loc.attrib.get("line", "")
            loc_s = f"{file_}:{line_}" if file_ else ""
        out.append(
            {
                "rule_id": f"cppcheck:{rid}",
                "severity": sev,
                "confidence": 0.75,
                "cwe": cwe,
                "quote": clip(str(msg), 240),
                "reason": clip(f"Cppcheck finding in {loc_s}" if loc_s else "Cppcheck finding", 300),
            }
        )
    return out, None


def shell_files(repo_path: Path) -> list[Path]:
    exts = {".sh", ".bash", ".zsh", ".ksh"}
    return [p for p in repo_path.rglob("*") if p.is_file() and p.suffix.lower() in exts and ".git" not in p.parts]


def run_shellcheck(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    files = shell_files(repo_path)
    if not files:
        return [], None

    out: list[dict[str, Any]] = []
    for fp in files:
        cmd = ["shellcheck", "-f", "json1", str(fp)]
        try:
            proc = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)
            stdout = proc.stdout
        except subprocess.CalledProcessError as e:
            # shellcheck non-zero when findings exist
            stdout = (e.stdout or "").strip()
            if not stdout:
                stderr = (e.stderr or "").strip()
                return out, f"shellcheck_failed:{clip(stderr, 240)}"
        except subprocess.TimeoutExpired:
            return out, "shellcheck_timeout"

        try:
            data = json.loads(stdout)
        except Exception:
            continue

        comments = data.get("comments") if isinstance(data, dict) else None
        if not isinstance(comments, list):
            continue
        for c in comments:
            if not isinstance(c, dict):
                continue
            code = c.get("code", "SC")
            level = str(c.get("level", "warning")).lower()
            sev = "medium"
            if level in {"error"}:
                sev = "high"
            elif level in {"info", "style"}:
                sev = "low"
            msg = str(c.get("message", f"ShellCheck {code}"))
            line_no = c.get("line")
            out.append(
                {
                    "rule_id": f"shellcheck:SC{code}",
                    "severity": sev,
                    "confidence": 0.75,
                    "cwe": [],
                    "quote": clip(msg, 240),
                    "reason": clip(f"ShellCheck finding in {fp}:{line_no}", 300),
                }
            )
    return out, None


def discover_spotbugs_targets(repo_path: Path) -> list[Path]:
    targets: list[Path] = []
    patterns = [
        "**/target/classes",
        "**/build/classes",
        "**/build/classes/java/main",
        "**/build/classes/kotlin/main",
        "**/target/*.jar",
        "**/build/libs/*.jar",
    ]
    for pat in patterns:
        for p in repo_path.glob(pat):
            if p.exists():
                targets.append(p)
    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for p in targets:
        s = str(p.resolve())
        if s not in seen:
            seen.add(s)
            out.append(p)
    return out[:80]


def run_spotbugs_findsecbugs(
    repo_path: Path,
    findsecbugs_jar: Path,
    timeout_sec: int,
) -> tuple[list[dict[str, Any]], str | None]:
    targets = discover_spotbugs_targets(repo_path)
    if not targets:
        return [], "spotbugs_no_bytecode_targets"

    with tempfile.NamedTemporaryFile(prefix="spotbugs-", suffix=".xml", delete=False) as tmp:
        report = Path(tmp.name)

    cmd = [
        "spotbugs",
        "-textui",
        "-effort:max",
        "-low",
        "-xml:withMessages",
        "-output",
        str(report),
    ]
    if findsecbugs_jar.exists():
        cmd.extend(["-pluginList", str(findsecbugs_jar)])
    cmd.extend(str(t) for t in targets)

    try:
        subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return [], "spotbugs_timeout"

    if not report.exists():
        return [], "spotbugs_no_report"

    try:
        root = ET.fromstring(report.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:  # noqa: BLE001
        return [], f"spotbugs_parse_failed:{e}"

    out: list[dict[str, Any]] = []
    for bug in root.findall(".//BugInstance"):
        bug_type = bug.attrib.get("type", "SPOTBUGS")
        priority = bug.attrib.get("priority", "2")
        sev = "medium"
        if priority == "1":
            sev = "high"
        elif priority == "3":
            sev = "low"

        long_msg = ""
        lm = bug.find("LongMessage")
        if lm is not None and lm.text:
            long_msg = lm.text
        if not long_msg:
            sm = bug.find("ShortMessage")
            if sm is not None and sm.text:
                long_msg = sm.text
        if not long_msg:
            long_msg = bug_type

        src = bug.find("SourceLine")
        loc = ""
        if src is not None:
            file_ = src.attrib.get("sourcepath", "")
            line_ = src.attrib.get("start", "")
            loc = f"{file_}:{line_}" if file_ else ""

        cwe = extract_cwe(long_msg) or extract_cwe(bug_type)
        out.append(
            {
                "rule_id": f"spotbugs:{bug_type}",
                "severity": sev,
                "confidence": 0.8,
                "cwe": cwe,
                "quote": clip(long_msg, 240),
                "reason": clip(f"SpotBugs finding in {loc}" if loc else "SpotBugs finding", 300),
            }
        )
    return out, None


def eslint_cwe(rule_id: str) -> list[str]:
    mapping = {
        "security/detect-child-process": ["CWE-78"],
        "security/detect-eval-with-expression": ["CWE-95"],
        "security/detect-non-literal-fs-filename": ["CWE-22"],
        "security/detect-non-literal-require": ["CWE-829"],
        "security/detect-disable-mustache-escape": ["CWE-79"],
        "security/detect-pseudoRandomBytes": ["CWE-338"],
        "security/detect-unsafe-regex": ["CWE-1333"],
        "security/detect-possible-timing-attacks": ["CWE-208"],
    }
    return mapping.get(rule_id, [])


def run_eslint_security(repo_path: Path, timeout_sec: int) -> tuple[list[dict[str, Any]], str | None]:
    rules = [
        "security/detect-buffer-noassert:warn",
        "security/detect-child-process:warn",
        "security/detect-disable-mustache-escape:warn",
        "security/detect-eval-with-expression:warn",
        "security/detect-new-buffer:warn",
        "security/detect-no-csrf-before-method-override:warn",
        "security/detect-non-literal-fs-filename:warn",
        "security/detect-non-literal-regexp:warn",
        "security/detect-non-literal-require:warn",
        "security/detect-object-injection:warn",
        "security/detect-possible-timing-attacks:warn",
        "security/detect-pseudoRandomBytes:warn",
        "security/detect-unsafe-regex:warn",
    ]

    base = [
        "eslint",
        "-f",
        "json",
        "--no-error-on-unmatched-pattern",
        "--ext",
        ".js,.jsx,.ts,.tsx,.vue",
        "--plugin",
        "security",
    ]
    for r in rules:
        base.extend(["--rule", r])

    attempts = [
        base + ["--no-config-lookup", str(repo_path)],
        base + ["--no-eslintrc", str(repo_path)],
        base + [str(repo_path)],
    ]

    last_err = "eslint_no_output"
    stdout = ""
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_sec)
            out = (proc.stdout or "").strip()
            if out.startswith("[") or out.startswith("{"):
                stdout = out
                break
            last_err = clip((proc.stderr or proc.stdout or "").strip(), 240)
        except subprocess.TimeoutExpired:
            return [], "eslint_timeout"

    if not stdout:
        return [], f"eslint_failed:{last_err}"

    try:
        data = json.loads(stdout)
    except Exception as e:  # noqa: BLE001
        return [], f"eslint_parse_failed:{e}"

    if not isinstance(data, list):
        return [], None

    out: list[dict[str, Any]] = []
    for file_obj in data:
        if not isinstance(file_obj, dict):
            continue
        file_ = str(file_obj.get("filePath", ""))
        for m in file_obj.get("messages", []) or []:
            if not isinstance(m, dict):
                continue
            rid = str(m.get("ruleId") or "eslint-security")
            if not rid.startswith("security/"):
                continue
            sev_num = int(m.get("severity") or 1)
            sev = "medium" if sev_num >= 2 else "low"
            msg = str(m.get("message", rid))
            line_no = m.get("line", "")
            out.append(
                {
                    "rule_id": f"eslint:{rid}",
                    "severity": sev,
                    "confidence": 0.75,
                    "cwe": eslint_cwe(rid),
                    "quote": clip(msg, 240),
                    "reason": clip(f"ESLint security finding in {file_}:{line_no}" if file_ else "ESLint security finding", 300),
                }
            )
    return out, None


def finding_record(candidate_id: str, analyzer: str, item: dict[str, Any], details: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(item.get("rule_id") or analyzer)
    fid = sha256_text(f"{candidate_id}:{analyzer}:{rule_id}:{item.get('quote', '')}")[:24]
    sev = str(item.get("severity", "medium"))
    return {
        "finding_id": fid,
        "candidate_id": candidate_id,
        "analyzer": analyzer,
        "is_risky": True,
        "severity": sev if sev in {"none", "low", "medium", "high", "critical"} else "medium",
        "confidence": float(item.get("confidence", 0.7)),
        "cwe": item.get("cwe") if isinstance(item.get("cwe"), list) else [],
        "evidence": [{"quote": str(item.get("quote", "")), "reason": str(item.get("reason", ""))}],
        "verdict": "likely" if sev in {"high", "critical"} else "possible",
        "rule_id": rule_id,
        "details": details,
    }


def main() -> None:
    args = parse_args()
    candidates = load_candidates(args.candidates, args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    resume_state = args.resume_state or default_resume_state_path(args.out)

    has_codeql = has_cmd("codeql")
    has_semgrep = has_cmd("semgrep")
    has_gitleaks = has_cmd("gitleaks")
    has_detect_secrets = has_cmd("detect-secrets")
    has_bandit = has_cmd("bandit")
    has_gosec = has_cmd("gosec")
    has_cppcheck = has_cmd("cppcheck")
    has_shellcheck = has_cmd("shellcheck")
    has_spotbugs = has_cmd("spotbugs")
    has_eslint = has_cmd("eslint")
    findsecbugs_exists = args.findsecbugs_jar.exists()

    # chat -> representative candidate (for repo-level mapping)
    rep_candidate_by_chat: dict[str, str] = {}
    for c in candidates:
        chat_id = str(c.get("chat_id", ""))
        cid = str(c.get("candidate_id", ""))
        if chat_id and cid and chat_id not in rep_candidate_by_chat:
            rep_candidate_by_chat[chat_id] = cid

    # repo -> chat_ids
    chats_by_repo: dict[str, set[str]] = defaultdict(set)
    for c in candidates:
        chat_id = str(c.get("chat_id", ""))
        repo = ((c.get("repo_context") or {}).get("repo_full_name"))
        if isinstance(repo, str) and repo and chat_id:
            chats_by_repo[repo].add(chat_id)

    # repo -> snippets (for semgrep fallback only)
    snippets_by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in candidates:
        if c.get("candidate_type") != "code_snippet":
            continue
        repo = ((c.get("repo_context") or {}).get("repo_full_name"))
        if isinstance(repo, str) and repo:
            snippets_by_repo[repo].append(c)

    counts = Counter()
    errors: list[str] = []
    done_repos: set[str] = set()
    if args.resume:
        done_repos |= load_done_repos_from_state(resume_state)
        # Backward compatibility for runs before sidecar existed.
        if not done_repos:
            done_repos |= load_done_repos_from_output(args.out)
    else:
        if args.out.exists():
            args.out.unlink()
        if resume_state.exists():
            resume_state.unlink()

    mode = "ab" if args.resume else "wb"
    resume_state.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open(mode) as wf, resume_state.open("a", encoding="utf-8") as checkpoint_f:
        for repo_full_name in tqdm(sorted(chats_by_repo.keys()), desc="static-per-repo"):
            if repo_full_name in done_repos:
                counts["repos_skipped_resume"] += 1
                continue
            chat_ids = sorted(chats_by_repo[repo_full_name])
            repo_path = repo_path_from_full_name(args.repos_root, repo_full_name)
            if not repo_path:
                counts["repo_not_found"] += 1
                errors.append(f"{repo_full_name}::repo_not_found")
                if has_semgrep:
                    semgrep_snippet_cache: dict[str, tuple[list[dict[str, Any]], str | None]] = {}
                    for snip in snippets_by_repo.get(repo_full_name, []):
                        cache_key = f"{snip.get('content_hash')}::{snip.get('language_hint')}"
                        if cache_key not in semgrep_snippet_cache:
                            semgrep_snippet_cache[cache_key] = run_semgrep_on_snippet(
                                content=str(snip.get("content", "")),
                                language_hint=snip.get("language_hint"),
                                config=args.semgrep_config,
                                timeout_sec=args.timeout_sec,
                            )
                        semgrep_findings, se = semgrep_snippet_cache[cache_key]
                        if se:
                            errors.append(f"{snip.get('candidate_id')}::{se}")
                        for item in semgrep_findings:
                            rec = finding_record(
                                str(snip.get("candidate_id")),
                                analyzer="static_rule",
                                item=item,
                                details={
                                    "engine": "semgrep",
                                    "scope": "snippet",
                                    "repo_full_name": repo_full_name,
                                    "chat_id": snip.get("chat_id"),
                                    "language_hint": snip.get("language_hint"),
                                },
                            )
                            wf.write(orjson.dumps(rec) + b"\n")
                            counts["findings"] += 1
                    counts["semgrep_repo_fallback_to_snippet"] += 1
                    checkpoint_f.write(orjson.dumps({"repo_full_name": repo_full_name}).decode("utf-8") + "\n")
                    checkpoint_f.flush()
                done_repos.add(repo_full_name)
                continue

            repo_items: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
            repo_langs = detect_repo_languages(repo_path)

            # 1) CodeQL first
            codeql_findings: list[dict[str, Any]] = []
            if has_codeql:
                lang = detect_repo_language(repo_path)
                if lang:
                    fds, err = run_codeql(
                        repo_path=repo_path,
                        lang=lang,
                        db_root=args.codeql_db_root,
                        sarif_root=args.codeql_sarif_root,
                        timeout_sec=args.timeout_sec,
                    )
                    if err:
                        errors.append(f"{repo_full_name}::{err}")
                        counts["codeql_failed_or_empty"] += 1
                    else:
                        codeql_findings = fds
                        counts["codeql_repo_scanned"] += 1
                        for item in fds:
                            repo_items.append(
                                (
                                    "static_rule",
                                    item,
                                    {
                                        "engine": "codeql",
                                        "scope": "repo",
                                        "repo_full_name": repo_full_name,
                                        "repo_language": lang,
                                    },
                                )
                            )
                else:
                    counts["codeql_failed_or_empty"] += 1
                    errors.append(f"{repo_full_name}::repo_language_unknown")

            # 2) Semgrep fallback (repo-level first, then snippet fallback)
            if not codeql_findings and has_semgrep:
                fds, err = run_semgrep_on_repo(repo_path, args.semgrep_config, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                if not fds:
                    # fallback to snippets if repo scan yielded nothing or failed
                    semgrep_snippet_cache: dict[str, tuple[list[dict[str, Any]], str | None]] = {}
                    for snip in snippets_by_repo.get(repo_full_name, []):
                        cache_key = f"{snip.get('content_hash')}::{snip.get('language_hint')}"
                        if cache_key not in semgrep_snippet_cache:
                            semgrep_snippet_cache[cache_key] = run_semgrep_on_snippet(
                                content=str(snip.get("content", "")),
                                language_hint=snip.get("language_hint"),
                                config=args.semgrep_config,
                                timeout_sec=args.timeout_sec,
                            )
                        semgrep_findings, se = semgrep_snippet_cache[cache_key]
                        if se:
                            errors.append(f"{snip.get('candidate_id')}::{se}")
                        for item in semgrep_findings:
                            rec = finding_record(
                                str(snip.get("candidate_id")),
                                analyzer="static_rule",
                                item=item,
                                details={
                                    "engine": "semgrep",
                                    "scope": "snippet",
                                    "repo_full_name": repo_full_name,
                                    "chat_id": snip.get("chat_id"),
                                    "language_hint": snip.get("language_hint"),
                                },
                            )
                            wf.write(orjson.dumps(rec) + b"\n")
                            counts["findings"] += 1
                    counts["semgrep_repo_fallback_to_snippet"] += 1
                else:
                    counts["semgrep_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "semgrep",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            # 3) Secret scanners (always try when available)
            if has_gitleaks:
                fds, err = run_gitleaks(repo_path, args.gitleaks_report_root, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["gitleaks_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "gitleaks",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            if has_detect_secrets:
                fds, err = run_detect_secrets(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["detect_secrets_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "detect-secrets",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            # 4) Language-specific analyzers
            if has_bandit and "python" in repo_langs:
                fds, err = run_bandit(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["bandit_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "bandit",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            if has_gosec and "go" in repo_langs:
                fds, err = run_gosec(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["gosec_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "gosec",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            if has_cppcheck and "cpp" in repo_langs:
                fds, err = run_cppcheck(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["cppcheck_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "cppcheck",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            if has_shellcheck and "shell" in repo_langs:
                fds, err = run_shellcheck(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["shellcheck_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "shellcheck",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            if has_spotbugs and "java" in repo_langs:
                fds, err = run_spotbugs_findsecbugs(repo_path, args.findsecbugs_jar, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["spotbugs_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "spotbugs",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                    "findsecbugs_plugin": findsecbugs_exists,
                                },
                            )
                        )

            if has_eslint and "javascript" in repo_langs:
                fds, err = run_eslint_security(repo_path, args.timeout_sec)
                if err:
                    errors.append(f"{repo_full_name}::{err}")
                else:
                    counts["eslint_repo_scanned"] += 1
                    for item in fds:
                        repo_items.append(
                            (
                                "static_rule",
                                item,
                                {
                                    "engine": "eslint-security",
                                    "scope": "repo",
                                    "repo_full_name": repo_full_name,
                                },
                            )
                        )

            # Map repo-level findings back to all chats of this repo.
            for analyzer, item, base_details in repo_items:
                for chat_id in chat_ids:
                    candidate_id = rep_candidate_by_chat.get(chat_id)
                    if not candidate_id:
                        continue
                    details = dict(base_details)
                    details["chat_id"] = chat_id
                    rec = finding_record(candidate_id, analyzer=analyzer, item=item, details=details)
                    wf.write(orjson.dumps(rec) + b"\n")
                    counts["findings"] += 1

            checkpoint_f.write(orjson.dumps({"repo_full_name": repo_full_name}).decode("utf-8") + "\n")
            checkpoint_f.flush()
            done_repos.add(repo_full_name)

    summary = {
        "candidates_total": len(candidates),
        "repos_total": len(chats_by_repo),
        "findings": counts["findings"],
        "codeql_available": has_codeql,
        "semgrep_available": has_semgrep,
        "gitleaks_available": has_gitleaks,
        "detect_secrets_available": has_detect_secrets,
        "bandit_available": has_bandit,
        "gosec_available": has_gosec,
        "cppcheck_available": has_cppcheck,
        "shellcheck_available": has_shellcheck,
        "spotbugs_available": has_spotbugs,
        "eslint_available": has_eslint,
        "findsecbugs_jar_exists": findsecbugs_exists,
        "codeql_repo_scanned": counts["codeql_repo_scanned"],
        "codeql_failed_or_empty": counts["codeql_failed_or_empty"],
        "semgrep_repo_scanned": counts["semgrep_repo_scanned"],
        "semgrep_repo_fallback_to_snippet": counts["semgrep_repo_fallback_to_snippet"],
        "gitleaks_repo_scanned": counts["gitleaks_repo_scanned"],
        "detect_secrets_repo_scanned": counts["detect_secrets_repo_scanned"],
        "bandit_repo_scanned": counts["bandit_repo_scanned"],
        "gosec_repo_scanned": counts["gosec_repo_scanned"],
        "cppcheck_repo_scanned": counts["cppcheck_repo_scanned"],
        "shellcheck_repo_scanned": counts["shellcheck_repo_scanned"],
        "spotbugs_repo_scanned": counts["spotbugs_repo_scanned"],
        "eslint_repo_scanned": counts["eslint_repo_scanned"],
        "repo_not_found": counts["repo_not_found"],
        "repos_skipped_resume": counts["repos_skipped_resume"],
        "errors_count": len(errors),
        "errors_preview": errors[:40],
        "resume": args.resume,
        "resume_state": str(resume_state),
        "out": str(args.out),
    }

    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_bytes(orjson.dumps(summary, option=orjson.OPT_INDENT_2))

    print(orjson.dumps(summary, option=orjson.OPT_INDENT_2).decode("utf-8"))


if __name__ == "__main__":
    main()
