#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import orjson

from cwe_reference import load_full_catalog_cache, search_full_catalog, split_cwe_values


try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


PATTERN_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "sql_construction",
        "cwes": ["CWE-89", "CWE-943", "CWE-20"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "php", "java", "sql"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"\bselect\b.+\+",
            r"\bexecute\([^)]*%",
            r"\bexecute\([^)]*f[\"']",
            r"\bquery\([^)]*\+",
            r"\$\{[^}]+\}.*\b(select|insert|update|delete)\b",
        ],
        "risk_tags": ["sql_injection", "raw_query_construction", "input_validation"],
        "reason": "Query text appears to be constructed with interpolation or concatenation.",
    },
    {
        "rule_id": "plaintext_password_sql",
        "cwes": ["CWE-798", "CWE-259", "CWE-522", "CWE-256"],
        "languages": {"sql", "javascript", "js", "typescript", "ts", "python", "py", "php", "java"},
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)\bALTER\s+USER\s+\w+\s+WITH\s+PASSWORD\s+['\"][^'\"]{4,}['\"]",
            r"(?i)\bWHERE\s+\w*(username|email|login)\w*\s*=\s*[^;\n]+AND\s+\w*password\w*\s*=",
            r"(?i)\bSELECT\s+\*\s+FROM\s+\w*users?\w*[^;\n]+\bpassword\b",
        ],
        "risk_tags": ["hardcoded_secret", "plaintext_password", "credential_exposure", "weak_authentication"],
        "reason": "SQL or database logic appears to set, compare, or expose plaintext passwords or credentials.",
    },
    {
        "rule_id": "command_construction",
        "cwes": ["CWE-78", "CWE-88"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "bash", "shell", "sh"},
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"shell\s*=\s*true",
            r"\bos\.system\(",
            r"\bsubprocess\.[^(]+\([^)]*\+",
            r"\beval\s+\"\$\(",
            r"\beval\s+['\"]?\$\w+",
        ],
        "risk_tags": ["command_injection", "shell_execution", "dangerous_command"],
        "reason": "Shell command construction or shell execution may include untrusted data.",
    },
    {
        "rule_id": "command_substitution_in_data_or_sql",
        "cwes": ["CWE-78", "CWE-88", "CWE-89"],
        "languages": {"bash", "shell", "sh"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"\$\(\s*cat\s+[^)]+\)",
            r"--command\s*=\s*['\"][^'\"]*\$\(",
            r"\b(psql|wrangler|mysql|sqlite3)\b[^\n]*\$\(",
        ],
        "risk_tags": ["command_injection", "shell_execution", "dangerous_command", "raw_query_construction"],
        "reason": "Shell command substitution appears inside an executable data-processing or SQL command.",
    },
    {
        "rule_id": "hardcoded_secret",
        "cwes": ["CWE-798", "CWE-259", "CWE-321"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}",
            r"sk-[A-Za-z0-9_-]{20,}",
            r"(?i)bearer\s+[A-Za-z0-9._-]{20,}",
            r"(?i)aws_access_key_id\s*[:=]\s*['\"]?[A-Z0-9]{16,}",
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}",
        ],
        "risk_tags": ["hardcoded_secret", "credential_exposure"],
        "reason": "Credential-like value appears directly in generated code or command text.",
    },
    {
        "rule_id": "credential_exposure_extended",
        "cwes": ["CWE-798", "CWE-259", "CWE-321", "CWE-200", "CWE-522"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)\b[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY|SERVICE[_-]?ROLE[_-]?KEY|JWT[_-]?SECRET)[A-Z0-9_]*\s*=\s*[^\s#'\"]{8,}",
            r"(?i)\b[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY|SERVICE[_-]?ROLE[_-]?KEY|JWT[_-]?SECRET)[A-Z0-9_]*\s*=\s*['\"][^'\"]{8,}['\"]",
            r"(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^:\s/]+:[^@\s]+@",
            r"(?i)\bSUPABASE_(ACCESS_TOKEN|SERVICE_ROLE_KEY|ANON_KEY)\s*=",
            r"(?i)\bJWT_SECRET(_KEY)?\s*=",
            r"(?i)\bOPEN_?AI?_?API_KEY\s*=\s*sk-[A-Za-z0-9_-]*",
            r"(?i)\bOPEN_?API_KEY\s*=\s*sk-[A-Za-z0-9_-]*",
            r"(?i)\baws_iam_access_key\.[A-Za-z0-9_-]+\.secret\b",
            r"(?i)\bvalue\s*=\s*aws_iam_access_key\.[A-Za-z0-9_-]+\.secret\b",
            r"(?i)#define\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s+\"[^\"]{4,}\"",
            r"(?i)\bPASSWORD_DEFAULT\s+\"[^\"]{4,}\"",
            r"(?i)\bMQTT_(USERNAME|PASSWORD)\s+\"[^\"]+\"",
        ],
        "risk_tags": ["credential_exposure", "hardcoded_secret", "information_exposure"],
        "reason": "Credential-like value, secret, token, database URL, firmware credential, or secret output appears directly in generated content.",
    },
    {
        "rule_id": "weak_default_secret_or_password",
        "cwes": ["CWE-798", "CWE-259", "CWE-521"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)\b(DEFAULT_?PASSWORD|PASSWORD_DEFAULT)\b[^=\n]*=\s*['\"]?(123456|password|admin|test|changeme|default)['\"]?",
            r"(?i)#define\s+\w*(PASSWORD|PIN|SECRET)\w*\s+\"(123456|password|admin|test|changeme|default)\"",
            r"(?i)\bPOSTGRES_PASSWORD\s*=\s*(password|postgres|admin|test)\b",
            r"(?i)\bREDIS_PASSWORD\s*=\s*$",
        ],
        "risk_tags": ["weak_default_password", "hardcoded_secret", "credential_exposure"],
        "reason": "Generated configuration appears to use a weak default password or empty credential.",
    },
    {
        "rule_id": "unsafe_deserialization",
        "cwes": ["CWE-502"],
        "languages": {"python", "py", "java", "javascript", "js", "typescript", "ts", "yaml", "yml", "php"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"\bpickle\.loads?\(",
            r"\byaml\.load\(",
            r"\bObjectInputStream\b",
            r"\bunserialize\(",
            r"\bmarshal\.loads?\(",
        ],
        "risk_tags": ["unsafe_deserialization"],
        "reason": "Unsafe deserialization API appears in the candidate.",
    },
    {
        "rule_id": "tls_disabled",
        "cwes": ["CWE-295", "CWE-319"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "go", "java", "bash", "shell", "sh"},
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"InsecureSkipVerify\s*:\s*true",
            r"curl\s+[^|\n]*(-k|--insecure)",
            r"wget\s+[^|\n]*(--no-check-certificate)",
        ],
        "risk_tags": ["tls_disabled", "certificate_validation_bypass", "insecure_transport"],
        "reason": "TLS certificate verification or transport protection appears disabled.",
    },
    {
        "rule_id": "embedded_insecure_security_config",
        "cwes": ["CWE-295", "CWE-319", "CWE-494", "CWE-693", "CWE-311"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"\bCONFIG_ESP_TLS_INSECURE\s*=\s*y\b",
            r"\bCONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY\s*=\s*y\b",
            r"\bCONFIG_OTA_ALLOW_HTTP\s*=\s*y\b",
            r"\bCONFIG_OTA_SKIP_COMMON_NAME_CHECK\s*=\s*y\b",
            r"\bCONFIG_OTA_SKIP_VERSION_CHECK\s*=\s*y\b",
            r"\bCONFIG_SECURE_BOOT\s*=\s*n\b",
            r"\bCONFIG_SECURE_FLASH_ENC_ENABLED\s*=\s*n\b",
            r"\bCONFIG_SECURE_FLASH_ENCRYPTION\s*=\s*n\b",
            r"\bCONFIG_NVS_ENCRYPTION\s*=\s*n\b",
        ],
        "risk_tags": ["tls_disabled", "insecure_transport", "secure_boot_disabled", "insecure_update", "security_control_disabled"],
        "reason": "Embedded firmware configuration disables transport verification, secure boot, flash encryption, NVS encryption, or secure OTA controls.",
    },
    {
        "rule_id": "overbroad_permissions",
        "cwes": ["CWE-732", "CWE-266"],
        "languages": {"bash", "shell", "sh", "yaml", "yml", "json", "terraform", "hcl"},
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"chmod\s+777",
            r'Action"\s*:\s*"\*"',
            r'Principal"\s*:\s*"\*"',
            r"\ballUsers\b",
            r"\bpublic-read\b",
        ],
        "risk_tags": ["overbroad_permission", "access_control"],
        "reason": "Permission or access-control configuration appears overly broad.",
    },
    {
        "rule_id": "public_inbound_nonstandard_ports",
        "cwes": ["CWE-284", "CWE-200", "CWE-668"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?i)(22|3000|5000|5432|6379|8080|9200|27017|3306)\s*.*0\.0\.0\.0/0",
            r"(?i)0\.0\.0\.0/0\s*.*(22|3000|5000|5432|6379|8080|9200|27017|3306)",
            r"(?i)(SSH|Postgres|Redis|MongoDB|MySQL|Frontend|API Gateway).*0\.0\.0\.0/0",
        ],
        "risk_tags": ["public_exposure", "overbroad_network_access", "access_control"],
        "reason": "Nonstandard, database, admin, development, or SSH service port appears publicly exposed.",
    },
    {
        "rule_id": "unsafe_html_rendering",
        "cwes": ["CWE-79", "CWE-80", "CWE-116"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"dangerouslySetInnerHTML",
            r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:",
            r"\.innerHTML\s*=",
            r"\bv-html\b",
            r"\bdocument\.write\(",
            r"`<[^`]+>\$\{[^}]+\}",
        ],
        "risk_tags": ["xss", "unsafe_rendering", "output_encoding"],
        "reason": "Untrusted or dynamic content may be inserted into HTML without proper neutralization.",
    },
    {
        "rule_id": "path_traversal",
        "cwes": ["CWE-22", "CWE-73"],
        "languages": {"python", "py", "javascript", "js", "typescript", "ts", "php", "java", "go", "ruby"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"\bopen\([^)]*\+",
            r"\breadFileSync\([^)]*\+",
            r"\bsend_file\(",
            r"\.\./",
        ],
        "risk_tags": ["path_traversal", "external_controlled_path"],
        "reason": "Filesystem path construction may be influenced by external input.",
    },
    {
        "rule_id": "request_controlled_path_join",
        "cwes": ["CWE-22", "CWE-73"],
        "languages": {"python", "py"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"\w+\s*=\s*request\.(args|form|json|values)\.get\(",
            r"os\.path\.join\([^)]*\b\w+\b[^)]*\)",
            r"with\s+open\([^)]*\b\w+\b[^)]*\)",
        ],
        "risk_tags": ["path_traversal", "external_controlled_path"],
        "reason": "Request-controlled input appears to influence filesystem path construction.",
    },
    {
        "rule_id": "sensitive_logging",
        "cwes": ["CWE-200", "CWE-532"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"console\.log\([^)]*(password|token|secret|key)",
            r"print\([^)]*(password|token|secret|key)",
            r"logger\.[^(]+\([^)]*(password|token|secret|key)",
        ],
        "risk_tags": ["sensitive_logging", "information_exposure"],
        "reason": "Sensitive values appear to be logged or exposed.",
    },
    {
        "rule_id": "auth_or_payload_debug_logging",
        "cwes": ["CWE-532", "CWE-200", "CWE-209"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"console\.log\([^)]*(code|session|auth|credential|data|payload|jsonEncode|JSON\.stringify)",
            r"debugPrint\([^)]*(data|payload|jsonEncode|token|session|auth)",
            r"print\([^)]*(code|session|auth|credential|data|payload|json)",
            r"logger\.[^(]+\([^)]*(code|session|auth|credential|data|payload|json)",
            r"console\.error\([^)]*(token|secret|password|session|auth|credential)",
        ],
        "risk_tags": ["sensitive_logging", "information_exposure", "debug_logging"],
        "reason": "Debug logging may expose auth artifacts, serialized payloads, credentials, or sensitive runtime data.",
    },
    {
        "rule_id": "token_in_url_or_insecure_websocket",
        "cwes": ["CWE-319", "CWE-598", "CWE-200"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"ws://[^`'\"\s]*\?[^`'\"\s]*(token|access_token|auth|key)=",
            r"https?://[^`'\"\s]*\?[^`'\"\s]*(token|access_token|api_key|key|secret)=",
            r"`ws://[^`]+(token|access_token|auth|key)=\$\{[^}]+\}",
            r"\bnew\s+WebSocket\([^)]*ws://",
        ],
        "risk_tags": ["insecure_transport", "token_in_url", "information_exposure"],
        "reason": "Token or credential is placed in a URL or sent over insecure WebSocket/HTTP transport.",
    },
    {
        "rule_id": "auth_bypass_or_test_identity",
        "cwes": ["CWE-287", "CWE-288", "CWE-306", "CWE-862", "CWE-863"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?i)skip\s+(verification|auth|authentication|authorization|permission)\s+check",
            r"(?i)temporar(il)?y\s+skipping\s+(verification|auth|authentication|authorization)",
            r"(?i)temporar(y|ily):?\s+skip\s+(verification|auth|authentication|authorization)",
            r"(?i)remove\s+withAuth",
            r"(?i)without\s+auth",
            r"(?i)const\s+userId\s*=\s*['\"]test[-_ ]?user[-_ ]?id['\"]",
            r"(?i)emailVerified\)",
            r"(?i)throw\s+new\s+Error\(['\"]Please verify your email",
            r"(?i)-\s*<ProtectedRoute[^>]*requiresPermission=",
            r"(?i)requiresPermission\s*=\s*['\"][^'\"]+['\"]",
        ],
        "risk_tags": ["auth_bypass", "missing_authorization", "access_control"],
        "reason": "Authentication, verification, or authorization checks appear removed, skipped, or replaced with a test identity.",
    },
    {
        "rule_id": "database_permission_grant_to_public_or_anon",
        "cwes": ["CWE-732", "CWE-284", "CWE-266"],
        "languages": {"sql", "bash", "shell", "sh"},
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)\bgrant\s+(usage|select|insert|update|delete|all)\b[^;\n]+\bto\s+(anon|anonymous|public)\b",
            r"(?i)\balter\s+default\s+privileges\b[^;\n]+\bgrant\b[^;\n]+\bto\s+(anon|anonymous|public)\b",
        ],
        "risk_tags": ["overbroad_permission", "access_control", "public_exposure"],
        "reason": "Database privileges are granted to anonymous, public, or broadly accessible roles.",
    },
    {
        "rule_id": "curl_pipe_shell",
        "cwes": ["CWE-494", "CWE-829", "CWE-78"],
        "languages": {"bash", "shell", "sh"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"curl\s+[^|\n]+\|\s*(bash|sh)",
            r"wget\s+[^|\n]+-O\s*-\s*\|\s*(bash|sh)",
        ],
        "risk_tags": ["untrusted_download", "supply_chain", "dangerous_command"],
        "reason": "Remote content is downloaded and executed directly.",
    },
    {
        "rule_id": "docker_privileged",
        "cwes": ["CWE-250", "CWE-732", "CWE-266"],
        "languages": {"bash", "shell", "sh"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"docker\s+run\b[^\n]*--privileged",
            r"docker\s+run\b[^\n]*-v\s+/\s*:",
            r"docker\s+run\b[^\n]*--cap-add\s+ALL",
        ],
        "risk_tags": ["privilege_escalation", "overbroad_permission", "container_escape_risk"],
        "reason": "Container command grants broad host or privilege access.",
    },
    {
        "rule_id": "dangerous_recursive_delete",
        "cwes": ["CWE-78", "CWE-73"],
        "languages": {"bash", "shell", "sh"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"rm\s+-rf\s+/",
            r"rm\s+-rf\s+\$[A-Za-z_][A-Za-z0-9_]*",
            r"rm\s+-rf\s+\*",
        ],
        "risk_tags": ["dangerous_command", "destructive_operation"],
        "reason": "Command may recursively delete broad or variable-controlled paths.",
    },
    {
        "rule_id": "powershell_execution_policy_bypass",
        "cwes": ["CWE-693"],
        "languages": {"bash", "shell", "sh", "powershell", "ps1"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"(?i)powershell(\.exe)?\s+.*-ExecutionPolicy\s+Bypass",
        ],
        "risk_tags": ["security_control_bypass", "dangerous_command"],
        "reason": "Command bypasses PowerShell execution policy.",
    },
    {
        "rule_id": "route_middleware_auth_disabled",
        "cwes": ["CWE-306", "CWE-862", "CWE-863", "CWE-287"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?i)withoutMiddleware\(\s*\[[^\]]*(auth|permission|sanctum|web)[^\]]*\]\s*\)",
            r"(?i)->withoutMiddleware\([^)]*(auth|permission|sanctum|web)[^)]*\)",
            r"(?i)Route::(get|post|put|delete|patch)\([^;\n]+withoutMiddleware",
        ],
        "risk_tags": ["auth_bypass", "missing_authorization", "access_control"],
        "reason": "Route-level authentication or permission middleware appears disabled or removed.",
    },
    {
        "rule_id": "read_env_or_secret_file_command",
        "cwes": ["CWE-200", "CWE-532", "CWE-538"],
        "languages": {"bash", "shell", "sh", "powershell", "ps1"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"(?i)\bcat\s+([A-Za-z0-9_./-]+/)?\.env(\.[A-Za-z0-9_-]+)?\b",
            r"(?i)\btype\s+([A-Za-z0-9_./-]+/)?\.env(\.[A-Za-z0-9_-]+)?\b",
            r"(?i)\bGet-Content\s+([A-Za-z0-9_./\\-]+\\)?\.env(\.[A-Za-z0-9_-]+)?\b",
            r"(?i)\bcat\s+[^;\n]*(id_rsa|credentials|secrets?|\.npmrc|\.pypirc|\.aws/credentials)\b",
        ],
        "risk_tags": ["information_exposure", "credential_exposure", "secret_file_exposure"],
        "reason": "Command reads local environment, credential, or secret files that commonly contain sensitive values.",
    },
    {
        "rule_id": "additional_secret_key_patterns",
        "cwes": ["CWE-798", "CWE-259", "CWE-321", "CWE-200"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"(?i)\bVAPID_PRIVATE_KEY\s*=\s*[A-Za-z0-9_-]{20,}",
            r"(?i)\bAppSecret\s*[\(:： ]+[\w-]*[A-Za-z0-9]{20,}",
            r"(?i)\bApp Key\s+app_[A-Za-z0-9_-]{20,}",
            r"(?i)['\"]x-api-[A-Za-z0-9_-]+['\"]\s*:\s*['\"][A-Za-z0-9_-]{12,}['\"]",
            r"(?i)\b[A-Za-z0-9_-]*api[A-Za-z0-9_-]*['\"]?\s*:\s*['\"](bb|sk|app|key|tok)[A-Za-z0-9_-]{10,}['\"]",
            r"(?i)\bVAPID_(PUBLIC|PRIVATE)_KEY\s*=",
            r"(?i)\bWEATHER_API_KEY\b",
        ],
        "risk_tags": ["credential_exposure", "hardcoded_secret", "information_exposure"],
        "reason": "Additional API key, VAPID private key, app secret, or service-specific credential patterns appear in generated content.",
    },
    {
        "rule_id": "kconfig_default_credentials",
        "cwes": ["CWE-798", "CWE-259", "CWE-321", "CWE-521"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?is)config\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|WIFI_PASS|WIFI_PASSWORD)\w*.*?default\s+\"[^\"]{4,}\"",
            r"(?is)config\s+WIFI_PASSWORD.*?default\s+\"[^\"]+\"",
            r"(?is)config\s+WEATHER_API_KEY.*?default\s+\"[^\"]+\"",
        ],
        "risk_tags": ["hardcoded_secret", "credential_exposure", "weak_default_password"],
        "reason": "Kconfig-style embedded configuration defines default credentials or API keys.",
    },
    {
        "rule_id": "cors_wildcard_with_credentials",
        "cwes": ["CWE-942", "CWE-346", "CWE-284"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?is)Access-Control-Allow-Origin['\"]?\s*:\s*['\"]\*['\"].{0,500}Access-Control-Allow-Credentials['\"]?\s*:\s*['\"]true['\"]",
            r"(?is)Access-Control-Allow-Credentials['\"]?\s*:\s*['\"]true['\"].{0,500}Access-Control-Allow-Origin['\"]?\s*:\s*['\"]\*['\"]",
            r"(?is)allow_origins\s*=\s*\[[^\]]*['\"]\*['\"][^\]]*\].{0,500}allow_credentials\s*=\s*True",
            r"(?is)credentials\s*:\s*true.{0,500}origin\s*:\s*['\"]\*['\"]",
        ],
        "risk_tags": ["cors_misconfiguration", "overbroad_permission", "access_control"],
        "reason": "CORS configuration allows wildcard origins together with credentials or overly broad cross-origin access.",
    },
    {
        "rule_id": "container_host_secret_or_network_exposure",
        "cwes": ["CWE-200", "CWE-250", "CWE-284", "CWE-668"],
        "languages": None,
        "candidate_types": {"code_snippet", "command"},
        "patterns": [
            r"\$\{localEnv:HOME\}/\.ssh",
            r"source=\$\{localEnv:HOME\}/\.ssh,target=",
            r"target=/home/[^,\"]+/.ssh",
            r"(?i)\"--network=host\"",
            r"(?i)--network=host",
            r"(?i)docker\s+run\b[^\n]*--network=host",
        ],
        "risk_tags": ["credential_exposure", "container_escape_risk", "host_network", "overbroad_permission"],
        "reason": "Container or devcontainer configuration mounts host secrets or uses host networking.",
    },
    {
        "rule_id": "docker_compose_database_exposed_with_credentials",
        "cwes": ["CWE-798", "CWE-259", "CWE-200", "CWE-284"],
        "languages": {"yaml", "yml", "docker", "compose"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?is)MYSQL_ROOT_PASSWORD\s*:\s*[^\s#'\"]{4,}.{0,800}['\"]3306:3306['\"]",
            r"(?is)POSTGRES_PASSWORD\s*:\s*[^\s#'\"]{4,}.{0,800}['\"]5432:5432['\"]",
            r"(?is)REDIS_PASSWORD\s*:\s*[^\s#'\"]{4,}.{0,800}['\"]6379:6379['\"]",
            r"(?is)SPRING_DATASOURCE_PASSWORD\s*:\s*[^\s#'\"]{4,}",
            r"(?is)MYSQL_PASSWORD\s*:\s*[^\s#'\"]{4,}",
        ],
        "risk_tags": ["hardcoded_secret", "credential_exposure", "public_exposure", "database_exposure"],
        "reason": "Docker Compose configuration hardcodes database credentials and/or exposes database service ports.",
    },
    {
        "rule_id": "admin_credentials_in_curl",
        "cwes": ["CWE-798", "CWE-259", "CWE-521"],
        "languages": {"bash", "shell", "sh"},
        "candidate_types": {"command", "code_snippet"},
        "patterns": [
            r"(?i)curl\b[^\n]*auth/login[^\n]*['\"]username['\"]\s*:\s*['\"]admin['\"][^\n]*['\"]password['\"]\s*:\s*['\"]admin[0-9A-Za-z_-]*['\"]",
            r"(?i)curl\b[^\n]*login[^\n]*-d\s+['\"][^'\"]*(admin|root)[^'\"]*(password|admin123|changeme)[^'\"]*['\"]",
            r"(?i)admin_token\s*=\s*\$\(\s*curl\b[^\n]*(admin|root)[^\n]*(password|admin123|changeme)",
        ],
        "risk_tags": ["hardcoded_secret", "weak_default_password", "credential_exposure"],
        "reason": "Executable curl command contains hardcoded admin or default credentials.",
    },
    {
        "rule_id": "auth_token_in_local_storage",
        "cwes": ["CWE-922", "CWE-200", "CWE-312"],
        "languages": {"javascript", "js", "typescript", "ts", "jsx", "tsx"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"localStorage\.setItem\(\s*['\"]token['\"]",
            r"localStorage\.setItem\(\s*['\"]access_token['\"]",
            r"localStorage\.setItem\(\s*['\"]auth[_-]?token['\"]",
            r"localStorage\.setItem\(\s*['\"]user['\"]\s*,\s*JSON\.stringify",
            r"sessionStorage\.setItem\(\s*['\"]token['\"]",
        ],
        "risk_tags": ["client_side_secret_storage", "credential_exposure", "information_exposure"],
        "reason": "Authentication token or user data is stored in browser localStorage/sessionStorage.",
    },
    {
        "rule_id": "jwt_verification_disabled",
        "cwes": ["CWE-287", "CWE-306", "CWE-862", "CWE-347"],
        "languages": None,
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"(?i)\bverify_jwt\s*=\s*false\b",
            r"(?i)\bjwt[_-]?verify\s*[:=]\s*false\b",
            r"(?i)\bJWT_VERIFY\s*=\s*false\b",
            r"(?i)\bdisable[_-]?jwt[_-]?verification\b",
        ],
        "risk_tags": ["auth_bypass", "missing_authentication", "jwt_verification_disabled"],
        "reason": "JWT verification appears disabled for an endpoint or function.",
    },
    {
        "rule_id": "sensitive_hardware_or_crypto_debug_logging",
        "cwes": ["CWE-532", "CWE-200", "CWE-215"],
        "languages": {"c", "cpp", "h", "hpp", "objectivec"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"ESP_LOG_BUFFER_HEX",
            r"ESP_LOG_BUFFER_HEX_LEVEL",
            r"(?i)\blog[_a-z]*\([^)]*(apdu|atr|pin|puk|key|secret|token|password)",
            r"(?i)\bprintf\([^)]*(apdu|atr|pin|puk|key|secret|token|password)",
        ],
        "risk_tags": ["sensitive_logging", "information_exposure", "debug_logging"],
        "reason": "Security-sensitive hardware, smart-card, crypto, or authentication data appears to be logged.",
    },
    {
        "rule_id": "untrusted_url_browser_navigation",
        "cwes": ["CWE-918", "CWE-601", "CWE-20"],
        "languages": {"javascript", "js", "typescript", "ts"},
        "candidate_types": {"code_snippet"},
        "patterns": [
            r"const\s*\{\s*url\s*\}\s*=\s*message\.body",
            r"await\s+page\.goto\(\s*url\s*\)",
            r"page\.goto\([^)]*message\.body",
            r"puppeteer\.launch",
        ],
        "risk_tags": ["ssrf", "untrusted_url", "browser_automation_risk"],
        "reason": "Browser automation navigates to externally supplied URLs.",
    },
]


ABSTRACTION_PREFERENCE = {
    "Variant": 0,
    "Base": 1,
    "Class": 2,
    "Pillar": 3,
    "Category": 4,
    "": 5,
}


SECURITY_KEYWORDS = {
    "sql",
    "query",
    "execute",
    "exec",
    "shell",
    "subprocess",
    "system",
    "eval",
    "pickle",
    "yaml",
    "load",
    "deserialize",
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "auth",
    "authentication",
    "authorization",
    "permission",
    "chmod",
    "tls",
    "ssl",
    "certificate",
    "verify",
    "insecure",
    "path",
    "file",
    "upload",
    "download",
    "innerhtml",
    "html",
    "script",
    "xss",
    "cors",
    "csrf",
    "docker",
    "privileged",
    "curl",
    "wget",
    "bash",
    "sh",
}

STOP_TERMS = {
    "or", "and", "if", "for", "to", "of", "in", "on", "by", "as", "is",
    "v1", "v2", "v3", "api", "user", "data", "value", "max", "min",
    "true", "false", "none", "null", "tmp", "test", "demo",
}

COMMAND_SECURITY_KEYWORDS = {
    "curl", "wget", "bash", "sh", "sudo", "chmod", "chown",
    "rm", "docker", "privileged", "token", "secret", "password",
    "key", "insecure", "verify", "ssl", "tls", "firewall",
    "iptables", "ufw", "ssh", "scp", "eval", "exec",
}

EXCLUDED_CWES = {
    "CWE-1071",  # Empty Code Block
    "CWE-561",   # Dead Code
    "CWE-570",   # Expression Always False
    "CWE-571",   # Expression Always True
    "CWE-398",   # Indicator of Poor Code Quality
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build constrained CWE candidate options for each extracted candidate.")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--semgrep-findings", type=Path, default=None)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--catalog-cache", type=Path, default=Path("analysis/output/cwe_catalog_full.json"))
    p.add_argument("--mitre-top-k", type=int, default=5)
    p.add_argument("--max-options", type=int, default=12)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--no-progress", action="store_true", help="Disable progress bar.")
    return p.parse_args()


def iter_progress(items: list[dict[str, Any]], *, enabled: bool, desc: str) -> Any:
    if enabled and tqdm is not None:
        return tqdm(items, desc=desc, unit="candidate")
    return items


def load_jsonl(path: Path | None, limit: int = 0) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
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


def normalize_lang(value: Any) -> str:
    return str(value or "").strip().lower().split(":", 1)[0]


def normalize_candidate_type(value: Any) -> str:
    return str(value or "").strip().lower()


def tokenize(value: Any) -> list[str]:
    return [tok for tok in re.findall(r"[a-z0-9_]+", str(value or "").lower()) if len(tok) >= 2]

def filter_security_terms(terms: list[str]) -> list[str]:
    out: list[str] = []
    for term in terms:
        term = str(term or "").strip().lower()
        if not term:
            continue
        if term == "sk":
            out.append(term)
            continue
        if term in STOP_TERMS:
            continue
        if len(term) < 3:
            continue
        if re.fullmatch(r"[a-f0-9]{20,}", term):
            continue
        if re.fullmatch(r"[a-z0-9_-]{30,}", term):
            continue
        out.append(term)
    return sorted(set(out))

def compact_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def candidate_query(candidate: dict[str, Any]) -> str:
    parts = [
        str(candidate.get("candidate_type") or ""),
        str(candidate.get("language_hint") or ""),
        str(candidate.get("content") or ""),
    ]
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    parts.append(str(metadata.get("preceding_user_text") or ""))
    return "\n".join(parts)


def extract_api_and_risk_terms(content: str) -> list[str]:
    terms: list[str] = []

    api_patterns = [
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\s*\(",
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(",
        r"\b[A-Z][A-Za-z0-9_]*\b",
        r"--[a-zA-Z0-9_-]+",
    ]

    for pattern in api_patterns:
        for match in re.findall(pattern, content):
            terms.extend(tokenize(match))

    for tok in tokenize(content):
        if tok in SECURITY_KEYWORDS:
            terms.append(tok)

    return sorted(set(terms))[:40]


def build_cwe_search_query(candidate: dict[str, Any], matched_terms: list[str], risk_tags: list[str]) -> str:
    lang = normalize_lang(candidate.get("language_hint"))
    ctype = normalize_candidate_type(candidate.get("candidate_type"))
    content = str(candidate.get("content") or "")

    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    preceding = str(metadata.get("preceding_user_text") or "")

    extracted_terms = extract_api_and_risk_terms(content)

    preceding_terms = [
        tok
        for tok in tokenize(preceding)
        if tok in SECURITY_KEYWORDS or tok in {"login", "upload", "database", "admin", "server", "deploy"}
    ][:20]

    query_terms = [
        ctype,
        lang,
        *risk_tags,
        *filter_security_terms(matched_terms),
        *filter_security_terms(extracted_terms),
        *filter_security_terms(preceding_terms),
    ]

    query = " ".join(tok for tok in query_terms if tok)
    return compact_whitespace(query)[:1500]


def catalog_by_cwe(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(entry.get("cwe")): entry for entry in catalog.get("entries") or [] if entry.get("cwe")}


def catalog_entry_text(entry: dict[str, Any]) -> str:
    return " ".join(
        [
            str(entry.get("cwe") or ""),
            str(entry.get("name") or ""),
            str(entry.get("title") or ""),
            str(entry.get("description") or ""),
            str(entry.get("abstraction") or ""),
        ]
    )


def infer_catalog_risk_tags(entry: dict[str, Any]) -> list[str]:
    text = catalog_entry_text(entry).lower()
    tags: list[str] = []

    tag_rules = {
        "sql_injection": ["sql", "database query"],
        "command_injection": ["command injection", "os command", "shell"],
        "hardcoded_secret": ["hard-coded", "password", "credential", "secret"],
        "unsafe_deserialization": ["deserialization", "deserialize"],
        "tls_disabled": ["certificate", "tls", "ssl", "cryptographic"],
        "overbroad_permission": ["permission", "authorization", "access control"],
        "xss": ["cross-site scripting", "html", "script"],
        "path_traversal": ["path traversal", "pathname", "file name"],
        "information_exposure": ["information exposure", "sensitive information"],
        "untrusted_download": ["download", "untrusted", "integrity"],
        "privilege_escalation": ["privilege", "least privilege"],
    }

    for tag, needles in tag_rules.items():
        if any(needle in text for needle in needles):
            tags.append(tag)

    return tags


def add_option(
    options: dict[str, dict[str, Any]],
    cwe: str,
    *,
    source: str,
    reason: str,
    catalog_entries: dict[str, dict[str, Any]],
    score_component: float = 0.0,
    matched_terms: list[str] | None = None,
    risk_tags: list[str] | None = None,
) -> None:
    if cwe in EXCLUDED_CWES:
        return

    if not re.fullmatch(r"CWE-\d+", cwe):
        return

    entry = catalog_entries.get(cwe, {})
    catalog_tags = infer_catalog_risk_tags(entry) if entry else []

    option = options.setdefault(
        cwe,
        {
            "cwe": cwe,
            "cwe_id": cwe,
            "name": entry.get("name") or "",
            "title": entry.get("title") or entry.get("name") or cwe,
            "abstraction": entry.get("abstraction") or "",
            "description": entry.get("description") or "",
            "url": entry.get("url") or "",
            "sources": [],
            "source": [],
            "reasons": [],
            "matched_terms": [],
            "risk_tags": [],
            "catalog_risk_tags": catalog_tags,
            "score_components": defaultdict(float),
            "score": 0.0,
        },
    )

    if source not in option["sources"]:
        option["sources"].append(source)
    if source not in option["source"]:
        option["source"].append(source)
    if reason and reason not in option["reasons"]:
        option["reasons"].append(reason)

    for term in matched_terms or []:
        term = str(term).strip().lower()
        if term and term not in option["matched_terms"]:
            option["matched_terms"].append(term)

    for tag in risk_tags or []:
        tag = str(tag).strip().lower()
        if tag and tag not in option["risk_tags"]:
            option["risk_tags"].append(tag)

    option["score_components"][source] = max(float(option["score_components"].get(source) or 0.0), float(score_component))


def semgrep_by_candidate(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cid = str(row.get("candidate_id") or "")
        if cid:
            out[cid].append(row)
    return out


def add_semgrep_options(
    options: dict[str, dict[str, Any]],
    semgrep_rows: list[dict[str, Any]],
    catalog_entries: dict[str, dict[str, Any]],
) -> None:
    for row in semgrep_rows:
        rule_id = str(row.get("rule_id") or "")
        evidence_text = " ".join([rule_id, str(row.get("evidence") or ""), str(row.get("message") or "")])
        for cwe in split_cwe_values(row.get("cwe", [])):
            add_option(
                options,
                cwe,
                source="semgrep_metadata",
                reason=f"Semgrep finding {rule_id or row.get('finding_id') or ''}".strip(),
                catalog_entries=catalog_entries,
                score_component=5.0,
                matched_terms=tokenize(evidence_text),
                risk_tags=[],
            )


def add_pattern_options(
    options: dict[str, dict[str, Any]],
    candidate: dict[str, Any],
    catalog_entries: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    lang = normalize_lang(candidate.get("language_hint"))
    ctype = normalize_candidate_type(candidate.get("candidate_type"))
    content = str(candidate.get("content") or "")

    all_matched_terms: list[str] = []
    all_risk_tags: list[str] = []

    for rule in PATTERN_RULES:
        languages = rule.get("languages")
        candidate_types = rule.get("candidate_types")

        if languages is not None and lang not in languages:
            continue
        if candidate_types is not None and ctype not in candidate_types:
            continue

        matched_terms: list[str] = []
        for pattern in rule["patterns"]:
            match = re.search(pattern, content, flags=re.I | re.S)
            if match:
                matched_terms.extend(tokenize(match.group(0))[:10])

        if not matched_terms:
            continue

        risk_tags = list(rule.get("risk_tags") or [])
        all_matched_terms.extend(matched_terms)
        all_risk_tags.extend(risk_tags)

        for cwe in rule["cwes"]:
            add_option(
                options,
                cwe,
                source="pattern_match",
                reason=rule["reason"],
                catalog_entries=catalog_entries,
                score_component=3.0,
                matched_terms=matched_terms,
                risk_tags=risk_tags,
            )

    return sorted(set(all_matched_terms)), sorted(set(all_risk_tags))

def should_run_mitre_search(
    candidate: dict[str, Any],
    options: dict[str, dict[str, Any]],
    matched_terms: list[str],
    risk_tags: list[str],
) -> bool:
    lang = normalize_lang(candidate.get("language_hint"))
    ctype = normalize_candidate_type(candidate.get("candidate_type"))

    weak_languages = {"diff", "patch", "markdown", "md", "text", "txt", "plaintext", ""}
    has_prior_signal = bool(options) or bool(risk_tags) or bool(matched_terms)

    query_terms = set(tokenize(candidate_query(candidate)))
    has_security_keyword = bool(query_terms & SECURITY_KEYWORDS)

    # diff / markdown / plaintext 很容易造成 MITRE 噪声，除非已有 pattern 或 Semgrep signal
    if lang in weak_languages and not has_prior_signal:
        return False

    # command candidate 不能只因为 candidate_type 是 command 就召回 command injection
    # 只有出现明确危险命令关键词，或者已经有 pattern/Semgrep signal，才跑 MITRE
    if ctype == "command" and not has_prior_signal:
        has_command_security_keyword = bool(query_terms & COMMAND_SECURITY_KEYWORDS)
        if not has_command_security_keyword:
            return False

    # 没有任何安全关键词，也没有 pattern/Semgrep，不跑 MITRE
    if not has_prior_signal and not has_security_keyword:
        return False

    return True

def add_mitre_search_options(
    options: dict[str, dict[str, Any]],
    candidate: dict[str, Any],
    catalog: dict[str, Any],
    catalog_entries: dict[str, dict[str, Any]],
    top_k: int,
    matched_terms: list[str],
    risk_tags: list[str],
) -> None:
    if not catalog.get("entries") or top_k <= 0:
        return
    
    if not should_run_mitre_search(candidate, options, matched_terms, risk_tags):
        return

    preferred = list(options)
    query = build_cwe_search_query(candidate, matched_terms, risk_tags)

    if not query:
        return

    results = search_full_catalog(catalog, query, top_k=top_k, prefer_cwes=preferred)
    if not results:
        return

    max_score = max(float(result.get("score") or 0.0) for result in results) or 1.0
    query_terms = set(tokenize(query))

    for result in results:
        cwe = str(result.get("cwe") or "")
        entry = catalog_entries.get(cwe, {})
        entry_terms = set(tokenize(catalog_entry_text(entry or result)))
        overlap = sorted(query_terms & entry_terms)[:12]

        normalized_score = float(result.get("score") or 0.0) / max_score

        add_option(
            options,
            cwe,
            source="mitre_search",
            reason="MITRE catalog search matched compact candidate risk query.",
            catalog_entries=catalog_entries,
            score_component=normalized_score,
            matched_terms=overlap,
            risk_tags=risk_tags,
        )


def abstraction_rank(row: dict[str, Any]) -> int:
    return ABSTRACTION_PREFERENCE.get(str(row.get("abstraction") or ""), 5)


def compute_final_score(row: dict[str, Any]) -> float:
    components = dict(row.get("score_components") or {})

    semgrep_score = float(components.get("semgrep_metadata") or 0.0)
    pattern_score = float(components.get("pattern_match") or 0.0)
    mitre_score = float(components.get("mitre_search") or 0.0)

    source_diversity_bonus = 0.25 * max(0, len(row.get("sources") or []) - 1)

    tags = set(row.get("risk_tags") or [])
    catalog_tags = set(row.get("catalog_risk_tags") or [])
    semantic_overlap_bonus = 0.5 if tags and catalog_tags and tags & catalog_tags else 0.0

    abstraction = str(row.get("abstraction") or "")
    too_specific_penalty = 0.0

    if abstraction == "Variant" and semgrep_score == 0 and pattern_score == 0:
        too_specific_penalty = 0.25

    final = semgrep_score + pattern_score + mitre_score + source_diversity_bonus + semantic_overlap_bonus - too_specific_penalty
    return round(final, 4)


def keep_option(row: dict[str, Any], candidate_risk_tags: list[str]) -> bool:
    sources = set(row.get("sources") or [])

    # Pattern / Semgrep 支持的 option 保留
    if "pattern_match" in sources or "semgrep_metadata" in sources:
        return True

    # MITRE-only 没有 risk tag，通常太弱
    if sources == {"mitre_search"}:
        risk_tags = set(candidate_risk_tags or [])
        catalog_tags = set(row.get("catalog_risk_tags") or [])

        if not risk_tags:
            return False

        # MITRE-only 必须和当前 candidate 的 risk_tags 语义对齐
        return bool(risk_tags & catalog_tags)

    return True


def sorted_options(
    options: dict[str, dict[str, Any]],
    max_options: int,
    candidate_risk_tags: list[str],
) -> list[dict[str, Any]]:
    rows = [row for row in options.values() if keep_option(row, candidate_risk_tags)]

    for row in rows:
        row["score"] = compute_final_score(row)

    rows.sort(
        key=lambda row: (
            -float(row.get("score") or 0.0),
            abstraction_rank(row),
            str(row.get("cwe") or ""),
        )
    )

    out: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()

    for row in rows:
        if len(out) >= max_options:
            break

        family = str(row.get("abstraction") or "unknown")
        if family_counts[family] >= max(3, max_options // 3):
            continue

        fixed = dict(row)
        fixed["sources"] = sorted(fixed.get("sources") or [])
        fixed["source"] = sorted(fixed.get("source") or fixed["sources"])
        fixed["reasons"] = list(fixed.get("reasons") or [])[:3]
        fixed["matched_terms"] = filter_security_terms(list(fixed.get("matched_terms") or []))[:20]
        fixed["risk_tags"] = sorted(set(fixed.get("risk_tags") or []))
        fixed["catalog_risk_tags"] = sorted(set(fixed.get("catalog_risk_tags") or []))
        fixed["score_components"] = {
            key: round(float(value), 4)
            for key, value in dict(fixed.get("score_components") or {}).items()
        }

        out.append(fixed)
        family_counts[family] += 1

    return out


def summarize_option_sources(candidate_options: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for option in candidate_options:
        for source in option.get("sources") or []:
            counts[str(source)] += 1
    return counts


def main() -> None:
    args = parse_args()

    candidates = load_jsonl(args.candidates, args.limit)
    semgrep = semgrep_by_candidate(load_jsonl(args.semgrep_findings))
    catalog = load_full_catalog_cache(args.catalog_cache)
    entries = catalog_by_cwe(catalog)

    counts: Counter[str] = Counter()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    progress_enabled = not args.no_progress

    with args.out.open("wb") as wf:
        for candidate in iter_progress(candidates, enabled=progress_enabled, desc="Building CWE candidates"):
            cid = str(candidate.get("candidate_id") or "")
            options: dict[str, dict[str, Any]] = {}

            semgrep_rows = semgrep.get(cid, [])
            add_semgrep_options(options, semgrep_rows, entries)

            pattern_terms, risk_tags = add_pattern_options(options, candidate, entries)

            add_mitre_search_options(
                options,
                candidate,
                catalog,
                entries,
                args.mitre_top_k,
                matched_terms=pattern_terms,
                risk_tags=risk_tags,
            )

            candidate_options = sorted_options(options, args.max_options, risk_tags)
            source_counts = summarize_option_sources(candidate_options)

            if semgrep_rows:
                counts["semgrep_matched_candidates"] += 1
            if pattern_terms:
                counts["pattern_matched_candidates"] += 1
            if candidate_options:
                counts["with_options"] += 1
            else:
                counts["without_options"] += 1

            for source, count in source_counts.items():
                counts[f"option_source:{source}"] += count

            row = {
                "candidate_id": cid,
                "chat_id": candidate.get("chat_id"),
                "turn_index": candidate.get("turn_index", candidate.get("message_index")),
                "candidate_type": candidate.get("candidate_type"),
                "language_hint": candidate.get("language_hint"),
                "semgrep_matched": bool(semgrep_rows),
                "pattern_matched": bool(pattern_terms),
                "risk_tags": risk_tags,
                "cwe_options": candidate_options,
                "candidate_cwe_options": candidate_options,
                "cwe_candidate_generation": {
                    "strategy": "semgrep_metadata + pattern_match + compact_mitre_search",
                    "mitre_top_k": args.mitre_top_k,
                    "max_options": args.max_options,
                    "catalog_cache_used": bool(catalog.get("entries")),
                },
            }

            wf.write(orjson.dumps(row) + b"\n")

    print(f"Candidates seen: {len(candidates)}")
    print(f"With CWE options: {counts['with_options']}")
    print(f"Without CWE options: {counts['without_options']}")
    print(f"Semgrep matched candidates: {counts['semgrep_matched_candidates']}")
    print(f"Pattern matched candidates: {counts['pattern_matched_candidates']}")
    print(f"Catalog cache used: {args.catalog_cache if catalog.get('entries') else 'none'}")
    print(f"Output: {args.out}")

    option_source_counts = {
        key.replace("option_source:", ""): value
        for key, value in counts.items()
        if key.startswith("option_source:")
    }
    if option_source_counts:
        print("CWE option source counts:")
        for source, count in sorted(option_source_counts.items()):
            print(f"  {source}: {count}")


if __name__ == "__main__":
    main()