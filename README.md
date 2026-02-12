# vibe-coding-risk

Security risk analysis pipeline for large-scale vibe-coding chat data.

This project analyzes assistant-generated code/replies in chat logs and maps risks to CWE categories using a hybrid approach:

- LLM-as-a-judge (high recall)
- Static analysis per repo with CodeQL first, Semgrep fallback
- Secret scanning with Gitleaks + detect-secrets
- Dynamic validation (recommended for high-risk subsets)

## Dataset Assumptions

- Chat files are in `data/chats/*.md.json`
- Search metadata is in `data/searches.json`
- `searches.json` links each chat SHA to repository context

## Repository Structure

- `analysis/scripts/extract_candidates.py`: Extracts analyzable assistant outputs from chats
- `analysis/scripts/run_static_hybrid.py`: Runs static analysis (CodeQL first, Semgrep fallback)
- `analysis/scripts/judge_openrouter.py`: Runs LLM-as-a-judge via OpenRouter
- `analysis/scripts/backtrace_risky_user_context.py`: Backtraces risky findings to user+assistant context
- `analysis/scripts/judge_attribution_openrouter.py`: Runs root-cause attribution judge on risky backtrace rows
- `analysis/scripts/analyze_attribution_patterns.py`: Aggregates attribution + conversation tracing + CWE cross tables
- `analysis/scripts/analyze_trajectory_metrics.py`: Computes trajectory causal attribution metrics from aggregated outputs
- `analysis/schema/candidate_record.schema.json`: Schema for extracted candidates
- `analysis/schema/risk_finding.schema.json`: Schema for findings
- `analysis/prompts/judge_v1.md`: Prompt template for LLM judge
- `analysis/prompts/attribution_judge_v1.md`: Prompt template for attribution judge
- `analysis/tools/findsecbugs/findsecbugs-plugin.jar`: Recommended FindSecBugs plugin location

## Setup (uv)

```bash
uv sync
```

Optional dev dependencies:

```bash
uv sync --extra dev
```

## Environment Variables

Copy and edit:

```bash
cp .env.example .env
```

Required:

```env
OPENROUTER_API_KEY=your_openrouter_api_key
```

## Quick Start

Recommended order:

1. Extract candidates
2. Run static analysis (repo-level)
3. Run LLM judge
4. Fuse results (optional)

### 1. Extract candidates

Smoke test (20 chats):

```bash
uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --searches-file data/searches.json \
  --out analysis/output/candidates_20.jsonl \
  --limit 20
```

Pilot run (500 chats):

```bash
uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --searches-file data/searches.json \
  --out analysis/output/candidates_500.jsonl \
  --limit 500
```

Full run:

```bash
uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --searches-file data/searches.json \
  --out analysis/output/candidates_all.jsonl
```

Candidate types:

- `code_snippet`
- `command`
- `security_advice`

Attribution labels:

- `generated`
- `copied_from_repo`
- `execution_log`
- `unclear`

### 2. Static analysis (per repo, then map findings back to chats)

Install tools first:

- CodeQL CLI: `codeql`
- Semgrep CLI: `semgrep`
- Gitleaks: `gitleaks`
- detect-secrets: `detect-secrets`
- Bandit: `bandit`
- gosec: `gosec`
- Cppcheck: `cppcheck`
- ShellCheck: `shellcheck`
- SpotBugs: `spotbugs`
- ESLint: `eslint`
- eslint-plugin-security (global npm package)

Example global install (macOS):

```bash
brew install gitleaks semgrep
uv tool install detect-secrets
brew install cppcheck shellcheck
brew install spotbugs eslint
npm install -g eslint-plugin-security
go install github.com/securego/gosec/v2/cmd/gosec@latest
uv tool install bandit
```

FindSecBugs plugin jar:

- Recommended location: `analysis/tools/findsecbugs/findsecbugs-plugin.jar`
- You can override via: `--findsecbugs-jar /path/to/findsecbugs-plugin.jar`

Verify:

```bash
codeql version
semgrep --version
gitleaks version
detect-secrets --version
bandit --version
gosec -version
cppcheck --version
shellcheck --version
spotbugs -version
eslint --version
```

If your chat-to-repo mapping is available locally, put repos under one root (supported layouts):

- `<repos_root>/<owner>/<repo>`
- `<repos_root>/<owner>__<repo>`

Smoke test (20-candidate file):

```bash
uv run python analysis/scripts/run_static_hybrid.py \
  --candidates analysis/output/candidates_20.jsonl \
  --repos-root /path/to/local/repos \
  --findsecbugs-jar analysis/tools/findsecbugs/findsecbugs-plugin.jar \
  --out analysis/output/static_findings_20.jsonl \
  --summary-out analysis/output/static_summary_20.json \
  --semgrep-config auto
```

Pilot run (500):

```bash
uv run python analysis/scripts/run_static_hybrid.py \
  --candidates analysis/output/candidates_500.jsonl \
  --repos-root /path/to/local/repos \
  --findsecbugs-jar analysis/tools/findsecbugs/findsecbugs-plugin.jar \
  --out analysis/output/static_findings_500.jsonl \
  --summary-out analysis/output/static_summary_500.json \
  --semgrep-config auto
```

Full run:

```bash
uv run python analysis/scripts/run_static_hybrid.py \
  --candidates analysis/output/candidates_all.jsonl \
  --repos-root /path/to/local/repos \
  --findsecbugs-jar analysis/tools/findsecbugs/findsecbugs-plugin.jar \
  --out analysis/output/static_findings_all.jsonl \
  --summary-out analysis/output/static_summary_all.json \
  --semgrep-config auto
```

Resume behavior:

- Default is `--resume` (enabled).
- Repo progress is checkpointed to a sidecar file: `<out>.repos_done.jsonl`.
- To force a fresh run, use `--no-resume`.

Behavior:

- Runs static analysis once per repo (not once per chat).
- Maps each repo finding back to all chats linked to that repo.
- Uses CodeQL first; if no CodeQL result, falls back to Semgrep.
- Also runs `gitleaks` and `detect-secrets` at repo level for secret exposure.
- Also runs language-specialized analyzers when available:
  - `Bandit` for Python repos
  - `gosec` for Go repos
  - `Cppcheck` for C/C++ repos
  - `ShellCheck` for shell-heavy repos
  - `SpotBugs + FindSecBugs` for Java repos (requires bytecode targets such as `target/classes` or built `.jar`)
  - `ESLint + eslint-plugin-security` for JS/TS/Vue repos
- If a repo is missing locally, falls back to Semgrep on extracted snippets for that repo's chats.
- Outputs unified `risk_finding` JSONL.

The summary file includes tool availability and fallback stats, for example:

- `codeql_available`
- `semgrep_available`
- `gitleaks_available`
- `detect_secrets_available`
- `bandit_available`
- `gosec_available`
- `cppcheck_available`
- `shellcheck_available`
- `spotbugs_available`
- `eslint_available`
- `findsecbugs_jar_exists`
- `repo_not_found`
- `errors_preview`

### 3. LLM-as-a-judge via OpenRouter

Default model:

- `google/gemini-2.5-flash-lite`

Pilot run (500):

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_500.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_500.jsonl \
  --model google/gemini-2.5-flash-lite \
  --temperature 0.0
```

Full run:

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_all.jsonl \
  --model google/gemini-2.5-flash-lite \
  --temperature 0.0
```

Resume behavior:

- Default is `--resume` (enabled), so already judged `candidate_id` rows in output are skipped.
- To rerun from scratch, use `--no-resume`.

Output format follows `analysis/schema/risk_finding.schema.json`.

Prompt note:

- `analysis/prompts/judge_v1.md` explicitly asks the judge not to classify normal devops/git operations (for example `git reset --hard`, `git push --force`) as security vulnerabilities unless there is clear exploit/security impact.

### 4. Backtrace risky findings to user and assistant context

This step links risky judge findings back to:

- nearest user prompt(s) before the risky assistant output
- extracted user command-like strings
- assistant block text and the matched risky candidate text

Smoke test (first 200 finding lines):

```bash
uv run python analysis/scripts/backtrace_risky_user_context.py \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --chats-dir data/chats \
  --out analysis/output/risky_backtrace_sample.jsonl \
  --csv-out analysis/output/risky_backtrace_sample.csv \
  --limit 200
```

Full run:

```bash
uv run python analysis/scripts/backtrace_risky_user_context.py \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --chats-dir data/chats \
  --out analysis/output/risky_backtrace_all.jsonl \
  --csv-out analysis/output/risky_backtrace_all.csv
```

Useful flags:

- `--lookback-users 3` to include up to N previous user messages
- `--all-findings` to include non-risky findings too (default is risky-only)

### 5. Attribution + causal pattern analysis

Step 5a: LLM attribution judge on risky backtrace rows.

Smoke test (first 50 rows):

```bash
uv run python analysis/scripts/judge_attribution_openrouter.py \
  --input analysis/output/risky_backtrace_all.jsonl \
  --prompt analysis/prompts/attribution_judge_v1.md \
  --out analysis/output/attribution_labels_sample.jsonl \
  --limit 50 \
  --model google/gemini-2.5-flash-lite \
  --temperature 0.0
```

Full run:

```bash
uv run python analysis/scripts/judge_attribution_openrouter.py \
  --input analysis/output/risky_backtrace_all.jsonl \
  --prompt analysis/prompts/attribution_judge_v1.md \
  --out analysis/output/attribution_labels_all.jsonl \
  --model google/gemini-2.5-flash-lite \
  --temperature 0.0
```

Resume behavior:

- Default is `--resume` (enabled), so already processed `finding_id` rows in output are skipped.
- To rerun from scratch, use `--no-resume`.
- To resume and retry rows that previously ended as `judge_error` fallback, add `--retry-errors`.

Step 5b: Aggregate conversation-level tracing and `CWE x attribution`.

```bash
uv run python analysis/scripts/analyze_attribution_patterns.py \
  --backtrace analysis/output/risky_backtrace_all.jsonl \
  --attribution analysis/output/attribution_labels_all.jsonl \
  --out-dir analysis/output/attribution_analysis_all
```

Outputs under `analysis/output/attribution_analysis_all`:

- `attribution_enriched.csv`: row-level merged risk + attribution + trace fields
- `conversation_tracing.csv`: `first_mention_turn`, `first_concretization_turn`, `first_persistence_turn`
- `cwe_attribution.csv`: per-CWE cause counts and ratios
- `summary.json`: headline metrics and attribution distribution

Step 5c (optional): trajectory causal attribution metrics.

```bash
uv run python analysis/scripts/analyze_trajectory_metrics.py \
  --enriched analysis/output/attribution_analysis_all/attribution_enriched.csv \
  --tracing analysis/output/attribution_analysis_all/conversation_tracing.csv \
  --out-dir analysis/output/trajectory_analysis_all
```

Outputs under `analysis/output/trajectory_analysis_all`:

- `risk_emergence_turn_distribution.csv`: `P(risk first appears at turn t)`
- `risk_emergence_bucket_distribution.csv`: early/late emergence buckets
- `risk_escalation_samples.csv`: per-sample turn gaps (`mention/concretization/persistence`)
- `assistant_regression_by_cwe.csv`: assistant security regression proxy by CWE
- `severity_by_mention_gap_bucket.csv`: severity distribution vs trajectory depth
- `summary.json`: trajectory headline metrics

Path consistency tip:

- For full runs, keep the suffix aligned across steps (for example `_all`): `attribution_labels_all.jsonl` -> `attribution_analysis_all/` -> `trajectory_analysis_all/`.
- You can use any custom directory names via `--out-dir`, but Step 5c inputs must match the Step 5b output directory you actually used.
