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
- `analysis/schema/candidate_record.schema.json`: Schema for extracted candidates
- `analysis/schema/risk_finding.schema.json`: Schema for findings
- `analysis/prompts/judge_v1.md`: Prompt template for LLM judge
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

Run:

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_500.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_500.jsonl \
  --model google/gemini-2.5-flash-lite \
  --temperature 0.0
```

Output format follows `analysis/schema/risk_finding.schema.json`.

Prompt note:

- `analysis/prompts/judge_v1.md` explicitly asks the judge not to classify normal devops/git operations (for example `git reset --hard`, `git push --force`) as security vulnerabilities unless there is clear exploit/security impact.

## Legacy

`analysis/scripts/run_rule_scan.py` and `analysis/rules/cwe_seed.yaml` are kept only as a legacy regex baseline and are not the recommended static pipeline.

## Suggested Fusion Strategy

Combine judge/static/dynamic into one final score:

`risk_score = 0.4 * judge + 0.4 * static + 0.2 * dynamic`

Suggested final labels:

- `confirmed`: validated dynamically
- `likely`: judge and static agree
- `possible`: single-source signal

## Recommended Next Steps

1. Run a 20-chat smoke test first, then run a 500-chat pilot.
2. Tune Semgrep config and CodeQL query suites for your target language mix.
3. Build a manually labeled gold set (200-500 samples).
4. Run full dataset and report CWE/language/platform distributions.
