# vibe-coding-risk

Security risk analysis pipeline for large-scale vibe-coding chat data.

This project analyzes assistant-generated code/replies in chat logs and maps risks to CWE categories using a hybrid approach:

- LLM-as-a-judge (high recall)
- Static rule scanning (high precision baseline)
- Dynamic validation (recommended for high-risk subsets)

## Dataset Assumptions

- Chat files are in `data/chats/*.md.json`
- Search metadata is in `data/searches.json`
- `searches.json` links each chat SHA to repository context

## Repository Structure

- `analysis/scripts/extract_candidates.py`: Extracts analyzable assistant outputs from chats
- `analysis/scripts/run_rule_scan.py`: Runs baseline regex rules and outputs findings
- `analysis/scripts/judge_openrouter.py`: Runs LLM-as-a-judge via OpenRouter
- `analysis/schema/candidate_record.schema.json`: Schema for extracted candidates
- `analysis/schema/risk_finding.schema.json`: Schema for findings
- `analysis/rules/cwe_seed.yaml`: Seed CWE mapping rules
- `analysis/prompts/judge_v1.md`: Prompt template for LLM judge

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

Optional:

```env
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_HTTP_REFERER=
OPENROUTER_APP_TITLE=vibe-coding-risk
```

## Quick Start

### 1. Extract candidates

Sample run (500 chats):

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

### 2. Static baseline scan

```bash
uv run python analysis/scripts/run_rule_scan.py \
  --candidates analysis/output/candidates_500.jsonl \
  --rules analysis/rules/cwe_seed.yaml \
  --out analysis/output/static_findings_500.jsonl \
  --summary-out analysis/output/static_summary_500.json
```

Included seed CWE patterns:

- `CWE-78` command execution patterns (e.g., `curl | bash`)
- `CWE-295` TLS verification disabled
- `CWE-798` hardcoded secrets
- `CWE-89` SQL string construction risk
- `CWE-79` dangerous HTML rendering APIs
- `CWE-22` path traversal-like file access pattern
- `CWE-327` weak hash usage

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

## Suggested Fusion Strategy

Combine judge/static/dynamic into one final score:

`risk_score = 0.4 * judge + 0.4 * static + 0.2 * dynamic`

Suggested final labels:

- `confirmed`: validated dynamically
- `likely`: judge and static agree
- `possible`: single-source signal

## Recommended Next Steps

1. Run a 500-chat pilot and inspect false positives.
2. Extend `analysis/rules/cwe_seed.yaml` with language-specific rules.
3. Build a manually labeled gold set (200-500 samples).
4. Run full dataset and report CWE/language/platform distributions.
