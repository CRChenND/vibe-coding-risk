# vibe-coding-risk

`vibe-coding-risk` 是一个用于分析 coding-agent 多轮对话中安全风险形成过程的流水线。它不是只问“代码有没有 CWE”，而是在 CWE / Semgrep / LLM judge 之后继续分析：

- 风险出现在哪个 turn
- 风险是在什么 interaction stage 出现的
- 风险由用户、agent、修复过程、上下文丢失还是外部工具诱发
- 风险后续是保留、修复、放大、传播还是重新引入

完整链路：

```text
chat -> candidate -> risk finding -> risk episode -> attribution analysis -> human validation sample -> paper tables
```

## 1. 环境准备

需要 Python 3.11+ 和 `uv`。

```bash
uv sync
```

如果要跑 Semgrep 静态规则扫描，还需要安装 Semgrep：

```bash
python3 -m pip install semgrep
```

如果要跑 LLM judge / attribution，需要配置 OpenRouter API key：

```bash
cp .env.example .env
```

然后编辑 `.env`：

```bash
OPENROUTER_API_KEY=your_openrouter_api_key
```

可选环境变量：

```bash
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_HTTP_REFERER=https://your-project-url.example
OPENROUTER_APP_TITLE=vibe-coding-risk
```

## 2. 数据目录

原始聊天数据放在：

```text
data/chats/*.md.json
```

每个 chat JSON 需要包含类似结构：

```json
{
  "platform": "Cursor / Copilot",
  "timestamp": "2025-07-24 04:07:00",
  "messages": [
    {
      "role": "User",
      "blocks": [[{"type": "text", "content": "..."}]]
    },
    {
      "role": "Assistant",
      "blocks": [[{"type": "python", "content": "..."}]]
    }
  ]
}
```

分析输出默认写入：

```text
analysis/output/
```

该目录已在 `.gitignore` 中忽略，适合放大规模中间结果。

## 3. Step 1: 抽取候选代码和命令

从所有 chat 中抽取 assistant 生成的代码块和命令块：

```bash
uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --out analysis/output/candidates_all.jsonl
```

调试时可以先跑小样本：

```bash
uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --out analysis/output/candidates_sample.jsonl \
  --limit 100
```

输出记录包括：

- `candidate_id`
- `chat_id`
- `turn_index`
- `message_id`
- `role`
- `candidate_type`: `code_snippet` 或 `command`
- `language_hint`
- `content`
- `metadata.preceding_user_text`

## 4. Step 2: 跑 Semgrep 静态扫描

Semgrep 只扫描可识别语言的 `code_snippet` candidate：

```bash
uv run python analysis/scripts/run_semgrep_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --out analysis/output/semgrep_findings_all.jsonl \
  --summary-out analysis/output/semgrep_summary.json \
  --semgrep-config auto
```

常用参数：

- `--limit 1000`: 只扫描前 1000 条 candidate
- `--batch-size 1000`: 每批扫描多少个唯一 snippet
- `--timeout-sec 120`: Semgrep 每批超时时间

输出是 `risk_finding` 风格 JSONL，`analyzer` 为 `static_rule`。

## 5. Step 3: 构建受约束 CWE 候选集

不要让 LLM 自由生成 CWE。先为每个 candidate 构建候选 CWE options：

```bash
uv run python analysis/scripts/build_cwe_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --semgrep-findings analysis/output/semgrep_findings_all.jsonl \
  --out analysis/output/cwe_candidates_all.jsonl \
  --catalog-cache analysis/output/cwe_catalog_full.json \
  --mitre-top-k 5
```

这个脚本会综合：

- Semgrep metadata CWE
- candidate type / language
- 代码和命令中的风险模式
- 本地 MITRE CWE catalog cache 的检索结果

每个候选 CWE 会保留 provenance，例如：

```json
{
  "cwe_id": "CWE-89",
  "name": "Improper Neutralization of Special Elements used in an SQL Command",
  "source": ["semgrep", "pattern", "mitre_search"],
  "score": 12.0,
  "matched_terms": ["sql", "query", "execute"]
}
```

这些字段可以用来分析 Semgrep-derived、pattern-derived、MITRE-search-derived CWE mapping 的人工验证 precision。

如果 Semgrep 没命中，脚本仍然会用 pattern 和 MITRE search 生成候选；如果候选仍然很弱，后续 judge 可以输出 `primary_cwe=null` / `cwe=[]`，而不是强行 hallucinate CWE。

`unmapped` 不等于 non-risky。它表示 candidate 是 security-relevant，但在受约束候选集中没有干净映射到具体 CWE。这个状态对 command-level、workflow-level、deployment instruction、unsafe package recommendation 这类风险尤其重要。

如果还没有 MITRE catalog cache，可以先下载：

```bash
uv run python analysis/scripts/build_cwe_catalog.py \
  --out analysis/output/cwe_catalog_full.json
```

没有 cache 时也可以运行 `build_cwe_candidates.py`，只是不会加入 MITRE top-k 检索候选。

## 6. Step 4: 跑 LLM judge 做风险判断和受约束 CWE 选择

LLM judge 会逐条判断 candidate 是否是 actionable security risk，并且只能从 `cwe_candidates_all.jsonl` 里的候选 CWE 中选择。若没有合适 CWE，应输出 unmapped，而不是发明 CWE。

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_all.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --max-tokens 1400 \
  --workers 1
```

调试小样本：

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_sample.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_sample.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --limit 50
```

默认会启用 CWE verification prompt：

```text
analysis/prompts/cwe_verify_v1.md
```

如果只想跑初步 judge，不做 CWE 二次校验：

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_all.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_all.jsonl \
  --model openai/gpt-5.4-mini \
  --no-verify-cwe
```

judge 输出会包含：

- `primary_cwe`
- `cwe_ids`
- `cwe_abstraction`
- `cwe_confidence`
- `risk_confidence_tier`
- `cwe_confidence_tier`
- `cwe_specificity`: `specific` / `broad` / `ambiguous` / `unmapped`
- `needs_human_cwe_review`
- `rejected_cwes`

该脚本默认支持断点续跑。再次运行同一 `--out` 时，会读取已有 JSONL，跳过已有 `candidate_id`。每条结果写入后会立即 flush，降低中断时丢失已完成结果的概率。

如果上次运行中有 API 或解析失败产生的 fallback 行，默认也会被视为已完成。若希望续跑时重试这些失败行：

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_all.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_all.jsonl \
  --model openai/gpt-5.4-mini \
  --retry-failures
```

`--retry-failures` 会先压缩已有输出，移除失败行并保留每个 `candidate_id` 的最后一条成功记录，再继续处理。

## 7. 可选: No-Signal Candidate 审计

主流水线默认只 judge 有风险信号的 candidate。为了估计这套 signal gate 是否漏掉风险，可以从 no-signal candidates 中抽样，强制 LLM judge 全部样本，并导出人工审计 CSV。

先抽样 no-signal candidates：

```bash
uv run python analysis/scripts/sample_no_signal_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --out analysis/output/candidates_no_signal_sample_2000.jsonl \
  --sample-size 2000 \
  --seed 42 \
  --stratify-by-type
```

然后对这批样本强制 judge。这里必须加 `--judge-all`，否则 no-signal candidates 会被默认跳过：

```bash
uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_no_signal_sample_2000.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_no_signal_sample_2000.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --max-tokens 1400 \
  --workers 1 \
  --judge-all \
  --no-resume
```

快速汇总 no-signal 样本中的 risky rate：

```bash
uv run python - <<'PY'
import orjson
from pathlib import Path
from collections import Counter

path = Path("analysis/output/judge_findings_no_signal_sample_2000.jsonl")

n = 0
risky = 0
severity = Counter()
cwe = Counter()
unmapped = 0

for line in path.read_bytes().splitlines():
    if not line.strip():
        continue
    row = orjson.loads(line)
    n += 1
    if row.get("is_risky"):
        risky += 1
        severity[str(row.get("severity") or "unknown")] += 1
        if not row.get("cwe"):
            unmapped += 1
        for x in row.get("cwe") or []:
            cwe[str(x)] += 1

print("total judged:", n)
print("risky:", risky)
print("risky rate:", round(risky / n, 4) if n else 0)
print("severity:", dict(severity))
print("unmapped risky:", unmapped)
print("top cwe:", cwe.most_common(20))
PY
```

导出 risky no-signal rows 给人工检查：

```bash
uv run python analysis/scripts/export_risky_no_signal_audit.py \
  --candidates analysis/output/candidates_no_signal_sample_2000.jsonl \
  --judge-findings analysis/output/judge_findings_no_signal_sample_2000.jsonl \
  --out analysis/output/risky_no_signal_audit_2000.csv
```

这一步的目的不是替代主结果，而是估计候选召回和 signal gate 的 false-negative risk。论文或 appendix 中可以报告 no-signal audit 的 risky rate 和人工确认比例。

## 8. Step 5: 去重合并 Finding 文件

不要直接 `cat` Semgrep 和 LLM judge 输出，否则同一个 candidate 的同一个风险可能被重复计算。使用 merge 脚本按 `chat_id + candidate_id + CWE + risky_line_range` 合并，并保留 analyzer agreement：

```bash
mkdir -p analysis/output

uv run python analysis/scripts/merge_risk_findings.py \
  --candidates analysis/output/candidates_all.jsonl \
  --semgrep-findings analysis/output/semgrep_findings_all.jsonl \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --out analysis/output/risk_findings_all.jsonl
```

如果你暂时只想用 LLM judge：

```bash
uv run python analysis/scripts/merge_risk_findings.py \
  --candidates analysis/output/candidates_all.jsonl \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --out analysis/output/risk_findings_all.jsonl
```

如果你暂时只想用 Semgrep：

```bash
uv run python analysis/scripts/merge_risk_findings.py \
  --candidates analysis/output/candidates_all.jsonl \
  --semgrep-findings analysis/output/semgrep_findings_all.jsonl \
  --out analysis/output/risk_findings_all.jsonl
```

合并后的 finding 会增加：

- `analyzers`: `["semgrep", "llm_judge"]` 等
- `agreement`: `semgrep_only`、`llm_judge_only`、`both`
- `risk_confidence_tier`: risk 是否真实的置信层级
- `cwe_confidence_tier`: CWE mapping 是否准确的置信层级
- `confidence_tier`: legacy alias，等同于 `risk_confidence_tier`
- `source_finding_ids`
- `evidence.by_analyzer`

## 9. 可选: Risk Finding 人工标注前端

在进入 trajectory-level episode attribution 之前，可以先对 `risk_findings_all.jsonl` 做人工检查，尤其是：

- `llm_judge_only`
- `semgrep_only`
- `needs_human_cwe_review=true`
- high / critical severity
- `cwe_specificity=ambiguous` 或 `unmapped`

先把 finding 和 candidate 合成浏览器友好的精简 JSON。默认会构建 review units，而不是逐条 finding 标注。默认 scope 是 `chat_cwe`，也就是同一个 chat 里的同一个 CWE 会合成一个 review unit，便于同时对比不同文件里的同类风险。

- 每个 review unit 仍保留完整的 `finding_ids` / `candidate_ids`，前端会展开显示组内所有 candidates。

```bash
uv run python analysis/scripts/build_finding_annotation_dataset.py \
  --findings analysis/output/risk_findings_all.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --chats-dir data/chats \
  --out analysis/output/finding_annotation_dataset.json \
  --context-before 2 \
  --context-after 1
```

如果担心文件路径未知时过度合并，可以改用保守模式：

```bash
uv run python analysis/scripts/build_finding_annotation_dataset.py \
  --findings analysis/output/risk_findings_all.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --chats-dir data/chats \
  --out analysis/output/finding_annotation_dataset.json \
  --review-unit-scope file_turn_cwe \
  --no-group-unknown-file-by-turn
```

可选 scope：

- `chat_cwe`: 同一 chat + CWE 合并，最省人工，方便跨文件对比。
- `turn_cwe`: 同一 chat + turn + CWE 合并，适合避免跨较远 turn 合并。
- `file_turn_cwe`: 同一 chat + turn + file + CWE 合并，最保守。

如果只想优先检查 CWE 模糊样本：

```bash
uv run python analysis/scripts/build_finding_annotation_dataset.py \
  --findings analysis/output/risk_findings_all.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --chats-dir data/chats \
  --out analysis/output/finding_annotation_dataset_cwe_review.json \
  --only-needs-human-cwe-review
```

启动本地静态服务：

```bash
python3 -m http.server 8123
```

然后打开：

```text
http://localhost:8123/analysis/annotation_ui/
```

前端会默认读取 `analysis/output/finding_annotation_dataset.json`。左侧列表分页显示，severity 会作为主 badge；conversation context 会渲染基本 Markdown，并在对应 turn 附近插入正在审查的 candidate。一个 review unit 可能包含多个 findings/candidates，标注一次会覆盖组内所有 `finding_ids`。标注结果保存在浏览器 localStorage 中，可以导出：

- `risk_finding_human_annotations.jsonl`
- `risk_finding_human_annotations.csv`

把导出的 finding-level 人工标注反写回 findings：

```bash
uv run python analysis/scripts/apply_finding_human_validation.py \
  --findings analysis/output/risk_findings_all.jsonl \
  --human analysis/output/risk_finding_human_annotations.jsonl \
  --out analysis/output/risk_findings_verified.jsonl \
  --overwrite-cwe
```

如果已经生成了 `risk_findings_verified.jsonl`，后续构建 episode 时可以把 `--findings` 指向 verified 文件：

```bash
uv run python analysis/scripts/build_risk_episodes.py \
  --chats-dir data/chats \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_verified.jsonl \
  --out analysis/output/risk_episodes_all.jsonl \
  --window-before 4 \
  --window-after 2 \
  --merge-max-turn-distance 3 \
  --merge-strategy cwe_or_candidate_lineage
```

这个前端适合 finding-level 的第一轮人工质检；后面的 `sample_for_human_validation.py` / `apply_human_validation.py` 仍然用于 episode-level attribution 的正式抽样验证和 merge-back。

## 10. Step 6: 构建 Risk Episodes

Risk episode 是风险形成过程，不是单个 snippet。脚本会：

- 读取 risky findings
- 找到对应 candidate 的 `turn_index`
- 抽取风险前后若干 turn 的上下文窗口
- 只在 turn 距离足够近且 CWE / candidate lineage 相关时合并 finding
- 给 episode 增加 `risk_lineage_id` 和 `lineage_role`

```bash
uv run python analysis/scripts/build_risk_episodes.py \
  --chats-dir data/chats \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_all.jsonl \
  --out analysis/output/risk_episodes_all.jsonl \
  --window-before 4 \
  --window-after 2 \
  --merge-max-turn-distance 3 \
  --merge-strategy cwe_or_candidate_lineage
```

输出 schema：

```text
analysis/schema/risk_episode.schema.json
```

核心字段：

- `episode_id`
- `chat_id`
- `finding_ids`
- `candidate_ids`
- `risk_lineage_id`
- `lineage_role`: `introduced` 或 `propagated`
- `risk_turn_index`
- `episode_window`
- `confidence_tier`
- `cwe_ids`
- `evidence_quotes`
- `risk_summary`

此时 attribution 字段大多还是 `unknown` 或 preliminary label。

## 11. Step 7: LLM Risk Attribution

这一步不再判断“是否有漏洞”，而是判断风险如何在交互中形成：

- `interaction_stage`
- `risk_origin`
- `mechanism`
- `risk_evolution`
- `user_reaction`
- `evidence_turns`

```bash
uv run python analysis/scripts/attribute_risk_episodes.py \
  --episodes analysis/output/risk_episodes_all.jsonl \
  --chats-dir data/chats \
  --prompt analysis/prompts/risk_attribution_v1.md \
  --out analysis/output/risk_episode_attributions_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --fallback-wide \
  --fallback-window-before 8 \
  --fallback-window-after 4
```

`--fallback-wide` 是两阶段 attribution：第一阶段只用 episode builder 的 default window；如果关键标签仍为 `unknown` 或证据不足，脚本才对该 episode 临时扩展到 wide window 并进行第二次 LLM 调用。这样避免对全量 episode 做 wide attribution。

默认触发 wide fallback 的字段是：

```text
interaction_stage,risk_origin,mechanism
```

可以通过 `--fallback-unknown-fields` 调整，也可以用 `--fallback-max 100` 控制最多额外调用多少次。

调试小样本：

```bash
uv run python analysis/scripts/attribute_risk_episodes.py \
  --episodes analysis/output/risk_episodes_all.jsonl \
  --chats-dir data/chats \
  --prompt analysis/prompts/risk_attribution_v1.md \
  --out analysis/output/risk_episode_attributions_sample.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --limit 50 \
  --fallback-wide \
  --fallback-max 20
```

该脚本默认支持断点续跑。如果输出文件已存在，会跳过已有 `episode_id`。每条结果写入后会立即 flush。

如果要重试上次失败的 attribution 行：

```bash
uv run python analysis/scripts/attribute_risk_episodes.py \
  --episodes analysis/output/risk_episodes_all.jsonl \
  --chats-dir data/chats \
  --prompt analysis/prompts/risk_attribution_v1.md \
  --out analysis/output/risk_episode_attributions_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --retry-failures
```

`--retry-failures` 会先移除旧失败行，避免同一个 `episode_id` 在输出中重复出现。

如果要覆盖重跑：

```bash
uv run python analysis/scripts/attribute_risk_episodes.py \
  --episodes analysis/output/risk_episodes_all.jsonl \
  --chats-dir data/chats \
  --prompt analysis/prompts/risk_attribution_v1.md \
  --out analysis/output/risk_episode_attributions_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --no-resume
```

## 12. Step 8: 抽样给人工验证

生成 CSV，供人工验证 risk 是否真实、attribution label 是否正确。

```bash
uv run python analysis/scripts/sample_for_human_validation.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --out analysis/output/human_validation_sample.csv \
  --sample-size 300 \
  --stratify-by risk_origin,cwe_ids,interaction_stage
```

CSV 字段包括：

- `episode_id`
- `chat_id`
- `risk_turn_index`
- `candidate_id`
- `cwe_ids`
- `primary_cwe_llm`
- `cwe_abstraction_llm`
- `cwe_specificity_llm`
- `needs_human_cwe_review`
- `risk_summary`
- `analyzer_agreement`
- `risk_confidence_tier`
- `cwe_confidence_tier`
- `interaction_stage_llm`
- `risk_origin_llm`
- `mechanism_llm`
- `risk_evolution_llm`
- `user_reaction_llm`
- `evidence_turns`
- `human_is_valid_risk`
- `human_cwe_is_correct`
- `human_primary_cwe`
- `human_cwe_granularity`
- `human_interaction_stage`
- `human_risk_origin`
- `human_mechanism`
- `human_risk_evolution`
- `human_user_reaction`
- `human_notes`

抽样策略会优先纳入：

- high / critical severity episode
- Semgrep 和 LLM judge 覆盖不一致的 episode
- 按指定字段分层后的多样样本

## 13. Step 9: 合并人工验证结果

人工验证填完后，将 CSV 反哺回 episode JSONL。主分析应优先使用这个 verified 文件。

```bash
uv run python analysis/scripts/apply_human_validation.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --human-csv analysis/output/human_validation_sample_filled.csv \
  --out analysis/output/risk_episode_attributions_verified.jsonl \
  --report-out analysis/output/human_validation_report.json
```

作用：

- `human_is_valid_risk=false` 的 episode 会被标记为 `risk_confidence_tier=excluded`
- `human_primary_cwe` 会覆盖 LLM 的 `primary_cwe` / `cwe_ids`
- `human_cwe_granularity` 会更新 CWE mapping 质量
- 人工填写的 attribution label 会覆盖 LLM label
- 生成 `manual_validation_precision`
- 生成 `cwe_exact_precision` 和 `cwe_correction_rate`
- 生成 label correction rate 和 most confused labels

如果有两个 annotator，可以计算 Cohen's kappa：

```bash
uv run python analysis/scripts/apply_human_validation.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --human-csv analysis/output/human_validation_annotator_a.csv \
  --second-human-csv analysis/output/human_validation_annotator_b.csv \
  --out analysis/output/risk_episode_attributions_verified.jsonl \
  --report-out analysis/output/human_validation_report.json
```

报告会包含：

- `cohen_kappa_risk_validity`
- `cohen_kappa_risk_origin`
- `cohen_kappa_interaction_stage`
- `cohen_kappa_mechanism`

## 14. Step 10: 生成论文统计表

```bash
uv run python analysis/scripts/analyze_risk_attribution.py \
  --episodes analysis/output/risk_episode_attributions_verified.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_all.jsonl \
  --out-dir analysis/output/risk_attribution_tables \
  --confidence-tiers high,medium
```

如果想输出全量 appendix 表：

```bash
uv run python analysis/scripts/analyze_risk_attribution.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_all.jsonl \
  --out-dir analysis/output/risk_attribution_tables_full \
  --confidence-tiers all
```

输出目录中会生成：

```text
analysis/output/risk_attribution_tables/
  summary.json
  cwe_distribution.csv
  language_distribution.csv
  command_vs_code_risk_distribution.csv
  risk_origin_counts.csv
  interaction_stage_counts.csv
  mechanism_counts.csv
  risk_evolution_counts.csv
  user_reaction_counts.csv
  confidence_tier_distribution.csv
  risk_confidence_tier_distribution.csv
  cwe_confidence_tier_distribution.csv
  cwe_specificity_distribution.csv
  human_cwe_granularity_counts.csv
  human_validation_outcomes.csv
  analyzer_agreement.csv
  lineage_role_counts.csv
  risk_lineage_summary.csv
  interaction_stage_x_risk_origin.csv
  interaction_stage_x_cwe.csv
  risk_origin_x_user_reaction.csv
  mechanism_x_cwe.csv
  turn_depth_x_risk_probability.csv
  repair_debugging_x_severity.csv
```

这些表可以支持论文中的问题：

- repair/debugging turn 是否引入了不成比例的风险
- 风险更多是 agent-induced 还是 user-induced
- 用户是否很少质疑 risky code / command
- 某些漏洞是否在后续 turn 中传播
- CWE 是否掩盖了 interaction-level cause

论文中可以这样描述 CWE 标注设计：

```text
To reduce unconstrained CWE hallucination, we first construct a bounded CWE candidate set for each code or command candidate using static analyzer metadata, language- and pattern-specific heuristics, and retrieval over the MITRE CWE catalog. The LLM judge is then constrained to select from this candidate set or mark the risk as unmapped when no candidate is appropriate. Human validation separately assesses risk validity and CWE mapping granularity.
```

## 15. 一键顺序命令

完整跑一遍：

```bash
mkdir -p analysis/output

uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --out analysis/output/candidates_all.jsonl

uv run python analysis/scripts/run_semgrep_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --out analysis/output/semgrep_findings_all.jsonl \
  --summary-out analysis/output/semgrep_summary.json \
  --semgrep-config auto

uv run python analysis/scripts/build_cwe_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --semgrep-findings analysis/output/semgrep_findings_all.jsonl \
  --out analysis/output/cwe_candidates_all.jsonl \
  --catalog-cache analysis/output/cwe_catalog_full.json \
  --mitre-top-k 5

uv run python analysis/scripts/judge_openrouter.py \
  --candidates analysis/output/candidates_all.jsonl \
  --cwe-candidates analysis/output/cwe_candidates_all.jsonl \
  --prompt analysis/prompts/judge_v1.md \
  --out analysis/output/judge_findings_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0

uv run python analysis/scripts/merge_risk_findings.py \
  --candidates analysis/output/candidates_all.jsonl \
  --semgrep-findings analysis/output/semgrep_findings_all.jsonl \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --out analysis/output/risk_findings_all.jsonl

uv run python analysis/scripts/build_risk_episodes.py \
  --chats-dir data/chats \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_all.jsonl \
  --out analysis/output/risk_episodes_all.jsonl \
  --window-before 4 \
  --window-after 2 \
  --merge-max-turn-distance 3 \
  --merge-strategy cwe_or_candidate_lineage

uv run python analysis/scripts/attribute_risk_episodes.py \
  --episodes analysis/output/risk_episodes_all.jsonl \
  --chats-dir data/chats \
  --prompt analysis/prompts/risk_attribution_v1.md \
  --out analysis/output/risk_episode_attributions_all.jsonl \
  --model openai/gpt-5.4-mini \
  --temperature 0.0 \
  --fallback-wide \
  --fallback-window-before 8 \
  --fallback-window-after 4

uv run python analysis/scripts/sample_for_human_validation.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --out analysis/output/human_validation_sample.csv \
  --sample-size 300 \
  --stratify-by risk_origin,cwe_ids,interaction_stage

# Fill analysis/output/human_validation_sample.csv manually, save it as:
# analysis/output/human_validation_sample_filled.csv

uv run python analysis/scripts/apply_human_validation.py \
  --episodes analysis/output/risk_episode_attributions_all.jsonl \
  --human-csv analysis/output/human_validation_sample_filled.csv \
  --out analysis/output/risk_episode_attributions_verified.jsonl \
  --report-out analysis/output/human_validation_report.json

uv run python analysis/scripts/analyze_risk_attribution.py \
  --episodes analysis/output/risk_episode_attributions_verified.jsonl \
  --candidates analysis/output/candidates_all.jsonl \
  --findings analysis/output/risk_findings_all.jsonl \
  --out-dir analysis/output/risk_attribution_tables \
  --confidence-tiers high,medium
```

## 16. 快速 smoke test

只测试脚本能否运行，不跑完整 LLM：

```bash
uv run python -m compileall analysis/scripts

uv run python analysis/scripts/extract_candidates.py \
  --chats-dir data/chats \
  --out /tmp/vibe_candidates_smoke.jsonl \
  --limit 2
```

验证 candidate schema：

```bash
uv run python -c "import jsonschema, orjson, pathlib; schema=orjson.loads(pathlib.Path('analysis/schema/candidate_record.schema.json').read_bytes()); rows=pathlib.Path('/tmp/vibe_candidates_smoke.jsonl').read_bytes().splitlines(); [jsonschema.validate(orjson.loads(line), schema) for line in rows[:10]]; print('validated', min(10, len(rows)))"
```

## 17. 常见问题

### `Missing OPENROUTER_API_KEY`

确认 `.env` 存在，并包含：

```bash
OPENROUTER_API_KEY=...
```

### `semgrep command not found`

安装 Semgrep：

```bash
python3 -m pip install semgrep
```

或者跳过 Semgrep，只用 LLM judge：

```bash
uv run python analysis/scripts/build_cwe_candidates.py \
  --candidates analysis/output/candidates_all.jsonl \
  --out analysis/output/cwe_candidates_all.jsonl \
  --catalog-cache analysis/output/cwe_catalog_full.json \
  --mitre-top-k 5

uv run python analysis/scripts/merge_risk_findings.py \
  --candidates analysis/output/candidates_all.jsonl \
  --judge-findings analysis/output/judge_findings_all.jsonl \
  --out analysis/output/risk_findings_all.jsonl
```

### `ruff` 不存在

`ruff` 是 dev dependency。如果要跑 lint：

```bash
uv sync --extra dev
uv run ruff check analysis/scripts analysis/schema
```

### 输出太大

使用 `--limit` 先做小样本测试：

```bash
--limit 100
```

LLM judge 和 attribution 都会产生 API 成本，建议先用 sample 跑通。

## 18. 主要文件

```text
analysis/scripts/extract_candidates.py
analysis/scripts/run_semgrep_candidates.py
analysis/scripts/build_cwe_candidates.py
analysis/scripts/judge_openrouter.py
analysis/scripts/sample_no_signal_candidates.py
analysis/scripts/export_risky_no_signal_audit.py
analysis/scripts/merge_risk_findings.py
analysis/scripts/build_finding_annotation_dataset.py
analysis/scripts/apply_finding_human_validation.py
analysis/annotation_ui/
analysis/scripts/build_risk_episodes.py
analysis/scripts/attribute_risk_episodes.py
analysis/scripts/sample_for_human_validation.py
analysis/scripts/apply_human_validation.py
analysis/scripts/analyze_risk_attribution.py

analysis/prompts/judge_v1.md
analysis/prompts/cwe_verify_v1.md
analysis/prompts/risk_attribution_v1.md

analysis/schema/candidate_record.schema.json
analysis/schema/risk_finding.schema.json
analysis/schema/risk_episode.schema.json
```

## 19. 推荐分析顺序

第一次跑建议按这个顺序：

1. `extract_candidates.py --limit 100`
2. `run_semgrep_candidates.py --limit 100`
3. `build_cwe_candidates.py --limit 100`
4. `judge_openrouter.py --limit 20`
5. 可选 no-signal audit: `sample_no_signal_candidates.py` + `judge_openrouter.py --judge-all` + `export_risky_no_signal_audit.py`
6. `merge_risk_findings.py`
7. 可选 finding-level 人工质检: `build_finding_annotation_dataset.py` + `analysis/annotation_ui/` + `apply_finding_human_validation.py`
8. `build_risk_episodes.py`
9. `attribute_risk_episodes.py --limit 20`
10. `sample_for_human_validation.py --sample-size 20`
11. `apply_human_validation.py`
12. `analyze_risk_attribution.py`

确认输出合理后，再去掉 `--limit` 跑全量。
