# Trajectory Causal Attribution of Security Risks in Vibe-Coding Conversations

## Abstract
This project studies how security risks emerge and evolve in assistant-generated coding conversations. We build a pipeline that starts from risky assistant outputs, traces conversational context, attributes root causes, and quantifies risk trajectories over turns. On 381 risky samples, assistant-driven causes dominate (`56.69%` assistant-first vs `41.73%` user/context-first), with `assistant_over_implemented` as the largest attribution class (`51.18%`). Risk emergence is front-loaded (`58.06%` first appear at turn `0-1`) but escalation shows a long tail (mention-gap `p90=112`).

## 1. Method

### 1.1 Data and Processing Pipeline
We use conversation logs and metadata to build a multi-stage risk analysis pipeline:

1. Candidate extraction (`extract_candidates.py`): extract assistant outputs (code snippets, commands, security advice).
2. Risk judging (`judge_openrouter.py`): label risky vs non-risky findings and CWE tags.
3. Risk backtrace (`backtrace_risky_user_context.py`): map each risky finding to nearby user/assistant context.
4. Root-cause attribution (`judge_attribution_openrouter.py`): classify causal source.
5. Aggregation (`analyze_attribution_patterns.py` + `analyze_trajectory_metrics.py`): compute attribution and trajectory metrics.

### 1.2 Attribution Taxonomy (Operational Definitions)
Each risky finding is assigned one `primary_cause` from the following taxonomy.

- `user_requested_risk`: the user explicitly asks for insecure behavior or requests risky implementation choices.
- `assistant_over_implemented`: the user goal is benign/underspecified, but the assistant adds unnecessary risky details.
- `assistant_hallucinated_risk`: the assistant introduces risky content not grounded in user/context evidence.
- `inherited_or_context_risk`: risk originates from pasted context/logs/pre-existing insecure artifacts that are repeated or propagated.
- `mixed_causality`: multiple causes are strongly present and inseparable.
- `insufficient_evidence`: available evidence is not sufficient for reliable attribution.

For secondary analysis, sources are grouped as:

- `assistant_driven = {assistant_over_implemented, assistant_hallucinated_risk}`
- `user_driven = {user_requested_risk, inherited_or_context_risk}`
- `unclear = {mixed_causality, insufficient_evidence}`

### 1.3 Trajectory Metrics (Meaning and Formula)
To reduce notation burden, we use one conversation sample as a running mental model:

- `a`: turn where the assistant output is finally judged risky
- `m`: first turn where the risky concept is mentioned
- `c`: first turn where it becomes concrete/actionable
- `p`: first later turn where it is repeated/preserved

If a sample has `m=1, c=3, p=7, a=12`, then:
- mention gap = `12-1=11`
- concretization gap = `12-3=9`
- persistence gap = `12-7=5`

We use six metrics:

1. Risk Emergence Position  
Meaning: at which turn risk first shows up across conversations.  
Computation: for turn `t`,  
`P(first appears at t) = (# samples with m=t) / (# samples with observed m)`.

2. Risk Escalation Depth  
Meaning: how many turns it takes to move from early signal to final risky output.  
Computation:
- mention gap = `a - m`
- concretization gap = `a - c`
- persistence gap = `a - p`  
Reported as distribution summaries (median, p90).

3. User vs Assistant Initiation (proxy)  
Meaning: who mainly starts the insecure direction.  
Computation:
- `assistant_first_ratio = (# assistant_driven samples) / N`
- `user_first_ratio = (# user_driven samples) / N`

4. Assistant Security Regression Rate (proxy)  
Meaning: among assistant-driven samples, how often the assistant drifts from earlier safer state into risky output.  
Computation on assistant-driven subset `A`:
`regression_rate = (# samples in A with m < a) / |A|`.

5. Temporal Security Degradation Curve  
Meaning: probability that a conversation is still secure by turn `t`.  
Computation (discrete-time survival):
- `n_t`: samples still at risk set at turn `t`
- `d_t`: new risk-emergence events at turn `t`
- `S(t) = Π_{k<=t}(1 - d_k / n_k)`  
Interpretation: `S(t) = P(remaining secure | turn t)`.

6. Risk Introduction Source vs CWE  
Meaning: for each CWE class, whether it is mostly assistant-driven or user-driven.  
Computation for CWE `x`:
- `assistant_ratio(x) = n_assistant_driven(x) / n_total(x)`
- `user_ratio(x) = n_user_driven(x) / n_total(x)`

## 2. Results

### 2.1 Dataset Size
- Risky backtrace rows: `381`
- Attribution rows: `381`
- Joined analysis rows: `381`
- Attribution fallback rows (`judge_error`): `6`

Insight: the end-to-end join coverage is complete (`381 -> 381`), with a small fallback portion (`1.57%`).

Interpretation: the analysis is based on the full risky set, so the result patterns are not from sample truncation. The small fallback subset should still be treated as minor noise in fine-grained attribution splits.

### 2.2 Root-Cause Attribution Distribution
- `assistant_over_implemented`: `195/381` (`51.18%`)
- `inherited_or_context_risk`: `127/381` (`33.33%`)
- `user_requested_risk`: `32/381` (`8.40%`)
- `assistant_hallucinated_risk`: `21/381` (`5.51%`)
- `insufficient_evidence`: `6/381` (`1.57%`)
- `mixed_causality`: `0`

Insight: the dominant mode is assistant-side over-implementation, not explicit user demand for insecure behavior.

Interpretation: risk control should prioritize assistant generation policy and completion constraints, rather than relying primarily on user-intent filtering.

![Attribution Distribution](paper_figures/fig1_attribution_distribution.svg)

### 2.3 CWE Interpretation Guide (for Non-Security Readers)
| CWE | Plain Meaning | Example | Why It Matters |
|---|---|---|---|
| `CWE-312` | Sensitive information stored in plain text. | `OPENROUTER_API_KEY=sk-xxxx` in `.env` committed/logged. | Anyone with file/log access can directly reuse credentials. |
| `CWE-79` | Untrusted input rendered as HTML/JS (XSS). | `element.innerHTML = userComment` | Attacker script executes in victim browser session. |
| `CWE-327` | Weak/deprecated crypto algorithm is used. | `hashlib.md5(password.encode())` | Protection can be cracked or bypassed more easily. |
| `CWE-459` | Temporary/sensitive artifacts are not cleaned up. | `cp secrets.json /tmp/deploy-debug.json` and never removed | Residual files become unintended data exposure surfaces. |
| `CWE-522` | Credentials are insufficiently protected in storage/transit. | `Authorization: Basic base64(user:pass)` over unsafe channel | Credentials can be intercepted or recovered. |
| `CWE-200` | Sensitive internal information is exposed. | Error response contains DSN/password | Private data leakage helps attackers pivot. |
| `CWE-20` | Input validation is incomplete or missing. | User-controlled `id` used without checks | Malicious input can trigger unsafe behavior/injection paths. |
| `CWE-306` | Critical function lacks authentication. | `/admin/reset-db` callable without auth | Anyone can trigger privileged operations. |
| `CWE-321` | Cryptographic key is hard-coded. | `const KEY = 'my-static-key-123'` | Code leak implies key leak and decryptability. |
| `CWE-UNKNOWN` | Risk detected but not confidently mapped to a specific CWE. | Judge flags risk with ambiguous taxonomy | Treat as real risk signal with unresolved label granularity. |

### 2.4 CWE Concentration
Top CWE categories in current risky set:

- `CWE-312`: `110`
- `CWE-79`: `59`
- `CWE-UNKNOWN`: `44`
- `CWE-327`: `32`
- `CWE-459`: `32`

Insight: risk mass is concentrated in a few CWE families, especially secret/plaintext exposure and injection-like classes.

Interpretation: targeted mitigation on top CWE buckets is likely to produce disproportionate safety gains versus uniform mitigation across all CWE labels.

![Top CWE Counts](paper_figures/fig2_top_cwe_counts.svg)

### 2.5 Trajectory Findings
- Emergence coverage (has first mention): `279/381`
- Early emergence: `turn 0-1` accounts for `162/279` (`58.06%`)
- Escalation depth (median / p90):
  - mention gap: `12 / 112`
  - concretization gap: `14 / 104`
  - persistence gap: `24 / 116`

Insight: risk tends to appear early, but many cases continue to evolve over long turn horizons.

Interpretation: first-turn safeguards are necessary but insufficient; sustained multi-turn control is required to prevent late-stage security drift.

![Risk Emergence by Turn Bucket](paper_figures/fig3_risk_emergence_bucket.svg)

### 2.6 Initiation and Regression
- Assistant-first initiation (proxy): `216/381` (`56.69%`)
- User/context-first initiation (proxy): `159/381` (`41.73%`)
- Unclear initiation: `6/381` (`1.57%`)
- Assistant security regression rate (proxy): `121/216` (`56.02%`)

Representative regression rates by CWE (`n>=5` assistant-driven cases):
- `CWE-522`: `0.8750`
- `CWE-200`: `0.8125`
- `CWE-327`: `0.7857`
- `CWE-79`: `0.7097`
- `CWE-312`: `0.6829`

Insight: once an assistant-driven path starts, regression is common (`>50%`) and especially severe in several high-risk CWE families.

Interpretation: this pattern supports guardrails that monitor not only initial response quality but also turn-by-turn degradation.

![Assistant Regression by CWE](paper_figures/fig4_regression_by_cwe.svg)

### 2.7 Temporal Security Degradation Curves
Using turn-level first-risk events (`first_mention_turn`) and right-censoring when no mention is found before the risky assistant turn, we estimate a discrete-time survival curve.

- `P(remaining secure | turn t)` drops from `0.8924` at `t=0` to `0.5748` at `t=1`
- By `t=5`, remaining-secure probability is `0.4454`
- By `t=20`, remaining-secure probability is `0.2827`

Insight: security degradation is front-loaded, with a sharp early drop followed by a slower long-tail decline.

Interpretation: intervention latency matters. Delayed safeguards will miss a large fraction of degradations that occur in the first few turns.

![Temporal Security Degradation Curve](paper_figures/fig5_temporal_survival_curve.svg)

### 2.8 Risk Introduction Source vs CWE
We aggregate source attribution into three buckets (`assistant_driven`, `user_driven`, `unclear`) and compute per-CWE distributions.

Examples from high-frequency CWE groups:

- Strong assistant-driven: `CWE-459 (1.0000)`, `CWE-306 (0.9231)`, `CWE-200 (0.8000)`
- Strong user-driven: `CWE-312 (0.5727)`, `CWE-327 (0.5625)`, `CWE-UNKNOWN (0.5909)`

Insight: CWE classes exhibit distinct causal signatures rather than a single universal source pattern.

Interpretation: mitigation should be CWE-aware: assistant-side generation constraints for assistant-driven CWE, and stronger input/context sanitization for user-driven CWE.

Figure note: left panel shows CWE classes where assistant-driven ratio is dominant; right panel shows CWE classes where user-driven ratio is dominant.

![Attribution Source by CWE (Split by Dominant Source)](paper_figures/fig6_attribution_source_by_cwe.svg)

## 3. Interpretation
Overall, the evidence indicates that risk formation is both source-sensitive and trajectory-sensitive: assistant decisions dominate many classes, while degradation unfolds over multiple turns with substantial early failure risk.

## 4. Threats to Validity
- Attribution and initiation are model-assisted labels and can be prompt-sensitive.
- `CWE-UNKNOWN` remains non-trivial, limiting fine-grained security interpretation.
- Regression and initiation are proxy metrics, not manually adjudicated causal truth.
- A small subset (`6` rows) used error-fallback attribution and may add minor noise.

## 5. Reproducibility
The numbers in this document are computed from:

- `analysis/output/attribution_analysis_all/summary.json`
- `analysis/output/attribution_analysis_all/cwe_attribution.csv`
- `analysis/output/trajectory_analysis_all/summary.json`
- `analysis/output/trajectory_analysis_all/assistant_regression_by_cwe.csv`
- `analysis/output/trajectory_analysis_all/temporal_security_degradation_curve.csv`
- `analysis/output/trajectory_analysis_all/attribution_source_by_cwe.csv`

Figures are generated into tracked assets under:

- `paper_figures/fig1_attribution_distribution.svg`
- `paper_figures/fig2_top_cwe_counts.svg`
- `paper_figures/fig3_risk_emergence_bucket.svg`
- `paper_figures/fig4_regression_by_cwe.svg`
- `paper_figures/fig5_temporal_survival_curve.svg`
- `paper_figures/fig6_attribution_source_by_cwe.svg`
