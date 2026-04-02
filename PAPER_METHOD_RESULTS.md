# Trajectory Causal Attribution of Security Risks in Vibe-Coding Conversations

## Abstract
This project studies how code risks emerge and evolve in assistant-generated coding conversations. To align the analysis with a code-risk framing, the main quantitative results below are restricted to a high-precision subset of risky `code_snippet` and `command` candidates, excluding `security_advice`, deterministically filtering former `CWE-UNKNOWN` rows that resolve to non-security operational actions, removing obvious false positives, and flagging local-only/context-dependent rows out of the paper-facing count. We further treat `first_concretization_turn`, rather than `first_mention_turn`, as the first reliable risk signal. On `1887` high-precision code-risk samples, assistant-driven causes still dominate (`51.83%` assistant-first vs `45.57%` user/context-first), with `assistant_over_implemented` as the largest attribution class (`47.75%`). Under this stricter trajectory definition, early emergence is more conservative (`17.31%` first become concrete at turn `0-1`), and escalation still shows a long tail (concretization-gap `p90=64`).

## 1. Method

### 1.1 Data and Processing Pipeline
We use conversation logs and metadata to build a multi-stage risk analysis pipeline:

1. Candidate extraction (`extract_candidates.py`): extract assistant outputs (code snippets, commands, security advice).
2. Risk judging (`judge_openrouter.py`): label risky vs non-risky findings and CWE tags.
3. Risk backtrace (`backtrace_risky_user_context.py`): map each risky finding to nearby user/assistant context.
4. Root-cause attribution (`judge_attribution_openrouter.py`): classify causal source.
5. Aggregation (`analyze_attribution_patterns.py` + `analyze_trajectory_metrics.py`): compute attribution and trajectory metrics.

For the paper's code-risk framing, the final reporting layer further filters risky findings to candidates of type `code_snippet` or `command`. This excludes `security_advice` from the main tables and figures so that explanation-only risks do not dominate code-risk statistics. In the high-precision version used below, we further remove obvious false positives and separate local-only/context-dependent rows from the final paper count.

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
- mention gap = `12-1=11` (secondary / weaker anchor)
- concretization gap = `12-3=9`
- persistence gap = `12-7=5`

Operationally, the trace code searches backward from the risky assistant turn and records the earliest earlier turn where the same risk-relevant keywords or patterns appear. That gives us a concrete turn index for `m`, `c`, and `p`, not a manually guessed date or narrative stage. In the final reporting below, however, `m` is treated as a weaker auxiliary trace field and `c` is treated as the first reliable risk onset.

We use six metrics, but treat `c` rather than `m` as the main risk-onset anchor because early mentions are often too weak or ambiguous to count as meaningful code risk.

1. Risk Emergence Position  
Meaning: at which turn risk first shows up across conversations.  
Computation: for turn `t`,  
`P(first becomes concrete at t) = (# samples with c=t) / (# samples with observed c)`.

2. Risk Escalation Depth  
Meaning: how many turns it takes to move from early signal to final risky output.  
Computation:
- mention gap = `a - m` (reported only as a secondary trace field)
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
`regression_rate = (# samples in A with c < a) / |A|`.

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

For the main paper framing, we emphasize `concretization gap = a - c`, where `c` is the first earlier turn where the risky idea becomes concrete enough to count as a real risk signal. `p90=64` means that 90% of observed concretization gaps are 64 turns or smaller, so a long tail of cases still takes dozens of turns to fully surface.

For `assistant security regression`, we use the proxy `c < a` inside assistant-driven cases. In plain language, that means the conversation already had an earlier concrete risky step, and the assistant later carried or escalated it into the final risky output.

## 2. Results

### 2.1 Dataset Size
- All risky rows before code-risk filtering: `3174`
- Initial code-risk rows (`code_snippet` + `command`): `2264`
- Excluded `security_advice` rows: `759`
- Additional rows deterministically excluded from former `CWE-UNKNOWN` as non-security operational actions: `151`
- Additional audit exclusions from the code-risk slice: `71` obvious false positives and `306` local-only/context-dependent rows
- Final high-precision code-risk rows used for paper percentages: `1887`
- Rows with first-concretization trace coverage: `1034/1887` (`54.80%`)

Insight: under the final high-precision code-risk framing, `59.45%` of risky findings remain in scope. The removed portion is not only explanation-oriented `security_advice`, but also a substantial set of former `CWE-UNKNOWN` rows that resolve to operational cleanup, placeholder templates, or maintenance actions, plus rows that are better interpreted as obvious false positives or purely local-only development context.

Interpretation: this filter materially changes the empirical picture, especially for CWE families with large advice-only, operational-only, or local-dev-only components. Trace-based metrics still rely on partial observability because `45.20%` of high-precision code-risk rows do not have an automatically recovered first-concretization turn.

### 2.2 Root-Cause Attribution Distribution
- `assistant_over_implemented`: `901/1887` (`47.75%`)
- `inherited_or_context_risk`: `663/1887` (`35.14%`)
- `user_requested_risk`: `197/1887` (`10.44%`)
- `assistant_hallucinated_risk`: `77/1887` (`4.08%`)
- `insufficient_evidence`: `48/1887` (`2.54%`)
- `mixed_causality`: `1/1887` (`0.05%`)

Insight: the dominant mode is assistant-side over-implementation, not explicit user demand for insecure behavior.

Interpretation: risk control should prioritize assistant generation policy and completion constraints, rather than relying primarily on user-intent filtering.

Empirical evidence (anonymized excerpts):

- `assistant_over_implemented` (`finding_id=da1bf1a20fb28fad33ec76e6`): assistant injects DOM content with `innerHTML`-style behavior beyond the user’s stated need, creating a client-side injection risk.
- `inherited_or_context_risk` (`finding_id=89e53a152280d63793f9f874`): user/context already contains secrets, and assistant repeats those secrets in deployment guidance, propagating sensitive exposure.
- `user_requested_risk` (`finding_id=d089c3e04ea43a7a932c9e3e`): user asks to wire sensitive runtime configuration through `.env`, and assistant operationalizes that request by materializing credential-bearing configuration.
- `assistant_hallucinated_risk` (`finding_id=6df75cb2e281bb09a4f2fbcc`): user asks for generic troubleshooting, but assistant introduces destructive command advice (`rm -rf ...`) without grounded necessity.

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
| `CWE-UNKNOWN` | Legacy placeholder for risks that were originally unlabeled. | Empty-CWE row before deterministic reclassification | Not used as a final reporting bucket in this code-risk version. |

### 2.4 CWE Concentration
Top CWE categories in current risky set:

- `CWE-312`: `509`
- `CWE-79`: `258`
- `CWE-20`: `174`
- `CWE-200`: `169`
- `CWE-327`: `103`

Insight: once former `CWE-UNKNOWN` rows are deterministically reassigned where possible, the top buckets are dominated by plaintext secret handling, injection/validation problems, and information exposure. Residual `CWE-UNKNOWN` no longer appears in the top five.

Interpretation: targeted mitigation on top CWE buckets is likely to produce disproportionate safety gains versus uniform mitigation across all CWE labels.

Empirical risky snippets (assistant output only, anonymized):

- `CWE-312` example (`finding_id=89e53a152280d63793f9f874`):
```text
OPENROUTER_API_KEY=<API_KEY>
RUNWARE_API_KEY=<API_KEY>
```

- `CWE-79` example (`finding_id=00299d719beaaee7447f81ed`):
```text
<script src="/scripts.js"></script>
```

- `CWE-20` example (`finding_id=3f8589c53e7ce0f4d61b987d`):
```text
rm -rf apps/ledger-live-mobile/.git
```

- `CWE-200` example (`finding_id=b6a67420e9980166dff80423`):
```text
export https_proxy="http://${hostip}:7890"
export all_proxy="socks5://${hostip}:7891"
```

- `CWE-327` example (`finding_id=4358f313ed5425ee38785147`):
```text
echo MONGO_URL=mongodb+srv://<user>:<password>@cluster0.example.mongodb.net/expense-management >> utils/.env
```

![Top CWE Counts](paper_figures/fig2_top_cwe_counts.svg)

### 2.4.1 Deterministic Replacement of Former `CWE-UNKNOWN` Rows
The original code-risk slice contained `285` rows with empty or unresolved CWE labels. We first reused the manual audit of `68` reviewed code-risk rows, then extended those reviewed patterns into a deterministic remapping layer over the remaining unknown rows.

Replacement outcome over the original `285` unknown-code rows:

| Outcome | Count | Share |
|---|---:|---:|
| Reassigned to deterministic CWE | `134` | `47.02%` |
| Excluded as non-security operational action | `151` | `52.98%` |
| Residual `CWE-UNKNOWN` after remapping | `0` | `0.00%` |

Most common deterministic replacements:

| New CWE | Count from former `UNKNOWN` rows | Typical pattern |
|---|---:|---|
| `CWE-200` | `61` | Local HTTP servers, public tunnel exposure, env/config inspection, sensitive file access |
| `CWE-319` | `31` | Plaintext/local HTTP endpoints and unsecured transport references |
| `CWE-798` | `16` | Hardcoded bearer tokens, cookies, passwords, DSN credentials |
| `CWE-1104` | `9` | Dependency/package-install patterns with risky supply-chain implications |
| `CWE-522` | `10` | Variable-based bearer tokens or unencrypted/private-key credential handling |

Reclassified labels:

| Reclassified label | Count | Share | How we interpret it |
|---|---:|---:|---|
| `true_security_risk` | `5` | `7.35%` | Clear code/security issue that should stay in the code-risk analysis. |
| `conditional_security_risk` | `33` | `48.53%` | Context-dependent: can become a code/security issue in the wrong deployment or usage setting. |
| `not_security_risk` | `30` | `44.12%` | Operational or maintenance risk, but not a direct code security vulnerability. |

Insight: within the reviewed code-risk subset, only a very small minority are clear code-security issues; nearly half are context-dependent, and the rest are operational rather than code-security risks.

Interpretation: this is strong evidence against treating raw `CWE-UNKNOWN` as a first-class bucket in a code-risk paper. In this corpus, every formerly unknown code-risk row can now be either deterministically reassigned into concrete disclosure, transport, credential, and dependency CWEs, or dropped as non-security operational actions.

Representative evidence:
- `true_security_risk` (`finding_id=e0ae30b72df9d051062ab16d`): assistant outputs a hardcoded bearer JWT in command.
- `true_security_risk` (`finding_id=7e342843f087bd402dd73e7e`): assistant sets weak static secret `SESSION_SECRET=dev-secret-key-123`.
- `conditional_security_risk` (`finding_id=b8138cc4b2d2c8f20d991b73`): `npx http-server -p 8080` (safe in local dev, risky if exposed).
- `not_security_risk` (`finding_id=82cf1bf7edffd0bae5dadcb0`): `git push --force origin main` (operational integrity risk, not a direct software vulnerability).

### 2.4.2 CWE Labels That Need Splitting Under a Code-Risk Framing
Some CWE labels contain a large `security_advice` component in the full dataset and therefore need explicit splitting or careful wording when the paper focuses on code risk.

Using `security_advice_share >= 25%` and `total >= 20` as a review threshold, the main split candidates are:

- `CWE-327`: `56/182` (`30.77%`) are `security_advice`
- `CWE-522`: `47/139` (`33.81%`) are `security_advice`
- `CWE-798`: `32/73` (`43.84%`) are `security_advice`
- `CWE-306`: `36/61` (`59.02%`) are `security_advice`
- `CWE-284`: `26/36` (`72.22%`) are `security_advice`
- `CWE-257`: `13/29` (`44.83%`) are `security_advice`
- `CWE-287`: `21/21` (`100.00%`) are `security_advice`

Insight: not all CWE labels are equally stable across task framing. Some remain mostly code/command based, while others partially collapse once explanation-only advice is removed.

Interpretation: in a code-risk paper, these CWE families should either be reported with candidate-type filtering, or explicitly split into `code/command` versus `advice/explanation` variants.

### 2.5 Trajectory Findings
- Emergence coverage (has first concretization): `1034/1887`
- Early emergence: `turn 0-1` accounts for `179/1034` (`17.31%`)
- Escalation depth (median / p90):
  - mention gap (secondary): `6 / 69`
  - concretization gap: `6 / 64`
  - persistence gap: `8 / 76`

Insight: once we require the signal to be concrete rather than merely mentioned, risk looks less front-loaded than before, but many cases still evolve over long turn horizons.

Interpretation: first-turn safeguards still matter, but a large share of code risk is only becoming concrete after the opening turns, so sustained multi-turn control remains necessary.

![Risk Emergence by Turn Bucket](paper_figures/fig3_risk_emergence_bucket.svg)

### 2.6 Initiation and Regression
- Assistant-first initiation (proxy): `978/1887` (`51.83%`)
- User/context-first initiation (proxy): `860/1887` (`45.57%`)
- Unclear initiation: `49/1887` (`2.60%`)
- Assistant security regression rate (proxy): `280/978` (`28.63%`)

Representative regression rates by CWE (`n>=5` assistant-driven cases):
- `CWE-312`: `0.4105`
- `CWE-79`: `0.2960`
- `CWE-20`: `0.2031`
- `CWE-200`: `0.2439`
- `CWE-459`: `0.0000`

Insight: under the stricter concretization-based anchor, assistant regression is still substantial but clearly lower than the older mention-based estimate.

Interpretation: this pattern supports guardrails that monitor not only initial response quality but also turn-by-turn degradation.

![Assistant Regression by CWE](paper_figures/fig4_regression_by_cwe.svg)

### 2.7 Temporal Security Degradation Curves
Using turn-level first-risk events (`first_concretization_turn`) and right-censoring when no concretization is found before the risky assistant turn, we estimate a discrete-time survival curve.

- `P(remaining secure | turn t)` stays at `1.0000` at `t=0` and drops to `0.9051` at `t=1`
- By `t=5`, remaining-secure probability is `0.7795`
- By `t=20`, remaining-secure probability is `0.4864`

Insight: security degradation is front-loaded, with a sharp early drop followed by a slower long-tail decline.

Interpretation: intervention latency matters. Delayed safeguards will miss a large fraction of degradations that occur in the first few turns.

![Temporal Security Degradation Curve](paper_figures/fig5_temporal_survival_curve.svg)

### 2.8 Risk Introduction Source vs CWE
We aggregate source attribution into three buckets (`assistant_driven`, `user_driven`, `unclear`) and compute per-CWE distributions.

Examples from high-frequency CWE groups:

- Strong assistant-driven: `CWE-459 (0.9714)`, `CWE-20 (0.7356)`, `CWE-78 (0.7317)`
- Strong user-driven: `CWE-798 (0.6579)`, `CWE-522 (0.6207)`, `CWE-327 (0.6117)`

Insight: CWE classes exhibit distinct causal signatures rather than a single universal source pattern.

Interpretation: mitigation should be CWE-aware: assistant-side generation constraints for assistant-driven CWE, and stronger input/context sanitization for user-driven CWE.

Figure note: each CWE row shows three ratios side by side (`assistant-driven`, `user-driven`, `unclear`) for direct comparison.

![Attribution Source by CWE](paper_figures/fig6_attribution_source_by_cwe.svg)

## 3. Interpretation
Overall, the evidence indicates that risk formation is both source-sensitive and trajectory-sensitive: assistant decisions dominate many classes, while degradation unfolds over multiple turns with substantial early failure risk.

## 4. Threats to Validity
- Attribution and initiation are model-assisted labels and can be prompt-sensitive.
- Even after deterministic reassignment of `134` formerly unknown rows, exclusion of `151` non-security operational rows, and the extra audit pass that removes `71` obvious false positives and separates `306` local-only/context-dependent rows, some heuristics may still be contestable.
- Several CWE labels (`CWE-327`, `CWE-522`, `CWE-798`, `CWE-306`, `CWE-284`, `CWE-257`, `CWE-287`) are unstable across task framing because a large fraction of their full-set rows are `security_advice`.
- Regression and initiation are proxy metrics, not manually adjudicated causal truth.
- A small subset (`16` rows) used error-fallback attribution and may add minor noise.

## 5. Reproducibility
The high-precision code-risk numbers in this document are computed by taking finding IDs from `analysis/output/code_risk_analysis/high_precision_code_risk_rows.csv` and filtering the downstream attribution / tracing outputs to that ID set:

- `analysis/output/code_risk_analysis/high_precision_code_risk_rows.csv`
- `analysis/output/code_risk_analysis/code_risk_audit.csv`
- `analysis/output/code_risk_analysis/attribution_summary.json`
- `analysis/output/code_risk_analysis/top_cwe_counts.csv`
- `analysis/output/code_risk_analysis/all_unknown_resolution.csv`
- `analysis/output/code_risk_analysis/split_candidates.csv`
- `analysis/output/code_risk_analysis/trajectory_summary.json`
- `analysis/output/code_risk_analysis/assistant_regression_by_cwe.csv`
- `analysis/output/code_risk_analysis/temporal_security_degradation_curve.csv`
- `analysis/output/code_risk_analysis/attribution_source_by_cwe.csv`
- `analysis/output/empty_cwe_manual_review.csv`

Figures are generated into tracked assets under:

- `paper_figures/fig1_attribution_distribution.svg`
- `paper_figures/fig2_top_cwe_counts.svg`
- `paper_figures/fig3_risk_emergence_bucket.svg`
- `paper_figures/fig4_regression_by_cwe.svg`
- `paper_figures/fig5_temporal_survival_curve.svg`
- `paper_figures/fig6_attribution_source_by_cwe.svg`

## Appendix A. Representative Deterministic Remaps from Former `CWE-UNKNOWN`
| finding_id | new_cwe | snippet | reason |
|---|---|---|---|
| `46440f9e961ed61afc84d7c1` | `CWE-798` | `Authorization: Bearer <JWT_TOKEN>` | Hardcoded bearer token in a command creates direct credential reuse risk. |
| `7e342843f087bd402dd73e7e` | `CWE-321` | `SESSION_SECRET=dev-secret-key-123` | Assistant sets a static session secret, undermining session integrity if reused. |
| `b8138cc4b2d2c8f20d991b73` | `CWE-200` | `npx http-server -p 8080` | Local static server launch was reclassified as exposure-oriented rather than left unresolved. |
| `54fc9a0fcf9401c418e3a5d7` | `CWE-319` | `URL: http://www.gameshiftly.online/*` | Plaintext HTTP transport issue is concrete enough for deterministic mapping. |
| `7a70edcb91d93567d7513421` | `CWE-522` | `scp -i "jinmini-keypair.pem" ...` | Private-key based credential handling should be treated as credential-protection risk. |

## Appendix B. Metric and CWE Examples

### B.1 How to Read the Trajectory Metrics
| Metric | What it means in this paper | Example interpretation |
|---|---|---|
| `first risk appearance position` | Earliest earlier turn where the risk becomes concrete before the risky assistant output. | If `first_concretization_turn=3`, the risky idea had become actionable by turn 3, even if the final risky output was later. |
| `concretization gap` | `assistant_risk_turn - first_concretization_turn`. | A gap of `11` means the risky output came 11 turns after the first concrete risky step. |
| `p90=64` | 90% of concretization gaps are at most 64 turns. | The long tail is real: a minority of cases still take much longer to evolve. |
| `temporal degradation` | Survival-style probability that the conversation remains secure by turn `t`. | A lower value means the chance of avoiding risk until that turn is dropping. |
| `assistant security regression` | Assistant-driven cases where a concrete risky step was already present before the final risky output. | This captures escalation after an earlier concrete stage, not just a single-shot mistake. |

### B.2 Top 10 CWE Types in This Corpus
| CWE | Plain meaning | Typical risk pattern here | Source tendency |
|---|---|---|---|
| `CWE-312` | Sensitive information stored in plain text. | API keys, JWTs, `.env` secrets, leaked tokens. | Slightly user/context-driven in the code-risk subset. |
| `CWE-79` | Untrusted input reaches HTML/JS rendering. | Unsafe script tags, `innerHTML`, HTML injection-like patterns. | Roughly balanced, with a slight assistant-driven tilt. |
| `CWE-20` | Improper input validation. | Unsafe parameters, weak checks, malformed or unchecked input paths. | Strongly assistant-driven. |
| `CWE-200` | Sensitive information exposure. | Private URLs, env/config access, local HTTP servers, tunnel/webhook exposure. | Mixed, with a modest assistant-driven tilt after remapping. |
| `CWE-327` | Weak or deprecated cryptography / weak security primitive. | Weak secrets, insecure auth material, hardcoded low-entropy passwords. | More user/context-driven in the code-risk subset. |
| `CWE-459` | Incomplete cleanup of temporary artifacts. | Leftover debug files, caches, local servers or artifacts that expose data. | Strongly assistant-driven. |
| `CWE-522` | Insufficiently protected credentials. | Variable-based bearer tokens, auth headers, key material in commands. | More user/context-driven in the code-risk subset. |
| `CWE-78` | OS command injection / shell execution risk. | Shell commands with dangerous composition, piping to shells, unsafe execution. | Strongly assistant-driven. |
| `CWE-798` | Use of hard-coded credentials. | Root passwords, default passwords, explicit credential values in guidance. | More user/context-driven in the code-risk subset. |
| `CWE-269` | Improper privilege management. | Commands or code paths that grant broader capability than necessary. | Slightly assistant-driven in this corpus. |

### B.3 Why Some CWEs Look Assistant-Driven and Others User/Context-Driven
- `assistant_over_implemented` dominates when the user asks a benign question, but the assistant adds a risky implementation detail that was not required.
- `inherited_or_context_risk` and part of `user_requested_risk` dominate when the risky content was already present in the user prompt or pasted context, and the assistant repeats or propagates it.
- `CWE-459`, `CWE-20`, and `CWE-78` skew assistant-driven because they are often introduced as unnecessary commands, cleanup steps, or shell snippets by the assistant.
- `CWE-312`, `CWE-327`, `CWE-522`, and `CWE-798` skew more user/context-driven in the code-risk subset because the source material often already contains secrets, tokens, or dev credentials that the assistant repeats into code or commands.
- `CWE-79` and `CWE-522` are mixed because they can arise either from assistant-generated unsafe code or from user-provided content/credentials that the assistant echoes back.
- `CWE-200` is mixed in a different way: after remapping former `UNKNOWN` rows, this bucket now absorbs several concrete code/command patterns such as local HTTP servers, tunnel/webhook exposure, and env/config inspection commands.
