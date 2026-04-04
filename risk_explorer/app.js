const DATA_URL = "./data/site_data.json";
const CWE_CATALOG_URL = "../analysis/output/cwe_catalog_full.json";

const COLORS = {
  accent: "#b74419",
  blue: "#2955d9",
  red: "#d14028",
  gold: "#c68a17",
  green: "#16755d",
  gray: "#8a8177",
};

const state = {
  data: null,
  cweCatalog: null,
  filteredFindings: [],
  activePreset: "all",
  tablePage: 1,
};

const TABLE_PAGE_SIZE = 25;

const CWE_EXPLANATIONS = {
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
};

const CAUSE_EXPLANATIONS = {
  assistant_over_implemented: "The user goal was not explicitly unsafe, but the assistant expanded it into a riskier implementation than necessary.",
  inherited_or_context_risk: "The risky element already existed in the user prompt, pasted logs, or surrounding context, and the assistant carried it forward.",
  user_requested_risk: "The user directly asked for behavior that creates or preserves a security risk.",
  assistant_hallucinated_risk: "The assistant introduced a risky action without clear evidence that the user needed it.",
  insufficient_evidence: "The available context is too weak to confidently determine the source of the risk.",
  mixed_causality: "Multiple sources plausibly contributed, so the risk cannot be cleanly assigned to only one cause.",
};

const HIGHLIGHT_RULES = [
  { label: "Bearer token", pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9._-]+/gi },
  { label: "Session secret", pattern: /SESSION_SECRET\s*=\s*[^ \n"'`]+/gi },
  { label: "Hardcoded secret or credential", pattern: /[A-Z0-9_]*(API|AUTH|TOKEN|SECRET|PASSWORD|KEY)[A-Z0-9_]*\s*[:=]\s*[^ \n"'`]+/gi },
  { label: "URL or endpoint exposure", pattern: /https?:\/\/[^\s"'`]+/gi },
  { label: "Destructive delete command", pattern: /\brm\s+-rf\b/gi },
  { label: "Force push", pattern: /\bgit\s+push\s+--force\b/gi },
  { label: "Force push", pattern: /\bgit\s+push\s+-f\b/gi },
  { label: "Overly broad permissions", pattern: /\bchmod\s+777\b/gi },
  { label: "Privileged execution", pattern: /\bsudo\b[^\n]*/gi },
  { label: "Local HTTP server exposure", pattern: /\bhttp-server\b[^\n]*/gi },
  { label: "Local HTTP server exposure", pattern: /\bpython(?:3)?\s+-m\s+http\.server\b[^\n]*/gi },
  { label: "Unencrypted private key generation", pattern: /\bopenssl\s+req\b[^\n]*-nodes[^\n]*/gi },
  { label: "File copy over network", pattern: /\bscp\b[^\n]*/gi },
  { label: "Secret file access", pattern: /\bcat\s+\.env\b/gi },
  { label: "Secret file sourcing", pattern: /\bsource\s+\.env\b/gi },
  { label: "Environment variable extraction", pattern: /\benv\s+\|\s+grep\b[^\n]*/gi },
];

const ASSISTANT_DRIVEN_CAUSES = new Set(["assistant_over_implemented", "assistant_hallucinated_risk"]);
const USER_CONTEXT_DRIVEN_CAUSES = new Set(["inherited_or_context_risk", "user_requested_risk"]);

function fmtPct(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function fmtInt(value) {
  return new Intl.NumberFormat().format(value);
}

function truncateText(text, limit = 80) {
  const compact = String(text || "").replace(/\s+/g, " ").trim();
  if (compact.length <= limit) return compact;
  return `${compact.slice(0, limit - 3)}...`;
}

function pillClass(severity) {
  return `pill ${String(severity).toLowerCase()}`;
}

function createOption(label, value = label) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  return option;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function splitCwes(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => item.split(":")[0].trim());
}

function cweFallbackDescription(cwe) {
  return CWE_EXPLANATIONS[cwe] || "Concrete software security weakness used in the analysis.";
}

function buildCweCatalogIndex(catalog) {
  const index = new Map();
  const entries = Array.isArray(catalog?.entries) ? catalog.entries : [];
  entries.forEach((entry) => {
    const cwe = String(entry?.cwe || "").trim();
    if (!cwe) return;
    index.set(cwe, {
      cwe,
      title: String(entry?.title || entry?.name || cwe).trim(),
      name: String(entry?.name || "").trim(),
      description: String(entry?.description || "").trim(),
      extendedDescription: String(entry?.extended_description || "").trim(),
      url: String(entry?.url || "").trim(),
    });
  });
  return index;
}

function cweMeta(cwe) {
  const key = String(cwe || "").trim();
  return state.cweCatalog?.get(key) || null;
}

function cweTooltip(cwe) {
  const meta = cweMeta(cwe);
  if (meta) {
    return meta.title || meta.name || cwe;
  }
  return `${cwe}: ${cweFallbackDescription(cwe)}`;
}

function cweDetailText(cwe) {
  const meta = cweMeta(cwe);
  if (meta) {
    const title = meta.title || meta.name || cwe;
    const description = meta.description || meta.extendedDescription || "";
    return description ? `${title}. ${description}` : title;
  }
  return `${cwe}: ${cweFallbackDescription(cwe)}`;
}

function formatCweList(value) {
  return splitCwes(value);
}

function renderCweTags(value) {
  return formatCweList(value)
    .map(
      (cwe) =>
        `<span class="pill mono cwe-pill has-tip" data-tip="${escapeAttr(cweTooltip(cwe))}">${escapeHtml(cwe)}</span>`
    )
    .join("");
}

function formatTurn(value) {
  return value === null || value === undefined ? "-" : `turn ${value}`;
}

function buildTrajectorySteps(row) {
  if (Array.isArray(row.trajectory_context) && row.trajectory_context.length) {
    return row.trajectory_context.map((step) => ({
      key: String(step.label).toLowerCase().replaceAll(" ", "-"),
      title: step.label,
      turn: step.turn,
      note: step.note,
      role: step.role,
      text: step.text || step.preview || "",
      preview: step.preview || step.text || "",
      nearbyUserTurn: step.nearby_user_turn,
      nearbyUserText: step.nearby_user_text || "",
      nearbyUserPreview: step.nearby_user_preview || step.nearby_user_text || "",
    }));
  }
  return [
    {
      key: "concretization",
      title: "First Concretization",
      turn: row.first_concretization_turn,
      note: "The point where the risky idea becomes specific and actionable enough to count as a real risk signal.",
      nearbyUserTurn: row.nearest_user_message_index,
      nearbyUserText: row.nearest_user_text_short || "",
      nearbyUserPreview: row.nearest_user_text_short || "",
    },
    {
      key: "persistence",
      title: "First Persistence",
      turn: row.first_persistence_turn,
      note: "The first turn where the risky direction persists instead of disappearing immediately.",
      nearbyUserTurn: row.nearest_user_message_index,
      nearbyUserText: row.nearest_user_text_short || "",
      nearbyUserPreview: row.nearest_user_text_short || "",
    },
    {
      key: "assistant-risk",
      title: "Final Risk Output",
      turn: row.assistant_risk_turn,
      note: "The assistant turn that was ultimately recorded as the risky output.",
      nearbyUserTurn: row.nearest_user_message_index,
      nearbyUserText: row.nearest_user_text_short || "",
      nearbyUserPreview: row.nearest_user_text_short || "",
    },
  ].filter((step) => step.turn !== null && step.turn !== undefined);
}

function attributionBucketLabel(cause) {
  if (cause === "assistant_hallucinated_risk") return "Assistant Hallucinated";
  if (cause === "assistant_over_implemented") return "Assistant Over-Implemented";
  if (cause === "user_requested_risk") return "User Requested Risk";
  if (cause === "inherited_or_context_risk") return "Inherited or Context Risk";
  return humanizeCause(cause);
}

function attributionFamilyLabel(cause) {
  if (cause === "assistant_hallucinated_risk" || cause === "assistant_over_implemented") return "Assistant-Driven";
  if (cause === "user_requested_risk") return "User-Driven";
  if (cause === "inherited_or_context_risk") return "Context-Driven";
  return "Unclear";
}

function renderTrajectoryTimeline(row) {
  const steps = buildTrajectorySteps(row);
  return steps
    .map((step, index) => {
      const previewText = typeof step.preview === "string" ? step.preview : String(step.preview || "");
      const nearbyUserPreview = typeof step.nearbyUserPreview === "string" ? step.nearbyUserPreview : String(step.nearbyUserPreview || "");
      const signals = extractRiskSignals(previewText);
      return `
        <div class="trajectory-step trajectory-step-${step.key}">
          <div class="trajectory-marker">${index + 1}</div>
          <div class="trajectory-content">
            <div class="trajectory-head">
              <div class="trajectory-head-main">
                <strong>${step.title}</strong>
                <span class="trajectory-role">${escapeHtml(String(step.role || "unknown"))}</span>
              </div>
              <span class="trajectory-turn mono">${formatTurn(step.turn)}</span>
            </div>
            <p>${step.note}</p>
            <div class="trajectory-snippet mono">${highlightRiskText(previewText)}</div>
            ${
              nearbyUserPreview
                ? `
                  <div class="trajectory-user-context">
                    <strong>Nearby User Message</strong>
                    <div class="trajectory-user-meta mono">${formatTurn(step.nearbyUserTurn)}</div>
                    <div class="trajectory-user-snippet mono">${highlightRiskText(nearbyUserPreview)}</div>
                  </div>
                `
                : ""
            }
            ${
              signals.length
                ? `
                  <div class="trajectory-signals">
                    <strong>Why this looks risky</strong>
                    <div class="trajectory-signal-list">
                      ${signals
                        .map(
                          (signal) => `
                            <div class="trajectory-signal">
                              <span class="trajectory-signal-label">${escapeHtml(signal.label)}</span>
                              <span class="trajectory-signal-example">${escapeHtml(signal.examples.join(" · "))}</span>
                            </div>
                          `
                        )
                        .join("")}
                    </div>
                  </div>
                `
                : ""
            }
          </div>
        </div>
      `;
    })
    .join("");
}

function explainFinding(row) {
  const cwePart = formatCweList(row.cwe)
    .map((cwe) => cweDetailText(cwe))
    .join(" ");
  const causePart =
    CAUSE_EXPLANATIONS[row.primary_cause] || "The attribution label explains where the risky direction most likely came from.";
  const severityPart =
    row.severity === "high"
      ? "This finding was judged high severity, so the risky behavior is considered directly important rather than merely cosmetic."
      : row.severity === "medium"
        ? "This finding was judged medium severity, meaning it is important but usually more context-dependent than the highest-severity cases."
        : "This finding was judged low severity, meaning it still matters but often depends on deployment context or follow-on misuse.";
  return `${cwePart} ${causePart} ${severityPart}`;
}

function highlightRiskText(text) {
  let html = escapeHtml(text || "");
  HIGHLIGHT_RULES.forEach(({ pattern }) => {
    html = html.replace(pattern, (match) => `<mark class="risk-highlight">${match}</mark>`);
  });
  return html;
}

function extractRiskSignals(text) {
  const signals = [];
  HIGHLIGHT_RULES.forEach(({ label, pattern }) => {
    const matches = text.match(pattern) || [];
    if (matches.length) {
      signals.push({
        label,
        examples: [...new Set(matches.map((match) => truncateText(match, 80)))].slice(0, 2),
      });
    }
  });
  return signals;
}

function renderHeroMetrics(overview) {
  const mount = document.querySelector("#hero-metrics");
  const items = [
    ["Risk Rows", fmtInt(overview.n_code_risk_rows)],
    ["Assistant-First", fmtPct(overview.assistant_first_ratio)],
    ["Early Emergence", fmtPct(overview.early_emergence_ratio)],
    ["Risk Gap p90", String(overview.risk_gap_p90)],
    ["Assistant Regression", fmtPct(overview.assistant_regression_rate)],
    [`Top CWE: ${overview.top_cwe_label}`, fmtInt(overview.top_cwe_count)],
  ];
  mount.innerHTML = "";
  items.forEach(([label, value]) => {
    const tooltipMap = {
      "Risk Rows": "Rows shown in the explorer after widening the dataset to include all risky findings, including security-advice rows that may still affect users.",
      "Assistant-First": "Share of findings where the risky direction is attributed mainly to the assistant rather than user/context.",
      "Early Emergence": "Share of traced findings whose first concrete risk signal appears in turns 0-1.",
      "Risk Gap p90": "90th percentile of the number of turns between first concrete risk signal and final risky assistant output.",
      "Assistant Regression": "Share of assistant-driven trajectories that continue from an earlier risk signal into a later, concretized risky output.",
      [`Top CWE: ${overview.top_cwe_label}`]: "The single most common weakness family in the risky-row dataset.",
    };
    const card = document.createElement("div");
    card.className = "metric-card";
    card.innerHTML = `
      <div class="metric-value">${value}</div>
      <div class="metric-label">${label} <span class="term inline-term" data-tip="${tooltipMap[label]}">?</span></div>
    `;
    mount.appendChild(card);
  });
}

function renderInsights(insights) {
  const mount = document.querySelector("#insight-grid");
  mount.innerHTML = "";
  insights.forEach((insight) => {
    const card = document.createElement("article");
    card.className = "insight-card";
    card.innerHTML = `<h3>${insight.title}</h3><p>${insight.body}</p>`;
    mount.appendChild(card);
  });
}

function shortAttributionLabel(value) {
  const mapping = {
    assistant_over_implemented: "Assistant Over-Implemented",
    inherited_or_context_risk: "User/Context Inherited",
    user_requested_risk: "User Requested",
    assistant_hallucinated_risk: "Assistant Hallucinated",
    others: "Others",
  };
  return mapping[value] || value;
}

function collapseAttributionRows(distribution) {
  const othersCount =
    Number(distribution.insufficient_evidence?.count || 0) +
    Number(distribution.mixed_causality?.count || 0);
  const othersRatio =
    Number(distribution.insufficient_evidence?.ratio || 0) +
    Number(distribution.mixed_causality?.ratio || 0);

  return [
    { label: "assistant_over_implemented", value: Number(distribution.assistant_over_implemented?.ratio || 0) },
    { label: "inherited_or_context_risk", value: Number(distribution.inherited_or_context_risk?.ratio || 0) },
    { label: "user_requested_risk", value: Number(distribution.user_requested_risk?.ratio || 0) },
    { label: "assistant_hallucinated_risk", value: Number(distribution.assistant_hallucinated_risk?.ratio || 0) },
    { label: "others", value: othersRatio, count: othersCount },
  ];
}

function renderBarChart(mountSelector, rows, getLabel, getValue, color, onBarClick = null) {
  const mount = document.querySelector(mountSelector);
  const maxValue = Math.max(...rows.map(getValue), 1);
  mount.innerHTML = "";
  rows.forEach((row) => {
    const value = getValue(row);
    const rawLabel = getLabel(row);
    const labelHtml = String(rawLabel).startsWith("CWE-")
      ? `<span class="has-tip" data-tip="${escapeAttr(cweTooltip(String(rawLabel)))}">${escapeHtml(String(rawLabel))}</span>`
      : escapeHtml(String(rawLabel));
    const wrapper = document.createElement("div");
    wrapper.className = "bar-row";
    wrapper.innerHTML = `
      <div class="bar-label mono">${labelHtml}</div>
      <div class="bar-track${onBarClick ? " chart-clickable" : ""}"><div class="bar-fill" style="width:${(value / maxValue) * 100}%;background:${color};"></div></div>
      <div class="bar-value mono">${typeof value === "number" && value <= 1 ? fmtPct(value) : fmtInt(value)}</div>
    `;
    if (onBarClick) {
      wrapper.querySelector(".bar-track").addEventListener("click", () => onBarClick(row));
    }
    mount.appendChild(wrapper);
  });
}

function renderSourceByCwe(rows) {
  const mount = document.querySelector("#source-by-cwe-chart");
  const top = rows.slice(0, 10);
  const assistantDominated = top.filter((row) => Number(row.assistant_driven_ratio) >= Number(row.user_driven_ratio));
  const userDominated = top.filter((row) => Number(row.user_driven_ratio) > Number(row.assistant_driven_ratio));
  const maxRatio = Math.max(
    ...[...assistantDominated, ...userDominated].flatMap((row) => [Number(row.assistant_driven_ratio), Number(row.user_driven_ratio)]),
    1
  );
  const renderColumn = (title, rowsForColumn, dominantKey, dominantLabel, dominantColor, otherKey, otherLabel, otherColor) => `
    <div class="source-column">
      <h4>${title}</h4>
      <div class="source-column-list">
        ${rowsForColumn
          .map(
            (row) => `
              <div class="grouped-row">
                <div class="grouped-label mono"><span class="has-tip" data-tip="${escapeAttr(cweTooltip(String(row.cwe)))}">${escapeHtml(String(row.cwe))}</span></div>
                <div class="grouped-bars">
                  <div class="grouped-bar-item chart-clickable" data-cwe="${escapeAttr(String(row.cwe))}" data-side="${escapeAttr(dominantKey)}">
                    <div class="grouped-bar-head">
                      <span>${dominantLabel}</span>
                      <span class="mono">${fmtPct(Number(row[dominantKey]))}</span>
                    </div>
                    <div class="grouped-track">
                      <div class="grouped-fill" style="width:${(Number(row[dominantKey]) / maxRatio) * 100}%;background:${dominantColor};"></div>
                    </div>
                  </div>
                  <div class="grouped-bar-item chart-clickable" data-cwe="${escapeAttr(String(row.cwe))}" data-side="${escapeAttr(otherKey)}">
                    <div class="grouped-bar-head">
                      <span>${otherLabel}</span>
                      <span class="mono">${fmtPct(Number(row[otherKey]))}</span>
                    </div>
                    <div class="grouped-track">
                      <div class="grouped-fill" style="width:${(Number(row[otherKey]) / maxRatio) * 100}%;background:${otherColor};"></div>
                    </div>
                  </div>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
  mount.innerHTML = `
    <div class="source-columns">
      ${renderColumn("Assistant-Driven Dominant", assistantDominated, "assistant_driven_ratio", "assistant-driven", COLORS.blue, "user_driven_ratio", "user/context-driven", COLORS.red)}
      ${renderColumn("User/Context-Driven Dominant", userDominated, "user_driven_ratio", "user/context-driven", COLORS.red, "assistant_driven_ratio", "assistant-driven", COLORS.blue)}
    </div>
    <div class="stack-legend">
      <span><span class="legend-dot" style="background:${COLORS.blue}"></span>assistant-driven</span>
      <span><span class="legend-dot" style="background:${COLORS.red}"></span>user/context-driven</span>
    </div>
  `;
  mount.querySelectorAll(".grouped-bar-item").forEach((item) => {
    item.addEventListener("click", () => {
      openExamplesDrawerForSource(item.dataset.cwe, item.dataset.side);
    });
  });
}

function matchesTurnBucket(bucket, turn) {
  if (turn === null || turn === undefined) return false;
  if (bucket === "16+") return turn >= 16;
  const match = String(bucket).match(/^(\d+)-(\d+)$/);
  if (!match) return false;
  return turn >= Number(match[1]) && turn <= Number(match[2]);
}

function openExamplesDrawer(title, subtitle, findings) {
  const drawer = document.querySelector("#detail-drawer");
  const content = document.querySelector("#drawer-content");
  const rows = findings.slice(0, 12);
  content.innerHTML = `
    <div class="section-head">
      <div>
        <p class="section-kicker">Examples</p>
        <h2>${escapeHtml(title)}</h2>
        <p class="section-copy">${escapeHtml(subtitle)}</p>
      </div>
    </div>
    <div class="example-list">
      ${
        rows.length
          ? rows
              .map((row) => {
                const summary = summarizeCard(row);
                return `
                  <article class="example-card" data-finding-id="${escapeAttr(row.finding_id)}">
                    <div class="finding-card-top">
                      <div class="finding-card-meta">
                        <span class="${pillClass(row.severity)}">${row.severity}</span>
                        <span class="pill">${humanizeCause(row.primary_cause)}</span>
                      </div>
                      <div class="mono finding-card-id">${escapeHtml(row.finding_id.slice(0, 12))}</div>
                    </div>
                    <div class="cwe-tag-list">${renderCweTags(row.cwe)}</div>
                    <p class="finding-card-summary">${escapeHtml(summary.title)}</p>
                    <div class="finding-card-context">
                      <strong>Nearby Context</strong>
                      <p>${escapeHtml(summary.context)}</p>
                    </div>
                    <button class="finding-card-action" type="button">Open Detail</button>
                  </article>
                `;
              })
              .join("")
          : `<div class="empty-state">No findings matched this bar.</div>`
      }
    </div>
  `;
  content.querySelectorAll(".example-card").forEach((card) => {
    const row = state.data.findings.find((item) => item.finding_id === card.dataset.findingId);
    if (!row) return;
    card.querySelector(".finding-card-action").addEventListener("click", (event) => {
      event.stopPropagation();
      safeOpenDrawer(row);
    });
    card.addEventListener("click", (event) => {
      if (event.target.closest("button")) return;
      safeOpenDrawer(row);
    });
  });
  drawer.classList.remove("hidden");
  drawer.setAttribute("aria-hidden", "false");
}

function openExamplesDrawerForSource(cwe, side) {
  const findings = state.data.findings.filter((row) => {
    const hasCwe = formatCweList(row.cwe).includes(cwe);
    if (!hasCwe) return false;
    if (side === "assistant_driven_ratio") return ASSISTANT_DRIVEN_CAUSES.has(row.primary_cause);
    if (side === "user_driven_ratio") return USER_CONTEXT_DRIVEN_CAUSES.has(row.primary_cause);
    return false;
  });
  const sideLabel = side === "assistant_driven_ratio" ? "assistant-driven" : "user/context-driven";
  openExamplesDrawer(
    `${cweTooltip(cwe)} · ${sideLabel}`,
    `Representative findings that contribute to the ${sideLabel} bar for ${cweTooltip(cwe)}.`,
    findings
  );
}

function openExamplesDrawerForAttribution(cause) {
  const findings = state.data.findings.filter((row) => {
    if (cause === "others") {
      return row.primary_cause === "insufficient_evidence" || row.primary_cause === "mixed_causality";
    }
    return row.primary_cause === cause;
  });
  openExamplesDrawer(shortAttributionLabel(cause), "Representative findings attributed to this source category.", findings);
}

function openExamplesDrawerForCwe(cwe) {
  const findings = state.data.findings.filter((row) => formatCweList(row.cwe).includes(cwe));
  openExamplesDrawer(cweTooltip(cwe), `Representative findings categorized under ${cweTooltip(cwe)}.`, findings);
}

function openExamplesDrawerForEmergence(bucket) {
  const findings = state.data.findings.filter((row) => matchesTurnBucket(bucket, row.first_concretization_turn));
  openExamplesDrawer(`First Concretization in ${bucket}`, "Representative findings whose first concrete risk signal appears in this turn bucket.", findings);
}

function humanizeCause(value) {
  return String(value || "")
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function summarizeCard(row) {
  const cweList = formatCweList(row.cwe);
  const snippet = row.assistant_candidate_preview || row.assistant_candidate_text_short || "No risky code or command snippet available.";
  const context = row.nearest_user_preview || row.nearest_user_text_short || "No nearby user context available.";
  const signal = extractRiskSignals(snippet)[0];
  const primaryCwe = cweList[0] || "";
  const primaryCweName = cweMeta(primaryCwe)?.name || cweMeta(primaryCwe)?.title || primaryCwe;
  const cweSummary = cweList.map((cwe) => cweDetailText(cwe)).join(" ");
  const why =
    signal?.label
      ? `${signal.label}. ${cweSummary}`
      : cweSummary;
  const title = signal?.label
    ? `${signal.label} in ${primaryCweName || "risk finding"}`
    : primaryCweName
      ? `${primaryCweName} finding`
      : "Risk finding";
  return {
    title,
    context,
    snippet,
    why,
  };
}

function setSelectValue(selector, value) {
  const element = document.querySelector(selector);
  if (element) element.value = value;
}

function clearFilters({ keepSort = true } = {}) {
  document.querySelector("#search-input").value = "";
  setSelectValue("#cwe-filter", "");
  setSelectValue("#cause-filter", "");
  setSelectValue("#severity-filter", "");
  setSelectValue("#block-filter", "");
  if (!keepSort) setSelectValue("#sort-filter", "severity");
}

function getPresetDefinitions(data) {
  const topCwes = data.top_cwe_counts.slice(0, 4).map((row) => row.cwe);
  return [
    {
      id: "assistant-driven",
      label: "Mostly Assistant-Driven",
      description: "Find cases where the assistant introduced or escalated the risky direction.",
      apply: () => {
        clearFilters();
        setSelectValue("#cause-filter", "assistant_over_implemented");
        setSelectValue("#sort-filter", "severity");
      },
    },
    {
      id: "user-driven",
      label: "Mostly User-Driven",
      description: "Focus on findings where the user explicitly asked for risky behavior.",
      apply: () => {
        clearFilters();
        setSelectValue("#cause-filter", "user_requested_risk");
        setSelectValue("#sort-filter", "severity");
      },
    },
    {
      id: "context-driven",
      label: "Mostly Context-Driven",
      description: "Inspect findings where the risky element was already present in surrounding prompt or pasted context.",
      apply: () => {
        clearFilters();
        setSelectValue("#cause-filter", "inherited_or_context_risk");
        setSelectValue("#sort-filter", "severity");
      },
    },
    {
      id: "assistant-hallucinated",
      label: "Assistant Hallucinated",
      description: "Inspect findings where the assistant introduced a risky move without a clear user request.",
      apply: () => {
        clearFilters();
        setSelectValue("#cause-filter", "assistant_hallucinated_risk");
        setSelectValue("#sort-filter", "severity");
      },
    },
    ...topCwes.map((cwe) => ({
      id: `cwe-${cwe}`,
      label: cwe,
      description: `Browse the most common examples in ${cwe}.`,
      apply: () => {
        clearFilters();
        setSelectValue("#cwe-filter", cwe);
        setSelectValue("#sort-filter", "severity");
      },
    })),
  ];
}

function renderPresets() {
  const mount = document.querySelector("#preset-chips");
  const presets = getPresetDefinitions(state.data);
  mount.innerHTML = "";
  presets.forEach((preset) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `preset-chip${state.activePreset === preset.id ? " active" : ""}`;
    button.innerHTML = `
      <strong>${preset.label}</strong>
      <span>${preset.description}</span>
    `;
    button.addEventListener("click", () => {
      state.activePreset = preset.id;
      preset.apply();
      renderPresets();
      applyFilters();
    });
    mount.appendChild(button);
  });
}

function populateFilters(filters) {
  const cweOptions = Array.from(new Set(state.data.findings.flatMap((row) => formatCweList(row.cwe)))).sort();
  const mapping = [
    ["#cwe-filter", cweOptions],
    ["#cause-filter", filters.primary_cause],
    ["#severity-filter", filters.severity],
    ["#block-filter", filters.assistant_block_type],
  ];
  mapping.forEach(([selector, values]) => {
    const select = document.querySelector(selector);
    select.innerHTML = "";
    select.appendChild(createOption("All", ""));
    values.forEach((value) => select.appendChild(createOption(value)));
  });
}

function applyFilters() {
  const search = document.querySelector("#search-input").value.trim().toLowerCase();
  const cwe = document.querySelector("#cwe-filter").value;
  const cause = document.querySelector("#cause-filter").value;
  const severity = document.querySelector("#severity-filter").value;
  const block = document.querySelector("#block-filter").value;
  const sort = document.querySelector("#sort-filter").value;

  const filtered = state.data.findings.filter((row) => {
    const cweList = formatCweList(row.cwe);
    if (cwe && !cweList.includes(cwe)) return false;
    if (cause && row.primary_cause !== cause) return false;
    if (severity && row.severity !== severity) return false;
    if (block && row.assistant_block_type !== block) return false;
    if (!search) return true;

    const haystack = [
      row.finding_id,
      cweList.join(" "),
      row.primary_cause,
      row.severity,
      row.assistant_candidate_text_short,
      row.nearest_user_text_short,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(search);
  });

  const severityRank = { high: 0, medium: 1, low: 2, none: 3 };
  filtered.sort((a, b) => {
    if (sort === "mention_gap") return (b.concretization_gap ?? -1) - (a.concretization_gap ?? -1);
    if (sort === "cwe") return formatCweList(a.cwe).join(",").localeCompare(formatCweList(b.cwe).join(","));
    if (sort === "cause") return String(a.primary_cause).localeCompare(String(b.primary_cause));
    return (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9);
  });

  state.filteredFindings = filtered;
  state.tablePage = 1;
  syncPresetState();
  renderPresets();
  renderFindingCards();
  renderFindingsTable();
}

function syncPresetState() {
  const search = document.querySelector("#search-input").value.trim();
  const cwe = document.querySelector("#cwe-filter").value;
  const cause = document.querySelector("#cause-filter").value;
  const severity = document.querySelector("#severity-filter").value;
  const block = document.querySelector("#block-filter").value;
  const sort = document.querySelector("#sort-filter").value;

  if (!search && !cwe && !cause && !severity && !block && sort === "severity") {
    state.activePreset = "";
    return;
  }
  if (!search && !cwe && cause === "assistant_over_implemented" && !severity && !block) {
    state.activePreset = "assistant-driven";
    return;
  }
  if (!search && !cwe && cause === "user_requested_risk" && !severity && !block) {
    state.activePreset = "user-driven";
    return;
  }
  if (!search && !cwe && cause === "inherited_or_context_risk" && !severity && !block) {
    state.activePreset = "context-driven";
    return;
  }
  if (!search && !cwe && cause === "assistant_hallucinated_risk" && !severity && !block) {
    state.activePreset = "assistant-hallucinated";
    return;
  }
  if (!search && cwe && !cause && !severity && !block) {
    state.activePreset = `cwe-${cwe}`;
    return;
  }
  state.activePreset = "";
}

function renderFindingCards() {
  const mount = document.querySelector("#finding-card-grid");
  mount.innerHTML = "";
  const rows = state.filteredFindings.slice(0, 12);

  if (!rows.length) {
    mount.innerHTML = `<div class="empty-state">No findings match the current filters.</div>`;
    return;
  }

  rows.forEach((row) => {
    const summary = summarizeCard(row);
    const card = document.createElement("article");
    card.className = "finding-card";
    card.innerHTML = `
      <div class="finding-card-top">
        <div class="finding-card-meta">
          <span class="${pillClass(row.severity)}">${row.severity}</span>
          <span class="pill">${humanizeCause(row.primary_cause)}</span>
        </div>
        <div class="mono finding-card-id">${row.finding_id.slice(0, 12)}</div>
      </div>
      <div class="cwe-tag-list">${renderCweTags(row.cwe)}</div>
      <div class="finding-card-context">
        <strong>Risky Code / Command</strong>
        <p class="mono">${highlightRiskText(summary.snippet)}</p>
      </div>
      <p class="finding-card-detail">${escapeHtml(summary.why)}</p>
      <button class="finding-card-action" type="button">Open Detail</button>
    `;
    card.querySelector(".finding-card-action").addEventListener("click", (event) => {
      event.stopPropagation();
      safeOpenDrawer(row);
    });
    card.addEventListener("click", (event) => {
      if (event.target.closest("button")) return;
      safeOpenDrawer(row);
    });
    mount.appendChild(card);
  });
}

function renderFindingsTable() {
  const body = document.querySelector("#findings-table-body");
  const pageInfo = document.querySelector("#table-page-info");
  const pageLabel = document.querySelector("#table-page-label");
  const prevButton = document.querySelector("#table-prev");
  const nextButton = document.querySelector("#table-next");
  body.innerHTML = "";
  const total = state.filteredFindings.length;
  const totalPages = Math.max(1, Math.ceil(total / TABLE_PAGE_SIZE));
  state.tablePage = Math.min(Math.max(1, state.tablePage), totalPages);
  const startIndex = (state.tablePage - 1) * TABLE_PAGE_SIZE;
  const endIndex = Math.min(startIndex + TABLE_PAGE_SIZE, total);
  const rows = state.filteredFindings.slice(startIndex, endIndex);

  pageInfo.textContent = total ? `Showing ${fmtInt(startIndex + 1)}-${fmtInt(endIndex)} of ${fmtInt(total)}` : "Showing 0-0 of 0";
  pageLabel.textContent = `Page ${fmtInt(state.tablePage)} of ${fmtInt(totalPages)}`;
  prevButton.disabled = state.tablePage <= 1;
  nextButton.disabled = state.tablePage >= totalPages;

  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.className = "finding-row";
    tr.innerHTML = `
      <td class="mono">${row.finding_id.slice(0, 12)}</td>
      <td><div class="cwe-tag-list">${renderCweTags(row.cwe)}</div></td>
      <td>${row.primary_cause}</td>
      <td><span class="${pillClass(row.severity)}">${row.severity}</span></td>
      <td class="table-snippet-cell">${row.assistant_candidate_preview}</td>
    `;
    tr.addEventListener("click", () => safeOpenDrawer(row));
    body.appendChild(tr);
  });
}

function safeOpenDrawer(row) {
  try {
    openDrawer(row);
  } catch (error) {
    console.error("Failed to open finding detail", error, row);
    const errorMessage = error instanceof Error ? error.message : String(error);
    const drawer = document.querySelector("#detail-drawer");
    const content = document.querySelector("#drawer-content");
    content.innerHTML = `
      <div class="section-head">
        <div>
          <p class="section-kicker">Finding Detail</p>
          <h2 class="mono">${escapeHtml(row.finding_id || "unknown")}</h2>
        </div>
      </div>
      <div class="detail-explainer">
        <h4>Detail Rendering Failed</h4>
        <p>The full detail view hit a client-side rendering error. A simplified fallback view is shown instead.</p>
        <p><strong>Error:</strong> ${escapeHtml(errorMessage)}</p>
      </div>
      <div class="detail-grid detail-grid-secondary">
        <div class="detail-block">
          <h4>Classification</h4>
          <p><strong>CWE:</strong> ${escapeHtml(String(row.cwe || "-"))}</p>
          <p><strong>Cause:</strong> ${escapeHtml(String(row.primary_cause || "-"))}</p>
          <p><strong>Severity:</strong> ${escapeHtml(String(row.severity || "-"))}</p>
        </div>
        <div class="detail-block">
          <h4>Context</h4>
          <p class="mono">${highlightRiskText(row.nearest_user_text_short || "")}</p>
        </div>
        <div class="detail-block">
          <h4>Assistant Risk Snippet</h4>
          <pre class="mono">${highlightRiskText(row.assistant_candidate_text_short || "")}</pre>
        </div>
      </div>
    `;
    drawer.classList.remove("hidden");
    drawer.setAttribute("aria-hidden", "false");
  }
}

function openDrawer(row) {
  const drawer = document.querySelector("#detail-drawer");
  const content = document.querySelector("#drawer-content");
  const explainer = explainFinding(row);
  const cweList = formatCweList(row.cwe);
  const attributionLabel = attributionBucketLabel(row.primary_cause);
  const attributionFamily = attributionFamilyLabel(row.primary_cause);
  content.innerHTML = `
    <div class="section-head">
      <div>
        <p class="section-kicker">Finding Detail</p>
        <h2 class="mono">${row.finding_id}</h2>
      </div>
    </div>
    <div class="detail-block detail-block-classification">
      <h4>Classification</h4>
      <div class="detail-pill-row">
        <span class="${pillClass(row.severity)}">${escapeHtml(String(row.severity || ""))}</span>
        <span class="pill">${escapeHtml(attributionFamily)}</span>
        <span class="pill">${escapeHtml(attributionLabel)}</span>
      </div>
      <p><strong>CWE:</strong></p>
      <div class="cwe-tag-list detail-cwe-list">${renderCweTags(row.cwe)}</div>
      <p>${cweList.map((cwe) => cweDetailText(cwe)).join(" ")}</p>
      <p><strong>Attribution Distribution:</strong> ${escapeHtml(attributionLabel)}</p>
      <p><strong>Attribution Family:</strong> ${escapeHtml(attributionFamily)}</p>
      <p><strong>Verdict:</strong> ${row.verdict} (${row.confidence ?? "n/a"})</p>
      <p><strong>Block Type:</strong> ${row.assistant_block_type}</p>
      <p><strong>Chat:</strong> <span class="mono">${row.chat_id}</span></p>
      <p><strong>Candidate:</strong> <span class="mono">${row.candidate_id}</span></p>
    </div>
    <div class="detail-explainer">
      <h4>Plain-Language Interpretation</h4>
      <p>${explainer}</p>
      <div class="risk-legend">Highlighted text marks secret-like values, insecure URLs, risky commands, or credential-handling fragments that likely triggered the risk label.</div>
    </div>
    <div class="detail-block detail-block-featured">
      <h4>Trajectory</h4>
      <div class="trajectory-timeline">
        ${renderTrajectoryTimeline(row)}
      </div>
    </div>
  `;
  drawer.classList.remove("hidden");
  drawer.setAttribute("aria-hidden", "false");
}

function bindEvents() {
  ["#search-input", "#cwe-filter", "#cause-filter", "#severity-filter", "#block-filter", "#sort-filter"].forEach((selector) => {
    document.querySelector(selector).addEventListener("input", applyFilters);
    document.querySelector(selector).addEventListener("change", applyFilters);
  });
  document.querySelector("#drawer-close").addEventListener("click", () => {
    const drawer = document.querySelector("#detail-drawer");
    drawer.classList.add("hidden");
    drawer.setAttribute("aria-hidden", "true");
  });
  document.querySelector("#detail-drawer").addEventListener("click", (event) => {
    if (event.target.id === "detail-drawer") {
      event.currentTarget.classList.add("hidden");
      event.currentTarget.setAttribute("aria-hidden", "true");
    }
  });
  document.querySelector("#table-prev").addEventListener("click", () => {
    if (state.tablePage <= 1) return;
    state.tablePage -= 1;
    renderFindingsTable();
  });
  document.querySelector("#table-next").addEventListener("click", () => {
    const totalPages = Math.max(1, Math.ceil(state.filteredFindings.length / TABLE_PAGE_SIZE));
    if (state.tablePage >= totalPages) return;
    state.tablePage += 1;
    renderFindingsTable();
  });
}

function render(data) {
  document.querySelector("#hero-subtitle").textContent =
    `${data.meta.subtitle}. Risk rows: ${fmtInt(data.overview.n_code_risk_rows)} from a total corpus of ${fmtInt(data.overview.n_total_candidates)} extracted candidates.`;
  renderHeroMetrics(data.overview);
  renderInsights(data.insights);

  const attrRows = collapseAttributionRows(data.attribution_summary.attribution_distribution);
  renderBarChart(
    "#attribution-chart",
    attrRows,
    (row) => shortAttributionLabel(row.label),
    (row) => row.value,
    COLORS.blue,
    (row) => openExamplesDrawerForAttribution(row.label)
  );
  renderBarChart(
    "#top-cwe-chart",
    data.top_cwe_counts.slice(0, 8),
    (row) => row.cwe,
    (row) => Number(row.count),
    COLORS.accent,
    (row) => openExamplesDrawerForCwe(row.cwe)
  );
  renderBarChart(
    "#emergence-chart",
    data.risk_emergence_bucket_distribution,
    (row) => row.turn_bucket,
    (row) => Number(row.probability),
    COLORS.gold,
    (row) => openExamplesDrawerForEmergence(row.turn_bucket)
  );
  renderSourceByCwe(data.attribution_source_by_cwe);

  populateFilters(data.filters);
  renderPresets();
  applyFilters();
}

async function init() {
  bindEvents();
  const [dataResponse, catalogResponse] = await Promise.all([fetch(DATA_URL), fetch(CWE_CATALOG_URL)]);
  if (!dataResponse.ok) {
    throw new Error(`Failed to load ${DATA_URL}`);
  }
  state.data = await dataResponse.json();
  if (catalogResponse.ok) {
    const catalog = await catalogResponse.json();
    state.cweCatalog = buildCweCatalogIndex(catalog);
  } else {
    state.cweCatalog = new Map();
    console.warn(`Failed to load ${CWE_CATALOG_URL}; falling back to local CWE descriptions.`);
  }
  render(state.data);
}

init().catch((error) => {
  console.error(error);
  document.body.innerHTML = `<pre style="padding:20px;">Failed to load explorer data.\n${error.message}</pre>`;
});
