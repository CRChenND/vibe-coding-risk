const MANIFEST_URL = "../analysis/output/risk_dataset_export_1887/manifest.json";
const SOURCE_BASE = "../analysis/output/risk_dataset_export_1887/";
const STORAGE_KEY = "vibe-risk-annotations-v1";
const PAGE_SIZES = [20, 25, 50];
const REVIEW_STATES = ["unreviewed", "approve", "reject", "unsure"];
const BOOL_STATES = ["unsure", "yes", "no"];
const CAUSE_EXPLANATIONS = {
  assistant_over_implemented: "The user goal was not explicitly unsafe, but the assistant expanded it into a riskier implementation than necessary.",
  inherited_or_context_risk: "The risky element already existed in the user prompt, pasted logs, or surrounding context, and the assistant carried it forward.",
  user_requested_risk: "The user directly asked for behavior that creates or preserves a security risk.",
  assistant_hallucinated_risk: "The assistant introduced a risky action without clear evidence that the user needed it.",
  insufficient_evidence: "The available context is too weak to confidently determine the source of the risk.",
  mixed_causality: "Multiple sources plausibly contributed, so the risk cannot be cleanly assigned to only one cause.",
};
const COMMAND_BLOCK_TYPES = new Set(["bash", "shell", "sh", "zsh", "terminal", "console", "command"]);
const CODE_BLOCK_TYPES = new Set([
  "diff",
  "read-file",
  "json",
  "yaml",
  "yml",
  "xml",
  "html",
  "css",
  "scss",
  "sql",
  "python",
  "javascript",
  "typescript",
  "java",
  "go",
  "rust",
  "ruby",
  "php",
  "c",
  "cpp",
  "csharp",
  "cs",
  "kotlin",
  "swift",
  "dart",
  "tsx",
  "jsx",
  "js",
  "ts",
  "vue",
  "svelte",
  "toml",
  "ini",
  "dockerfile",
]);
const CODE_FILE_EXTENSIONS = [
  ".py",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".java",
  ".go",
  ".rs",
  ".rb",
  ".php",
  ".c",
  ".cc",
  ".cpp",
  ".cs",
  ".kt",
  ".swift",
  ".dart",
  ".json",
  ".yaml",
  ".yml",
  ".xml",
  ".html",
  ".css",
  ".scss",
  ".sql",
  ".sh",
  ".bash",
  ".zsh",
  ".toml",
  ".ini",
  ".vue",
  ".svelte",
  ".dockerfile",
];
const TEXT_FILE_EXTENSIONS = [".md", ".markdown", ".mdx", ".txt", ".rst"];

const state = {
  rows: [],
  filteredRows: [],
  selectedFindingId: null,
  search: "",
  statusFilter: "all",
  pageSize: 25,
  page: 1,
  annotations: loadAnnotations(),
  chatCache: new Map(),
  loadingChat: false,
  showRaw: false,
  renderToken: 0,
};

const els = {};

function defaultAnnotation() {
  return {
    review_state: "unreviewed",
    cwe_correct: "unsure",
    reason_correct: "unsure",
    corrected_cwe: "",
    corrected_reason: "",
    notes: "",
    updated_at: "",
  };
}

function loadAnnotations() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveAnnotations() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.annotations));
  setSaveState(`Autosaved ${new Date().toLocaleTimeString()}`);
}

function setSaveState(text) {
  if (els.saveState) {
    els.saveState.textContent = text;
  }
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

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function truncate(text, limit = 120) {
  const compact = normalizeText(text);
  if (compact.length <= limit) return compact;
  return `${compact.slice(0, limit - 3)}...`;
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildRiskFragments(row) {
  const fragments = [];
  const raw = String(row?.risk_snippets_content || "").trim();
  const short = String(row?.assistant_candidate_text_short || "").trim();
  const add = (text) => {
    const compact = normalizeText(text);
    if (compact.length >= 8) fragments.push(compact);
  };

  if (raw) {
    add(raw);
    raw.split(/\n+/).forEach((line) => add(line));
  }
  if (short) {
    add(short);
    short.split(/\n+/).forEach((line) => add(line));
  }

  const seen = new Set();
  return fragments.filter((frag) => {
    if (seen.has(frag)) return false;
    seen.add(frag);
    return true;
  }).slice(0, 6);
}

function classifyBlockKind(type, role, content = "") {
  const t = String(type || "").toLowerCase();
  const r = String(role || "").toLowerCase();
  if (r === "user") return "user";
  if (COMMAND_BLOCK_TYPES.has(t) || t.includes("command")) return "command";
  if (t === "markdown") return r === "assistant" ? inferAssistantTextKind(content) : "other";
  if (t.startsWith("markdown:")) {
    const target = t.slice("markdown:".length).trim();
    if (TEXT_FILE_EXTENSIONS.some((ext) => target.endsWith(ext))) return "text";
    if (CODE_FILE_EXTENSIONS.some((ext) => target.endsWith(ext))) return "code";
    return inferAssistantTextKind(content);
  }
  if (t === "unknown") return r === "assistant" ? inferAssistantTextKind(content) : "other";
  if (CODE_BLOCK_TYPES.has(t) || t.includes("code") || t.includes("snippet")) return "code";
  return r === "assistant" ? "text" : "other";
}

function inferAssistantTextKind(content) {
  const text = String(content || "");
  const compact = normalizeText(text);
  if (!compact) return "text";

  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) return "text";

  const commandLineCount = lines.filter((line) =>
    /^(\$|#)\s/.test(line) ||
    /^(git|npm|pnpm|yarn|npx|node|python|python3|pip|pip3|uv|pytest|cargo|go|java|javac|mvn|gradle|docker|kubectl|helm|brew|apt|apt-get|curl|wget|chmod|chown|mkdir|rm|cp|mv|ls|cd|cat|sed|awk|grep|find|ssh|scp)\b/.test(line)
  ).length;
  if (commandLineCount >= 2 || (commandLineCount >= 1 && lines.length <= 3 && !/[.!?]\s*$/.test(compact))) {
    return "command";
  }

  const codeSignals = [
    /^(import|from|export|const|let|var|function|class|interface|type|enum|def|async def|fn|pub fn|package|public class|SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|<\w+)/m,
    /[{};=][^\n]*$/m,
    /^\s{2,}\S/m,
    /^diff --git|^\+\+\+ |^--- |^@@/m,
  ];
  const codeScore = codeSignals.reduce((score, pattern) => score + (pattern.test(text) ? 1 : 0), 0);
  if (codeScore >= 2 || (codeScore >= 1 && lines.length >= 3)) {
    return "code";
  }

  return "text";
}

function isShellFenceLanguage(lang) {
  const value = String(lang || "").trim().toLowerCase();
  return ["bash", "sh", "shell", "zsh", "console", "terminal"].includes(value);
}

function splitAssistantTextSegments(content) {
  const text = String(content || "");
  if (!text.includes("```")) {
    return [{ kind: "text", content: text }];
  }

  const parts = [];
  const fenceRegex = /```([^\n`]*)\n?([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  while ((match = fenceRegex.exec(text))) {
    const [fullMatch, lang, fencedContent] = match;
    const leading = text.slice(lastIndex, match.index);
    if (normalizeText(leading)) {
      parts.push({ kind: "text", content: leading });
    }
    parts.push({
      kind: isShellFenceLanguage(lang) ? "command" : "code",
      content: fencedContent,
    });
    lastIndex = match.index + fullMatch.length;
  }

  const trailing = text.slice(lastIndex);
  if (normalizeText(trailing)) {
    parts.push({ kind: "text", content: trailing });
  }

  return parts.length ? parts : [{ kind: "text", content: text }];
}

function splitBlockSegments(blk, role) {
  const type = String(blk?.type || "text");
  const content = typeof blk?.content === "string" ? blk.content : JSON.stringify(blk?.content ?? "", null, 2);
  const kind = classifyBlockKind(type, role, content);

  if (role === "assistant" && kind === "text") {
    return splitAssistantTextSegments(content)
      .filter((segment) => normalizeText(segment.content))
      .map((segment) => ({
        ...segment,
        kind: segment.kind === "text" ? inferAssistantTextKind(segment.content) : segment.kind,
        type,
      }));
  }

  return normalizeText(content) ? [{ kind, content, type }] : [];
}

function highlightHtmlText(text, fragments) {
  let html = escapeHtml(text || "");
  for (const fragment of fragments) {
    const escapedFragment = escapeHtml(fragment);
    const pattern = new RegExp(escapeRegex(escapedFragment).replace(/\s+/g, "\\s+"), "gi");
    html = html.replace(pattern, (match) => `<mark class="risk-hit">${match}</mark>`);
  }
  return html;
}

function flattenBlocks(blocks) {
  const out = [];
  if (!Array.isArray(blocks)) return out;
  for (const entry of blocks) {
    if (Array.isArray(entry)) {
      for (const inner of entry) {
        if (inner && typeof inner === "object") out.push(inner);
      }
    } else if (entry && typeof entry === "object") {
      out.push(entry);
    }
  }
  return out;
}

function messageText(msg) {
  return flattenBlocks(msg?.blocks)
    .map((blk) => (typeof blk.content === "string" ? blk.content : ""))
    .filter(Boolean)
    .join("\n\n")
    .trim();
}

function csvEscape(value) {
  const s = String(value ?? "");
  return `"${s.replaceAll('"', '""')}"`;
}

function buildCsv(rows) {
  const header = [
    "index",
    "finding_id",
    "candidate_id",
    "chat_id",
    "cwe",
    "cwe_reason",
    "attribution_domain",
    "risk_snippets_appear_turn",
    "review_state",
    "cwe_correct",
    "reason_correct",
    "corrected_cwe",
    "corrected_reason",
    "notes",
    "updated_at",
  ];
  const lines = [header.join(",")];
  for (const row of rows) {
    const a = getAnnotation(row.finding_id);
    const record = [
      row.index,
      row.finding_id,
      row.candidate_id,
      row.chat_id,
      row.cwe,
      row.cwe_reason,
      row.attribution_domain,
      row.risk_snippets_appear_turn,
      a.review_state,
      a.cwe_correct,
      a.reason_correct,
      a.corrected_cwe,
      a.corrected_reason,
      a.notes,
      a.updated_at,
    ];
    lines.push(record.map(csvEscape).join(","));
  }
  return lines.join("\n");
}

function downloadText(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function getAnnotation(findingId) {
  return { ...defaultAnnotation(), ...(state.annotations[findingId] || {}) };
}

function setAnnotation(findingId, patch) {
  state.annotations[findingId] = {
    ...getAnnotation(findingId),
    ...patch,
    updated_at: new Date().toISOString(),
  };
  saveAnnotations();
  renderStats();
  renderQueue();
  renderRecord();
}

function clearAnnotation(findingId) {
  delete state.annotations[findingId];
  saveAnnotations();
  renderStats();
  renderQueue();
  renderRecord();
}

function matchesSearch(row, query) {
  if (!query) return true;
  const haystack = [
    row.index,
    row.finding_id,
    row.candidate_id,
    row.chat_id,
    row.cwe,
    row.cwe_reason,
    row.attribution_domain,
    row.risk_snippets_content,
    row.risk_snippets_appear_turn,
    row.assistant_candidate_text_short,
    row.nearest_user_text_short,
    getAnnotation(row.finding_id).notes,
  ]
    .map((value) => normalizeText(value).toLowerCase())
    .join(" | ");
  return haystack.includes(query.toLowerCase());
}

function getFilteredRows() {
  const q = normalizeText(state.search);
  return state.rows.filter((row) => {
    if (state.statusFilter !== "all") {
      const status = getAnnotation(row.finding_id).review_state;
      if (status !== state.statusFilter) return false;
    }
    return matchesSearch(row, q);
  });
}

function getCurrentRow() {
  return state.filteredRows.find((row) => row.finding_id === state.selectedFindingId) || state.filteredRows[0] || state.rows[0] || null;
}

function setSelectedFindingId(findingId) {
  state.selectedFindingId = findingId;
  const idx = state.filteredRows.findIndex((row) => row.finding_id === findingId);
  if (idx >= 0) {
    state.page = Math.floor(idx / state.pageSize) + 1;
  }
  renderQueue();
  renderRecord();
}

async function loadChat(row) {
  if (!row) return null;
  if (state.chatCache.has(row.source_file)) return state.chatCache.get(row.source_file);
  const res = await fetch(`${SOURCE_BASE}${row.source_file}`);
  if (!res.ok) {
    throw new Error(`Failed to load source file ${row.source_file}`);
  }
  const chat = await res.json();
  state.chatCache.set(row.source_file, chat);
  return chat;
}

function renderStats() {
  const counts = {
    total: state.rows.length,
    reviewed: 0,
    approve: 0,
    reject: 0,
    unsure: 0,
  };
  for (const row of state.rows) {
    const status = getAnnotation(row.finding_id).review_state;
    if (status !== "unreviewed") counts.reviewed += 1;
    if (counts[status] !== undefined) counts[status] += 1;
  }
  els.stats.innerHTML = [
    ["Total", counts.total],
    ["Reviewed", counts.reviewed],
    ["Approve", counts.approve],
    ["Reject", counts.reject],
  ]
    .map(
      ([label, value]) => `
        <div class="stat">
          <div class="value">${value}</div>
          <div class="label">${label}</div>
        </div>
      `
    )
    .join("");
}

function statusPill(status) {
  const map = {
    unreviewed: "pill",
    approve: "pill good",
    reject: "pill bad",
    unsure: "pill",
  };
  const labelMap = {
    unreviewed: "Unreviewed",
    approve: "Approve",
    reject: "Reject",
    unsure: "Unsure",
  };
  return `<span class="${map[status] || "pill"}">${labelMap[status] || status}</span>`;
}

function renderQueue() {
  state.filteredRows = getFilteredRows();
  const total = state.filteredRows.length;
  const pageCount = Math.max(1, Math.ceil(total / state.pageSize));
  state.page = Math.min(Math.max(1, state.page), pageCount);
  const start = (state.page - 1) * state.pageSize;
  const pageRows = state.filteredRows.slice(start, start + state.pageSize);
  if (!state.selectedFindingId || !state.filteredRows.some((row) => row.finding_id === state.selectedFindingId)) {
    state.selectedFindingId = pageRows[0]?.finding_id || state.filteredRows[0]?.finding_id || state.rows[0]?.finding_id || null;
  }
  els.queueInfo.textContent = `${total} results`;
  els.pageInfo.textContent = `Page ${state.page} of ${pageCount}`;
  els.pagePrev.disabled = state.page <= 1;
  els.pageNext.disabled = state.page >= pageCount;
  els.prevItem.disabled = !state.filteredRows.length;
  els.nextItem.disabled = !state.filteredRows.length;

  els.queueList.innerHTML = pageRows
    .map((row) => {
      const ann = getAnnotation(row.finding_id);
      const active = row.finding_id === state.selectedFindingId ? "active" : "";
      return `
        <button class="queue-item ${active}" data-finding-id="${escapeHtml(row.finding_id)}" type="button">
          <div class="row-top">
            <strong>#${row.index}</strong>
            <span class="mono queue-cwe">${escapeHtml(row.cwe)}</span>
            ${statusPill(ann.review_state)}
          </div>
          <div class="snippet">${escapeHtml(truncate(row.risk_snippets_content || row.assistant_candidate_text_short || "", 96))}</div>
        </button>
      `;
    })
    .join("");

  const statusOptions = ["all", ...REVIEW_STATES];
  els.statusFilter.innerHTML = statusOptions
    .map(
      (value) => `
        <option value="${value}" ${value === state.statusFilter ? "selected" : ""}>${value === "all" ? "All" : value.replaceAll("_", " ")}</option>
      `
    )
    .join("");
}

function renderReviewButtons(groupName, value) {
  const options = groupName === "review_state" ? REVIEW_STATES : BOOL_STATES;
  return options
    .map(
      (option) => `
        <button type="button" class="${option === value ? "selected" : ""}" data-field="${groupName}" data-value="${option}">${option.replaceAll("_", " ")}</button>
      `
    )
    .join("");
}

function renderRecordFields(row) {
  const items = [
    ["CWE", row.cwe],
    ["CWE Reason", row.cwe_reason],
    ["Attribution", row.attribution_domain],
  ];
  els.recordFields.innerHTML = items
    .map(
      ([k, v]) => `
        <div class="field-row">
          <div class="k">${escapeHtml(k)}</div>
          <div class="v">
            ${
              k === "CWE"
                ? `<button type="button" class="field-link" data-jump-target="risk-section" data-jump-index="${escapeHtml(row.index)}" data-jump-reason="cwe" title="${escapeHtml(v || "-")}">
                    <strong>${escapeHtml(v || "-")}</strong>
                    <span class="hint">Jump to risk block</span>
                  </button>`
                : k === "CWE Reason"
                  ? `<button type="button" class="field-link" data-jump-target="risk-section" data-jump-index="${escapeHtml(row.index)}" data-jump-reason="cwe_reason" title="${escapeHtml(v || "-")}">
                      ${escapeHtml(v || "-")}
                      <span class="hint">Jump to risk block</span>
                    </button>`
                  : k === "Attribution"
                    ? `<div class="plain-value">
                        <span class="has-tip" data-tip="${escapeAttr(CAUSE_EXPLANATIONS[v] || "The attribution label explains where the risky direction most likely came from.")}">
                          ${escapeHtml(v || "-")}
                        </span>
                      </div>`
                  : `<div class="plain-value">${escapeHtml(v || "-")}</div>`
            }
          </div>
        </div>
      `
    )
    .join("");
}

function renderTranscriptBlocks(blocks, messageIndex, row, fragments, role) {
  return flattenBlocks(blocks)
    .flatMap((blk, blockIndex) =>
      splitBlockSegments(blk, role).map((segment, segmentIndex) => ({ blk, blockIndex, segment, segmentIndex }))
    )
    .map(({ blockIndex, segment, segmentIndex }) => {
      const type = String(segment.type || "text");
      const content = segment.content;
      const selected = Number(row.assistant_message_index) === messageIndex && Number(row.assistant_block_index) === blockIndex;
      const normalizedContent = normalizeText(content);
      const hitScore = normalizedContent
        ? fragments.reduce((score, fragment) => score + (normalizedContent.includes(fragment) ? fragment.length : 0), 0)
        : 0;
      const hit = hitScore > 0;
      const kind = segment.kind;
      const jumpTarget = role === "assistant" && (selected || hit) ? "nearest-user" : "";
      return `
        <div class="block ${kind} ${selected ? "selected-block" : ""} ${hit ? "risk-block-hit" : ""}" id="block-${messageIndex}-${blockIndex}${segmentIndex ? `-seg-${segmentIndex}` : ""}" data-message-index="${messageIndex}" data-block-index="${blockIndex}" data-hit-score="${hitScore}" ${jumpTarget ? `data-jump-target="${jumpTarget}"` : ""}>
          <div class="block-head">
            <div class="type">${escapeHtml(kind === "user" ? "user prompt" : kind === "command" ? "assistant command" : kind === "code" ? "assistant code" : kind === "text" ? "assistant text" : type)}</div>
            ${selected || hit ? '<span class="pill active">Risk Block</span>' : ""}
          </div>
          <pre>${highlightHtmlText(content, fragments)}</pre>
        </div>
      `;
    })
    .join("");
}

function renderTranscriptMessage(msg, index, row) {
  const role = String(msg.role || "unknown").toLowerCase();
  const isSelected = index === Number(row.assistant_message_index);
  const isNeighbor = index === Number(row.nearest_user_message_index);
  const jumpTarget = isNeighbor ? "assistant-risk" : "";
  const classes = ["message", role, isSelected ? "selected" : "", isNeighbor ? "neighbor" : "", role === "user" ? "prompt" : "assistant"].filter(Boolean).join(" ");
  const text = messageText(msg);
  const blocks = flattenBlocks(msg.blocks).filter((blk) =>
    normalizeText(typeof blk?.content === "string" ? blk.content : JSON.stringify(blk?.content ?? "", null, 2))
  );
  const showBody = blocks.length === 0 && Boolean(normalizeText(text));
  const fragments = buildRiskFragments(row);
  if (!showBody && blocks.length === 0) {
    return "";
  }
  return `
    <article class="${classes}" id="message-${index}" ${jumpTarget ? `data-jump-target="${jumpTarget}"` : ""}>
      <div class="message-head">
        <div>
          <span class="message-role">${escapeHtml(role === "user" ? "user prompt" : "assistant reply")}</span>
          ${isSelected ? `<span class="pill active">Risk Turn</span>` : ""}
          ${isNeighbor ? `<span class="pill">Nearest User</span>` : ""}
        </div>
        <span class="pill">Turn ${index}</span>
      </div>
      ${showBody ? `<div class="message-body">${highlightHtmlText(text || "", fragments)}</div>` : ""}
      <div class="block-list">
        ${renderTranscriptBlocks(blocks, index, row, fragments, role)}
      </div>
    </article>
  `;
}

function flashElement(el) {
  if (!el) return;
  el.classList.add("flash-target");
  window.setTimeout(() => el.classList.remove("flash-target"), 1200);
}

function jumpToRiskSection(row) {
  const messageIndex = Number(row.assistant_message_index);
  const blockIndex = Number(row.assistant_block_index);
  const blockCandidates = Array.from(document.querySelectorAll(`[data-message-index="${messageIndex}"][data-block-index="${blockIndex}"]`));
  const block = blockCandidates.sort((a, b) => Number(b.dataset.hitScore || 0) - Number(a.dataset.hitScore || 0))[0] || null;
  const message = document.querySelector(`#message-${messageIndex}`);
  const target = block || message;
  if (target) {
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    flashElement(target);
  }
}

function jumpToNearestUser(row) {
  const messageIndex = Number(row.nearest_user_message_index);
  const target = document.querySelector(`#message-${messageIndex}`);
  if (target) {
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    flashElement(target);
  }
}

async function renderRecord() {
  const token = ++state.renderToken;
  const row = getCurrentRow();
  if (!row) {
    els.recordTitle.textContent = "No record selected";
    els.recordMeta.textContent = "";
    els.recordBadges.innerHTML = "";
    els.recordFields.innerHTML = "";
    els.transcript.innerHTML = "";
    els.rawJson.textContent = "";
    return;
  }

  const ann = getAnnotation(row.finding_id);
  els.recordTitle.textContent = `#${row.index}`;
  els.recordMeta.textContent = `${row.cwe} · ${row.attribution_domain}`;
  els.recordBadges.innerHTML = [
    statusPill(ann.review_state),
    `<span class="pill">${escapeHtml(ann.cwe_correct)}</span>`,
    `<span class="pill">${escapeHtml(ann.reason_correct)}</span>`,
  ].join("");
  renderRecordFields(row);

  els.correctedCwe.value = ann.corrected_cwe;
  els.correctedReason.value = ann.corrected_reason;
  els.notes.value = ann.notes;

  const reviewButtons = document.querySelector('[data-group="review_state"]');
  const cweButtons = document.querySelector('[data-group="cwe_correct"]');
  const reasonButtons = document.querySelector('[data-group="reason_correct"]');
  reviewButtons.innerHTML = renderReviewButtons("review_state", ann.review_state);
  cweButtons.innerHTML = renderReviewButtons("cwe_correct", ann.cwe_correct);
  reasonButtons.innerHTML = renderReviewButtons("reason_correct", ann.reason_correct);

  let rawChat = null;
  try {
    rawChat = await loadChat(row);
  } catch (err) {
    console.error(err);
  }
  if (token !== state.renderToken) return;
  if (rawChat) {
    els.transcript.innerHTML = rawChat.messages
      .map((msg, index) => renderTranscriptMessage(msg, index, row))
      .join("");
    els.rawJson.textContent = JSON.stringify(rawChat, null, 2);
    els.rawJson.classList.toggle("hidden", !state.showRaw);
  } else {
    els.transcript.innerHTML = "<p>Failed to load transcript.</p>";
    els.rawJson.textContent = "";
    els.rawJson.classList.add("hidden");
  }
}

function nextInFiltered(delta) {
  if (!state.filteredRows.length) return;
  const idx = state.filteredRows.findIndex((row) => row.finding_id === state.selectedFindingId);
  const nextIdx = idx < 0 ? 0 : (idx + delta + state.filteredRows.length) % state.filteredRows.length;
  const next = state.filteredRows[nextIdx];
  if (next) {
    state.selectedFindingId = next.finding_id;
    const pageIdx = Math.floor(nextIdx / state.pageSize) + 1;
    state.page = pageIdx;
    renderQueue();
    renderRecord();
  }
}

function bindControls() {
  els.searchInput.addEventListener("input", (e) => {
    state.search = e.target.value;
    state.page = 1;
    renderQueue();
    renderRecord();
  });

  els.statusFilter.addEventListener("change", (e) => {
    state.statusFilter = e.target.value;
    state.page = 1;
    renderQueue();
    renderRecord();
  });

  els.pageSize.addEventListener("change", (e) => {
    state.pageSize = Number(e.target.value) || 25;
    state.page = 1;
    renderQueue();
    renderRecord();
  });

  els.jumpInput.addEventListener("change", (e) => {
    const value = Number(e.target.value);
    const row = state.rows.find((item) => Number(item.index) === value);
    if (row) {
      state.selectedFindingId = row.finding_id;
      const idx = state.filteredRows.findIndex((item) => item.finding_id === row.finding_id);
      if (idx >= 0) state.page = Math.floor(idx / state.pageSize) + 1;
      renderQueue();
      renderRecord();
    }
  });

  els.prevItem.addEventListener("click", () => nextInFiltered(-1));
  els.nextItem.addEventListener("click", () => nextInFiltered(1));
  els.pagePrev.addEventListener("click", () => {
    state.page = Math.max(1, state.page - 1);
    renderQueue();
  });
  els.pageNext.addEventListener("click", () => {
    const pageCount = Math.max(1, Math.ceil(state.filteredRows.length / state.pageSize));
    state.page = Math.min(pageCount, state.page + 1);
    renderQueue();
  });

  els.queueList.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-finding-id]");
    if (!btn) return;
    state.selectedFindingId = btn.dataset.findingId;
    renderQueue();
    renderRecord();
  });

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-field][data-value]");
    if (!btn) return;
    const field = btn.dataset.field;
    const value = btn.dataset.value;
    const row = getCurrentRow();
    if (!row) return;
    setAnnotation(row.finding_id, { [field]: value });
  });

  document.addEventListener("click", (e) => {
    const jumpAssistant = e.target.closest("[data-jump-target='assistant-risk']");
    if (jumpAssistant) {
      const row = getCurrentRow();
      if (!row) return;
      jumpToRiskSection(row);
      return;
    }

    const jumpUser = e.target.closest("[data-jump-target='nearest-user']");
    if (jumpUser) {
      const row = getCurrentRow();
      if (!row) return;
      jumpToNearestUser(row);
      return;
    }

    const btn = e.target.closest("[data-jump-target='risk-section']");
    if (!btn) return;
    const row = getCurrentRow();
    if (!row) return;
    jumpToRiskSection(row);
  });

  els.correctedCwe.addEventListener("input", (e) => {
    const row = getCurrentRow();
    if (!row) return;
    setAnnotation(row.finding_id, { corrected_cwe: e.target.value });
  });
  els.correctedReason.addEventListener("input", (e) => {
    const row = getCurrentRow();
    if (!row) return;
    setAnnotation(row.finding_id, { corrected_reason: e.target.value });
  });
  els.notes.addEventListener("input", (e) => {
    const row = getCurrentRow();
    if (!row) return;
    setAnnotation(row.finding_id, { notes: e.target.value });
  });

  els.saveNow.addEventListener("click", () => saveAnnotations());
  els.resetItem.addEventListener("click", () => {
    const row = getCurrentRow();
    if (!row) return;
    clearAnnotation(row.finding_id);
  });
  els.clearStorage.addEventListener("click", () => {
    localStorage.removeItem(STORAGE_KEY);
    state.annotations = {};
    renderStats();
    renderQueue();
    renderRecord();
    setSaveState("Saved annotations cleared.");
  });

  els.exportJson.addEventListener("click", () => {
    const payload = state.rows.map((row) => ({
      index: row.index,
      finding_id: row.finding_id,
      candidate_id: row.candidate_id,
      chat_id: row.chat_id,
      cwe: row.cwe,
      cwe_reason: row.cwe_reason,
      attribution_domain: row.attribution_domain,
      risk_snippets_appear_turn: row.risk_snippets_appear_turn,
      annotation: getAnnotation(row.finding_id),
    }));
    downloadText("risk_annotations.json", JSON.stringify(payload, null, 2), "application/json");
  });

  els.exportCsv.addEventListener("click", () => {
    downloadText("risk_annotations.csv", buildCsv(state.rows), "text/csv");
  });

  els.toggleRaw.addEventListener("click", async () => {
    state.showRaw = !state.showRaw;
    els.rawJson.classList.toggle("hidden", !state.showRaw);
  });

  document.addEventListener("keydown", (e) => {
    const tag = document.activeElement?.tagName?.toLowerCase();
    const editing = tag === "input" || tag === "textarea" || document.activeElement?.isContentEditable;
    if (editing) return;
    if (e.key === "j" || e.key === "ArrowRight") {
      e.preventDefault();
      nextInFiltered(1);
    } else if (e.key === "k" || e.key === "ArrowLeft") {
      e.preventDefault();
      nextInFiltered(-1);
    } else if (e.key === "1") {
      e.preventDefault();
      const row = getCurrentRow();
      if (row) setAnnotation(row.finding_id, { review_state: "approve" });
    } else if (e.key === "2") {
      e.preventDefault();
      const row = getCurrentRow();
      if (row) setAnnotation(row.finding_id, { review_state: "reject" });
    } else if (e.key === "3") {
      e.preventDefault();
      const row = getCurrentRow();
      if (row) setAnnotation(row.finding_id, { review_state: "unsure" });
    } else if (e.key === "4") {
      e.preventDefault();
      const row = getCurrentRow();
      if (row) setAnnotation(row.finding_id, { review_state: "unreviewed" });
    }
  });
}

async function init() {
  els.stats = document.querySelector("#stats");
  els.searchInput = document.querySelector("#search-input");
  els.statusFilter = document.querySelector("#status-filter");
  els.pageSize = document.querySelector("#page-size");
  els.jumpInput = document.querySelector("#jump-input");
  els.queueInfo = document.querySelector("#queue-info");
  els.pageInfo = document.querySelector("#page-info");
  els.queueList = document.querySelector("#queue-list");
  els.pagePrev = document.querySelector("#page-prev");
  els.pageNext = document.querySelector("#page-next");
  els.prevItem = document.querySelector("#prev-item");
  els.nextItem = document.querySelector("#next-item");
  els.recordTitle = document.querySelector("#record-title");
  els.recordMeta = document.querySelector("#record-meta");
  els.recordBadges = document.querySelector("#record-badges");
  els.recordFields = document.querySelector("#record-fields");
  els.transcript = document.querySelector("#transcript");
  els.rawJson = document.querySelector("#raw-json");
  els.correctedCwe = document.querySelector("#corrected-cwe");
  els.correctedReason = document.querySelector("#corrected-reason");
  els.notes = document.querySelector("#notes");
  els.saveState = document.querySelector("#save-state");
  els.saveNow = document.querySelector("#save-now");
  els.resetItem = document.querySelector("#reset-item");
  els.clearStorage = document.querySelector("#clear-storage");
  els.exportJson = document.querySelector("#export-json");
  els.exportCsv = document.querySelector("#export-csv");
  els.toggleRaw = document.querySelector("#toggle-raw");
  els.showRaw = false;

  els.pageSize.innerHTML = PAGE_SIZES.map((size) => `<option value="${size}" ${size === state.pageSize ? "selected" : ""}>${size}</option>`).join("");

  try {
    const res = await fetch(MANIFEST_URL);
    if (!res.ok) throw new Error(`Failed to load manifest: ${res.status}`);
    state.rows = await res.json();
  } catch (err) {
    els.recordTitle.textContent = "Failed to load manifest";
    els.recordMeta.textContent = String(err);
    return;
  }

  if (!state.rows.length) {
    els.recordTitle.textContent = "No rows found";
    return;
  }

  bindControls();
  state.filteredRows = getFilteredRows();
  state.selectedFindingId = state.rows[0].finding_id;
  renderStats();
  renderQueue();
  await renderRecord();
}

init();
