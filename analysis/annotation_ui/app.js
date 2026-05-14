const DATASET_URL = "../output/finding_annotation_dataset.json";
const CWE_CATALOG_URL = "../output/cwe_catalog_full.json";
const STORAGE_PREFIX = "vibe-risk-finding-annotations:";

const state = {
  dataset: null,
  records: [],
  filtered: [],
  annotations: {},
  selectedIndex: 0,
  page: 0,
  pageSize: 100,
  storageKey: STORAGE_PREFIX + "default",
  cweCatalog: new Map(),
  cweEntries: [],
  activeTab: "code",
};

const el = {
  datasetMeta: document.getElementById("datasetMeta"),
  fileInput: document.getElementById("fileInput"),
  exportJsonl: document.getElementById("exportJsonl"),
  exportCsv: document.getElementById("exportCsv"),
  searchBox: document.getElementById("searchBox"),
  statusFilter: document.getElementById("statusFilter"),
  severityFilter: document.getElementById("severityFilter"),
  agreementFilter: document.getElementById("agreementFilter"),
  pageSize: document.getElementById("pageSize"),
  progressText: document.getElementById("progressText"),
  progressBar: document.getElementById("progressBar"),
  prevPage: document.getElementById("prevPage"),
  nextPage: document.getElementById("nextPage"),
  pageText: document.getElementById("pageText"),
  recordList: document.getElementById("recordList"),
  emptyState: document.getElementById("emptyState"),
  recordDetail: document.getElementById("recordDetail"),
  humanAgree: document.getElementById("humanAgree"),
  humanPrimaryCwe: document.getElementById("humanPrimaryCwe"),
  cweSuggestions: document.getElementById("cweSuggestions"),
  humanNotes: document.getElementById("humanNotes"),
  copyCode: document.getElementById("copyCode"),
  copyContext: document.getElementById("copyContext"),
  candidateMeta: document.getElementById("candidateMeta"),
  findingMeta: document.getElementById("findingMeta"),
  candidateCode: document.getElementById("candidateCode"),
  evidenceBox: document.getElementById("evidenceBox"),
  contextBox: document.getElementById("contextBox"),
  cweBox: document.getElementById("cweBox"),
};

function text(value) {
  if (value === null || value === undefined || value === "") return "unknown";
  if (Array.isArray(value)) return value.join(", ") || "unknown";
  return String(value);
}

function escapeHtml(value) {
  return text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function markdownToHtml(value) {
  const source = text(value);
  const blocks = source.split(/```/);
  return blocks
    .map((block, index) => {
      if (index % 2 === 1) {
        const lines = block.replace(/^\w+\n/, "");
        return `<pre class="mdCode"><code>${escapeHtml(lines)}</code></pre>`;
      }
      return renderMarkdownText(block);
    })
    .join("");
}

function renderMarkdownText(value) {
  const lines = value.split(/\n/);
  const html = [];
  let listOpen = false;
  const closeList = () => {
    if (listOpen) {
      html.push("</ul>");
      listOpen = false;
    }
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim()) {
      closeList();
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = Math.min(heading[1].length + 2, 5);
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) {
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
      continue;
    }
    closeList();
    html.push(`<p>${inlineMarkdown(line)}</p>`);
  }
  closeList();
  return html.join("");
}

function inlineMarkdown(value) {
  return escapeHtml(value)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function datasetId(payload) {
  const meta = payload.metadata || {};
  return [
    meta.source_findings || "findings",
    meta.record_count || 0,
    meta.finding_record_count || 0,
    meta.group_review_units ? "units" : "findings",
    meta.review_unit_scope || "default",
    meta.context_before || 0,
    meta.context_after || 0,
  ].join(":");
}

async function loadDefaultDataset() {
  await loadCweCatalog();
  try {
    const response = await fetch(DATASET_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    setDataset(payload);
  } catch (error) {
    el.datasetMeta.textContent = `No default dataset at ${DATASET_URL}`;
  }
}

async function loadCweCatalog() {
  try {
    const response = await fetch(CWE_CATALOG_URL, { cache: "force-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    state.cweEntries = entries;
    state.cweCatalog = new Map(entries.map((entry) => [normalizeCwe(entry.cwe), entry]));
  } catch {
    state.cweEntries = [];
    state.cweCatalog = new Map();
  }
}

function setDataset(payload) {
  state.dataset = payload;
  state.records = Array.isArray(payload.records) ? payload.records : [];
  state.storageKey = STORAGE_PREFIX + datasetId(payload);
  state.annotations = loadAnnotations();
  state.selectedIndex = 0;
  state.page = 0;
  populateFilters();
  applyFilters();
  updateDatasetMeta();
}

function loadAnnotations() {
  try {
    return JSON.parse(localStorage.getItem(state.storageKey) || "{}");
  } catch {
    return {};
  }
}

function saveAnnotations() {
  localStorage.setItem(state.storageKey, JSON.stringify(state.annotations));
  updateProgress();
}

function currentRecord() {
  return state.filtered[state.selectedIndex] || null;
}

function recordKey(record) {
  return record?.review_unit_id || record?.id || record?.finding_id;
}

function annotationFor(record) {
  if (!record) return {};
  return state.annotations[recordKey(record)] || {};
}

function isLabeled(annotation) {
  return Boolean(agreementValue(annotation) || annotation.human_notes);
}

function agreementValue(annotation) {
  if (annotation.human_agrees_with_finding) return annotation.human_agrees_with_finding;
  if (annotation.human_agrees_with_existing) return annotation.human_agrees_with_existing;
  if (annotation.human_agreement === "agree") return "true";
  if (annotation.human_agreement === "disagree") return "false";
  if (annotation.human_is_valid_risk === "true") return "true";
  if (["false", "needs_review"].includes(annotation.human_is_valid_risk)) return "false";
  return "";
}

function populateFilters() {
  const severities = new Set();
  const agreements = new Set();
  for (const record of state.records) {
    if (record.severity) severities.add(record.severity);
    if (record.agreement) agreements.add(record.agreement);
  }
  fillSelect(el.severityFilter, "All severities", severities);
  fillSelect(el.agreementFilter, "All sources", agreements);
}

function fillSelect(select, firstLabel, values) {
  const previous = select.value;
  select.innerHTML = `<option value="all">${escapeHtml(firstLabel)}</option>`;
  [...values].sort().forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
  if ([...select.options].some((option) => option.value === previous)) {
    select.value = previous;
  }
}

function applyFilters() {
  const query = el.searchBox.value.trim().toLowerCase();
  const status = el.statusFilter.value;
  const severity = el.severityFilter.value;
  const agreement = el.agreementFilter.value;
  state.pageSize = Number(el.pageSize.value || 100);

  state.filtered = state.records.filter((record) => {
    const ann = annotationFor(record);
    if (severity !== "all" && record.severity !== severity) return false;
    if (agreement !== "all" && record.agreement !== agreement) return false;
    if (status !== "all") {
      const labeled = isLabeled(ann);
      if (status === "unlabeled" && labeled) return false;
      if (status === "labeled" && !labeled) return false;
      if (status === "agree" && agreementValue(ann) !== "true") return false;
      if (status === "disagree" && agreementValue(ann) !== "false") return false;
    }
    if (!query) return true;
    const haystack = [
      record.review_unit_id,
      record.finding_id,
      ...(record.finding_ids || []),
      record.candidate_id,
      ...(record.candidate_ids || []),
      record.chat_id,
      record.file_path,
      ...(record.file_paths || []),
      ...(record.turn_indices || []),
      record.primary_cwe,
      ...(record.cwe_ids || []),
      record.content,
      record.reasoning,
    ]
      .join("\n")
      .toLowerCase();
    return haystack.includes(query);
  });

  if (state.selectedIndex >= state.filtered.length) {
    state.selectedIndex = Math.max(0, state.filtered.length - 1);
  }
  state.page = pageForIndex(state.selectedIndex);
  renderList();
  renderDetail();
  updateProgress();
}

function pageCount() {
  return Math.max(1, Math.ceil(state.filtered.length / state.pageSize));
}

function pageForIndex(index) {
  return Math.max(0, Math.floor(Math.max(0, index) / state.pageSize));
}

function visibleRecords() {
  const start = state.page * state.pageSize;
  return state.filtered.slice(start, start + state.pageSize);
}

function updateDatasetMeta() {
  const meta = state.dataset?.metadata || {};
  const mode = meta.group_review_units ? "review units" : "findings";
  const sourceCount = meta.finding_record_count ? `from ${meta.finding_record_count} findings` : "";
  const scope = meta.review_unit_scope ? `scope ${meta.review_unit_scope}` : "";
  el.datasetMeta.textContent = [
    `${state.records.length} ${mode}`,
    sourceCount,
    scope,
    `source ${meta.source_findings || "loaded file"}`,
  ]
    .filter(Boolean)
    .join(" · ");
}

function updateProgress() {
  const total = state.records.length;
  const labeled = state.records.filter((record) => isLabeled(annotationFor(record))).length;
  const pct = total ? Math.round((labeled / total) * 100) : 0;
  el.progressText.textContent = [
    `${labeled} / ${total} units labeled`,
    `${state.filtered.length} matched`,
  ].join(" · ");
  el.progressBar.style.width = `${pct}%`;
  el.pageText.textContent = `Page ${state.page + 1} / ${pageCount()}`;
  el.prevPage.disabled = state.page <= 0;
  el.nextPage.disabled = state.page >= pageCount() - 1;
}

function renderList() {
  el.recordList.innerHTML = "";
  const fragment = document.createDocumentFragment();
  const pageStart = state.page * state.pageSize;
  for (const [offset, record] of visibleRecords().entries()) {
    const index = pageStart + offset;
    const ann = annotationFor(record);
    const item = document.createElement("button");
    item.type = "button";
    item.className = `recordItem ${index === state.selectedIndex ? "active" : ""}`;
    item.innerHTML = `
      <div class="recordItemTop">
        <span>${escapeHtml(record.primary_cwe || record.cwe_ids?.[0] || "unmapped")}</span>
        <span class="recordItemRight">
          ${annotationStatus(ann)}
          ${badge(record.severity || "unknown", "severity")}
        </span>
      </div>
      <div class="recordItemCwe">${escapeHtml(cweEntry(record.primary_cwe || record.cwe_ids?.[0])?.name || "")}</div>
      <div class="recordItemMeta">
        ${escapeHtml(record.chat_id)} · ${escapeHtml(turnLabel(record))}
        · ${escapeHtml(fileLabel(record))}
      </div>
    `;
    item.addEventListener("click", () => {
      state.selectedIndex = index;
      renderList();
      renderDetail();
    });
    fragment.appendChild(item);
  }
  el.recordList.appendChild(fragment);
}

function badge(value, extraClass = "") {
  if (!value) return "";
  const className = `${escapeHtml(value)} ${escapeHtml(extraClass)}`.trim();
  return `<span class="badge ${className}">${escapeHtml(value)}</span>`;
}

function annotationStatus(annotation) {
  const agrees = agreementValue(annotation);
  if (agrees === "true") return '<span class="annotationStatus agree">Agree</span>';
  if (agrees === "false") return '<span class="annotationStatus disagree">Disagree</span>';
  return '<span class="annotationStatus unlabeled">Unlabeled</span>';
}

function renderDetail() {
  const record = currentRecord();
  if (!record) {
    el.emptyState.classList.remove("hidden");
    el.recordDetail.classList.add("hidden");
    return;
  }
  el.emptyState.classList.add("hidden");
  el.recordDetail.classList.remove("hidden");

  const ann = annotationFor(record);
  el.humanAgree.value = agreementValue(ann);
  el.humanPrimaryCwe.value = cweInputValue(ann);
  el.humanNotes.value = ann.human_notes || "";
  updateAnnotationSteps();
  hideCweSuggestions();

  el.candidateMeta.innerHTML = metaGrid([
    ["chat", record.chat_id],
    ["turns", turnLabel(record)],
    ["files", fileLabel(record)],
    ["findings", record.finding_count || 1],
    ["candidates", record.candidate_count || 1],
    ["type", record.candidate_type],
    ["language", record.language_hint],
    ["platform", record.platform],
    ["timestamp", record.timestamp],
  ]);
  el.findingMeta.innerHTML = metaGrid([
    ["review unit", record.review_unit_id || record.finding_id],
    ["finding ids", record.finding_ids || record.finding_id],
    ["source", record.agreement],
    ["analyzers", record.analyzers],
    ["risk confidence", record.risk_confidence_tier],
    ["cwe confidence", record.cwe_confidence_tier],
    ["needs CWE review", record.needs_human_cwe_review],
  ]);
  renderCandidatePane(record);
  renderEvidence(record);
  renderContext(record);
  renderCwe(record);
  renderTabs();
}

function turnLabel(record) {
  const turns = record.turn_indices || [];
  if (!turns.length) return `turn ${text(record.turn_index)}`;
  if (turns.length === 1) return `turn ${turns[0]}`;
  return `turns ${turns[0]}-${turns[turns.length - 1]} (${turns.length})`;
}

function fileLabel(record) {
  const files = (record.file_paths || []).filter((value) => value && value !== "unknown");
  if (!files.length) return record.file_path || "unknown file";
  if (files.length === 1) return files[0];
  return `${files.length} files`;
}

function renderCandidatePane(record) {
  const candidates = record.candidates?.length
    ? record.candidates
    : [
        {
          candidate_id: record.candidate_id,
          turn_index: record.turn_index,
          block_index: record.block_index,
          candidate_type: record.candidate_type,
          language_hint: record.language_hint,
          file_path: record.file_path,
          content: record.content,
          context_turns: record.context_turns,
        },
      ];
  el.candidateCode.innerHTML = candidates
    .map(
      (candidate, index) => `
        <section class="candidateBlock">
          <div class="candidateBlockHead">
            <strong>candidate ${index + 1}</strong>
            <span>${escapeHtml(candidate.file_path || "unknown file")}</span>
            <span>block ${escapeHtml(candidate.block_index)}</span>
          </div>
          <pre class="codeBlock">${escapeHtml(candidate.content)}</pre>
        </section>
      `
    )
    .join("");
}

function metaGrid(rows) {
  return rows
    .map(
      ([key, value]) => `
        <div class="metaCell">
          <span class="metaKey">${escapeHtml(key)}</span>
          <span class="metaValue">${escapeHtml(value)}</span>
        </div>
      `
    )
    .join("");
}

function renderEvidence(record) {
  const findingRows = record.findings?.length
    ? record.findings
    : [
        {
          finding_id: record.finding_id,
          candidate_id: record.candidate_id,
          evidence: record.evidence,
          reasoning: record.reasoning,
          severity: record.severity,
          agreement: record.agreement,
        },
      ];
  const items = [];
  for (const finding of findingRows) {
    items.push(`
      <div class="evidenceItem">
        <div class="contextHead">
          <strong>${escapeHtml(finding.finding_id)}</strong>
          <span>${escapeHtml(finding.severity)} · ${escapeHtml(finding.agreement)}</span>
        </div>
        <div class="evidenceReason">candidate: ${escapeHtml(finding.candidate_id)}</div>
      </div>
    `);
    const byAnalyzer = finding.evidence?.by_analyzer || {};
    for (const [analyzer, rows] of Object.entries(byAnalyzer)) {
      for (const row of rows || []) {
        items.push(`
          <div class="evidenceItem">
            <div class="contextHead"><strong>${escapeHtml(analyzer)}</strong></div>
            <div class="evidenceQuote">${escapeHtml(row.quote)}</div>
            <div class="evidenceReason">${escapeHtml(row.reason)}</div>
          </div>
        `);
      }
    }
    if (finding.reasoning) {
      items.push(`
        <div class="evidenceItem">
          <div class="contextHead"><strong>judge reasoning</strong></div>
          <div class="evidenceReason">${escapeHtml(finding.reasoning)}</div>
        </div>
      `);
    }
  }
  el.evidenceBox.innerHTML =
    items.join("") || '<div class="evidenceItem">No evidence available</div>';
}

function renderContext(record) {
  const candidates = record.candidates?.length
    ? record.candidates
    : [
        {
          candidate_id: record.candidate_id,
          turn_index: record.turn_index,
          candidate_type: record.candidate_type,
          language_hint: record.language_hint,
          file_path: record.file_path,
          content: record.content,
          context_turns: record.context_turns,
        },
      ];
  if (candidates.length > 1) {
    el.contextBox.innerHTML = candidates.map(renderCandidateContextGroup).join("");
    return;
  }
  const context = candidates[0]?.context_turns || record.context_turns || [];
  const items = [];
  let candidateInserted = false;
  for (const turn of context) {
    items.push(renderContextTurn(turn));
    if (Number(turn.turn_index) === Number(candidates[0]?.turn_index ?? record.turn_index)) {
      items.push(renderCandidateContext(record, candidates));
      candidateInserted = true;
    }
  }
  if (!candidateInserted && record.content) {
    items.push(renderCandidateContext(record, candidates));
  }
  el.contextBox.innerHTML = items.join("") || '<div class="contextTurn">No context loaded</div>';
}

function renderCandidateContextGroup(candidate) {
  const context = candidate.context_turns || [];
  const items = [];
  let inserted = false;
  for (const turn of context) {
    items.push(renderContextTurn(turn));
    if (Number(turn.turn_index) === Number(candidate.turn_index)) {
      items.push(renderCandidateContextItem(candidate));
      inserted = true;
    }
  }
  if (!inserted) {
    items.push(renderCandidateContextItem(candidate));
  }
  return `
    <section class="candidateContextGroup">
      <div class="contextGroupHead">
        <strong>${escapeHtml(candidate.file_path || "unknown file")}</strong>
        <span>${escapeHtml(candidate.candidate_id)}</span>
      </div>
      ${items.join("")}
    </section>
  `;
}

function renderContextTurn(turn) {
  const role = text(turn.role);
  return `
    <div class="contextTurn ${escapeHtml(role)}">
      <div class="contextHead">
        <strong>${escapeHtml(role)}</strong>
        <span>turn ${escapeHtml(turn.turn_index)}</span>
      </div>
      <div class="contextText mdBody">${markdownToHtml(turn.text)}</div>
    </div>
  `;
}

function renderCandidateContext(record, candidatesOverride = null) {
  const candidates =
    candidatesOverride || record.candidates?.length
      ? candidatesOverride || record.candidates
      : [
          {
            candidate_id: record.candidate_id,
            candidate_type: record.candidate_type,
            language_hint: record.language_hint,
            file_path: record.file_path,
            content: record.content,
          },
        ];
  return `
    <div class="contextTurn candidateContext">
      <div class="contextHead">
        <strong>candidate(s) under review</strong>
        <span>${escapeHtml(candidates.length)} candidate(s)</span>
      </div>
      ${candidates.map(renderCandidateContextItem).join("")}
    </div>
  `;
}

function renderCandidateContextItem(candidate, index = 0) {
  return `
    <div class="candidateContextItem">
      <div class="contextHead">
        <strong>candidate ${index + 1}</strong>
        <span>${escapeHtml(candidate.file_path || "unknown file")}</span>
      </div>
      <pre class="codeBlock compact">${escapeHtml(candidate.content)}</pre>
    </div>
  `;
}

function renderCwe(record) {
  const considered = record.cwe_candidates_considered || [];
  const rejected = record.rejected_cwes || [];
  const selectedCwes = record.cwe_ids?.length ? record.cwe_ids : [record.primary_cwe];
  const sections = [
    cweSection("Selected", selectedCwes, record.cwe_confidence_tier),
  ];
  if (considered.length) {
    sections.push(cweSection("Considered", considered));
  }
  for (const row of rejected) {
    const id = row.cwe || row.cwe_id;
    const entry = cweEntry(id);
    sections.push(`
      <div class="cweItem">
        <div class="cweHead"><strong>${escapeHtml(id)}</strong><span>rejected</span></div>
        ${
          entry
            ? `<div class="cweName">${escapeHtml(entry.name)}</div>
               <div class="cweDescription">${escapeHtml(oneLine(entry.description))}</div>`
            : ""
        }
        <div class="cweReason">${escapeHtml(row.reason)}</div>
      </div>
    `);
  }
  el.cweBox.innerHTML = sections.join("");
}

function candidateText(record) {
  const candidates = record.candidates?.length
    ? record.candidates
    : [
        {
          candidate_id: record.candidate_id,
          file_path: record.file_path,
          content: record.content,
        },
      ];
  return candidates
    .map((candidate, index) =>
      [
        `candidate ${index + 1}`,
        candidate.candidate_id ? `id: ${candidate.candidate_id}` : "",
        candidate.file_path ? `file: ${candidate.file_path}` : "",
        "",
        candidate.content || "",
      ]
        .filter((line) => line !== "")
        .join("\n")
    )
    .join("\n\n---\n\n");
}

function contextText(record) {
  const candidates = record.candidates?.length
    ? record.candidates
    : [
        {
          candidate_id: record.candidate_id,
          turn_index: record.turn_index,
          file_path: record.file_path,
          content: record.content,
          context_turns: record.context_turns,
        },
      ];
  const blocks = [];
  for (const candidate of candidates) {
    if (candidates.length > 1) {
      blocks.push(
        [
          `candidate: ${candidate.candidate_id || "unknown"}`,
          `file: ${candidate.file_path || "unknown file"}`,
        ].join("\n")
      );
    }
    for (const turn of candidate.context_turns || record.context_turns || []) {
      blocks.push(`[${turn.role || "unknown"} turn ${turn.turn_index ?? "unknown"}]\n${turn.text || ""}`);
    }
    blocks.push(
      [
        "[candidate under review]",
        candidate.content || record.content || "",
      ].join("\n")
    );
  }
  return blocks.join("\n\n---\n\n");
}

async function copyText(button, value) {
  const previous = button.textContent;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value || "");
    } else {
      fallbackCopy(value || "");
    }
    button.textContent = "✓";
    button.classList.add("copied");
  } catch {
    fallbackCopy(value || "");
    button.textContent = "✓";
    button.classList.add("copied");
  }
  window.setTimeout(() => {
    button.textContent = previous;
    button.classList.remove("copied");
  }, 900);
}

function fallbackCopy(value) {
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

function normalizeCwe(value) {
  if (!value) return "";
  const upper = String(value).trim().toUpperCase();
  const match = upper.match(/CWE-\d+/);
  if (match) return match[0];
  if (/^\d+$/.test(upper)) return `CWE-${upper}`;
  return upper;
}

function normalizeHumanCwe(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (raw.toLowerCase() === "unmapped") return "unmapped";
  const cwe = normalizeCwe(raw);
  if (/^\d+$/.test(cwe)) return `CWE-${cwe}`;
  return cwe;
}

function parseHumanCwes(value) {
  return String(value || "")
    .split(/[,;]+/)
    .map(normalizeHumanCwe)
    .filter(Boolean);
}

function cweInputValue(annotation) {
  const ids = Array.isArray(annotation.human_cwe_ids)
    ? annotation.human_cwe_ids
    : parseHumanCwes(annotation.human_primary_cwe || "");
  return ids.join(", ");
}

function currentCweToken() {
  const beforeCursor = el.humanPrimaryCwe.value.slice(0, el.humanPrimaryCwe.selectionStart || 0);
  const parts = beforeCursor.split(/[,;]/);
  return parts[parts.length - 1].trim();
}

function cweSuggestions(query) {
  const normalized = normalizeCwe(query);
  const needle = query.toLowerCase();
  const selected = new Set(parseCompletedHumanCwes());
  return state.cweEntries
    .filter((entry) => {
      const cwe = normalizeCwe(entry.cwe);
      if (selected.has(cwe)) return false;
      if (cwe.includes(normalized)) return true;
      return [entry.name, entry.description]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    })
    .slice(0, 8);
}

function parseCompletedHumanCwes() {
  const beforeCursor = el.humanPrimaryCwe.value.slice(0, el.humanPrimaryCwe.selectionStart || 0);
  const parts = beforeCursor.split(/[,;]/);
  return parseHumanCwes(parts.slice(0, -1).join(","));
}

function renderCweSuggestions() {
  const query = currentCweToken();
  if (!query || query.length < 2) {
    hideCweSuggestions();
    return;
  }
  const rows = cweSuggestions(query);
  if (!rows.length) {
    hideCweSuggestions();
    return;
  }
  el.cweSuggestions.innerHTML = rows
    .map(
      (entry) => `
        <button class="cweSuggestion" type="button" data-cwe="${escapeHtml(entry.cwe)}">
          <span class="cweSuggestionId">${escapeHtml(entry.cwe)}</span>
          <span class="cweSuggestionText">
            <strong>${escapeHtml(entry.name)}</strong>
            <span>${escapeHtml(oneLine(entry.description))}</span>
          </span>
        </button>
      `
    )
    .join("");
  el.cweSuggestions.classList.remove("hidden");
}

function hideCweSuggestions() {
  el.cweSuggestions.classList.add("hidden");
  el.cweSuggestions.innerHTML = "";
}

function insertCweSuggestion(cwe) {
  const value = el.humanPrimaryCwe.value;
  const cursor = el.humanPrimaryCwe.selectionStart || value.length;
  const before = value.slice(0, cursor);
  const after = value.slice(cursor);
  const separatorIndex = Math.max(before.lastIndexOf(","), before.lastIndexOf(";"));
  const prefix = separatorIndex >= 0 ? before.slice(0, separatorIndex + 1) : "";
  const needsSpace = prefix && !/\s$/.test(prefix) ? " " : "";
  el.humanPrimaryCwe.value = `${prefix}${needsSpace}${cwe}${after ? `, ${after.trimStart()}` : ", "}`;
  el.humanPrimaryCwe.focus();
  el.humanPrimaryCwe.selectionStart = el.humanPrimaryCwe.selectionEnd = el.humanPrimaryCwe.value.length;
  hideCweSuggestions();
  saveCurrentAnnotation();
}

function cweEntry(value) {
  return state.cweCatalog.get(normalizeCwe(value));
}

function oneLine(value) {
  return text(value).replace(/\s+/g, " ").trim();
}

function cweSection(title, cweIds, meta = "") {
  const ids = Array.isArray(cweIds) ? cweIds.filter(Boolean) : [cweIds].filter(Boolean);
  const rows = ids.map((id) => {
    const entry = cweEntry(id);
    return `
      <div class="cweLookupRow">
        <div class="cweLookupId">${escapeHtml(id)}</div>
        <div>
          <div class="cweName">${escapeHtml(entry?.name || "Description not found")}</div>
          <div class="cweDescription">${escapeHtml(oneLine(entry?.description || ""))}</div>
        </div>
      </div>
    `;
  });
  return `
    <div class="cweItem">
      <div class="cweHead"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></div>
      <div class="cweLookupList">${rows.join("") || "unknown"}</div>
    </div>
  `;
}

function renderTabs() {
  document.querySelectorAll(".tabButton").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === state.activeTab);
  });
  document.querySelectorAll(".tabPanel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === state.activeTab);
  });
}

function saveCurrentAnnotation() {
  const record = currentRecord();
  if (!record) return;
  const agrees = el.humanAgree.value;
  const isAgree = agrees === "true";
  const humanCweIds = isAgree ? [] : parseHumanCwes(el.humanPrimaryCwe.value);
  state.annotations[recordKey(record)] = {
    episode_id: "",
    review_unit_id: record.review_unit_id || "",
    finding_id: record.finding_ids?.[0] || record.finding_id,
    finding_ids: record.finding_ids || [record.finding_id],
    candidate_id: record.candidate_id,
    candidate_ids: record.candidate_ids || [record.candidate_id],
    chat_id: record.chat_id,
    risk_turn_index: record.turn_index,
    file_path: record.file_path || "",
    file_paths: record.file_paths || [],
    turn_indices: record.turn_indices || [record.turn_index],
    cwe_ids_llm: record.cwe_ids || [],
    primary_cwe_llm: record.primary_cwe || "",
    severity_llm: record.severity || "",
    agreement: record.agreement || "",
    human_agrees_with_finding: agrees,
    human_agreement: agrees === "true" ? "agree" : agrees === "false" ? "disagree" : "",
    human_is_valid_risk: isAgree ? "true" : "",
    human_cwe_granularity: "",
    human_primary_cwe: humanCweIds[0] || "",
    human_cwe_ids: humanCweIds,
    human_severity: "",
    human_notes: isAgree ? "" : el.humanNotes.value.trim(),
    updated_at: new Date().toISOString(),
  };
  saveAnnotations();
  renderList();
}

function updateAnnotationSteps() {
  const showDisagreeFields = el.humanAgree.value === "false";
  document.querySelectorAll(".disagreeField").forEach((field) => {
    field.classList.toggle("hidden", !showDisagreeFields);
  });
  if (!showDisagreeFields) hideCweSuggestions();
}

function exportRows() {
  if (currentRecord() && (el.humanAgree.value || el.humanPrimaryCwe.value.trim() || el.humanNotes.value.trim())) {
    saveCurrentAnnotation();
  }
  return state.records
    .map((record) => exportRow(record))
    .filter(Boolean);
}

function exportRow(record) {
  const row = state.annotations[recordKey(record)];
  if (!row) return null;
  const agrees = agreementValue(row);
  const humanCweIds = Array.isArray(row.human_cwe_ids)
    ? row.human_cwe_ids
    : parseHumanCwes(row.human_primary_cwe || "");
  return {
    ...row,
    human_agrees_with_finding: row.human_agrees_with_finding || agrees,
    human_agreement:
      row.human_agreement || (agrees === "true" ? "agree" : agrees === "false" ? "disagree" : ""),
    human_primary_cwe: row.human_primary_cwe || humanCweIds[0] || "",
    human_cwe_ids: humanCweIds,
  };
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportJsonl() {
  const rows = exportRows();
  download(
    "risk_finding_human_annotations.jsonl",
    rows.map((row) => JSON.stringify(row)).join("\n") + "\n",
    "application/x-ndjson"
  );
}

function csvEscape(value) {
  const s = Array.isArray(value) ? value.join(";") : text(value);
  return `"${s.replaceAll('"', '""')}"`;
}

function exportCsv() {
  const rows = exportRows();
  const headers = [
    "review_unit_id",
    "finding_id",
    "finding_ids",
    "candidate_id",
    "candidate_ids",
    "chat_id",
    "risk_turn_index",
    "file_path",
    "file_paths",
    "turn_indices",
    "primary_cwe_llm",
    "cwe_ids_llm",
    "severity_llm",
    "agreement",
    "human_agrees_with_finding",
    "human_agreement",
    "human_is_valid_risk",
    "human_primary_cwe",
    "human_cwe_ids",
    "human_notes",
    "updated_at",
  ];
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((key) => csvEscape(row[key])).join(","));
  }
  download("risk_finding_human_annotations.csv", lines.join("\n") + "\n", "text/csv");
}

function movePage(delta) {
  if (!state.filtered.length) return;
  state.page = Math.max(0, Math.min(pageCount() - 1, state.page + delta));
  state.selectedIndex = Math.min(state.filtered.length - 1, state.page * state.pageSize);
  renderList();
  renderDetail();
  updateProgress();
}

function bindEvents() {
  for (const input of [
    el.humanAgree,
    el.humanPrimaryCwe,
    el.humanNotes,
  ]) {
    input.addEventListener("change", saveCurrentAnnotation);
    input.addEventListener("blur", saveCurrentAnnotation);
  }
  el.humanAgree.addEventListener("change", updateAnnotationSteps);
  el.humanPrimaryCwe.addEventListener("input", renderCweSuggestions);
  el.humanPrimaryCwe.addEventListener("focus", renderCweSuggestions);
  el.humanPrimaryCwe.addEventListener("blur", () => {
    window.setTimeout(hideCweSuggestions, 120);
  });
  el.cweSuggestions.addEventListener("mousedown", (event) => {
    event.preventDefault();
    const button = event.target.closest(".cweSuggestion");
    if (button) insertCweSuggestion(button.dataset.cwe);
  });
  for (const input of [
    el.searchBox,
    el.statusFilter,
    el.severityFilter,
    el.agreementFilter,
    el.pageSize,
  ]) {
    input.addEventListener("input", () => {
      state.selectedIndex = 0;
      state.page = 0;
      applyFilters();
    });
  }
  el.prevPage.addEventListener("click", () => movePage(-1));
  el.nextPage.addEventListener("click", () => movePage(1));
  el.copyCode.addEventListener("click", () => {
    const record = currentRecord();
    if (record) copyText(el.copyCode, candidateText(record));
  });
  el.copyContext.addEventListener("click", () => {
    const record = currentRecord();
    if (record) copyText(el.copyContext, contextText(record));
  });
  document.querySelectorAll(".tabButton").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeTab = button.dataset.tab;
      renderTabs();
    });
  });
  el.exportJsonl.addEventListener("click", exportJsonl);
  el.exportCsv.addEventListener("click", exportCsv);
  el.fileInput.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setDataset(JSON.parse(await file.text()));
  });
}

bindEvents();
loadDefaultDataset();
