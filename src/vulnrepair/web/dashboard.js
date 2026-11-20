"use strict";

const REFRESH_INTERVAL_MS = 10000;
const MAX_DIFF_LINES = 4000;
const MAX_OUTPUT_CHARS = 30000;

const state = {
  runs: [],
  selectedRunId: null,
  selectedCandidateId: null,
  detail: null,
  autoRefresh: true,
  timer: null,
  listController: null,
  detailController: null,
  refreshing: false,
  currentDiff: "",
};

const elements = {};

function byId(id) {
  return document.getElementById(id);
}

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined && text !== null) item.textContent = String(text);
  return item;
}

function setText(target, value, fallback = "-") {
  target.textContent = value === undefined || value === null || value === "" ? fallback : String(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function numeric(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function countOf(value) {
  return Array.isArray(value) ? value.length : Math.max(0, numeric(value));
}

function truncate(value, limit) {
  const text = value === undefined || value === null ? "" : String(value);
  return text.length > limit ? `${text.slice(0, limit)}\n[output truncated in dashboard]` : text;
}

function shortId(value, size = 12) {
  const text = value === undefined || value === null ? "" : String(value);
  return text.length > size ? `${text.slice(0, size)}...` : text || "-";
}

function formatMoney(value) {
  return `$${numeric(value).toFixed(4)}`;
}

function formatDuration(value) {
  const seconds = numeric(value);
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function formatInteger(value) {
  return Math.max(0, Math.round(numeric(value))).toLocaleString();
}

function formatDate(value) {
  if (!value) return "時間未知";
  const normalized = typeof value === "number" && value < 1000000000000 ? value * 1000 : value;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-TW", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

const STATUS_COPY = {
  verified_fix: "已驗證修復",
  rejected: "已拒絕",
  inconclusive: "證據不足",
  infra_error: "基礎設施錯誤",
  pass: "通過",
  passed: "通過",
  fail: "失敗",
  failed: "失敗",
  error: "錯誤",
  skipped: "略過",
  not_run: "未執行",
  clean: "乾淨",
  blocked: "已阻擋",
  vulnerable: "仍有漏洞",
  finding_present: "發現仍存在",
  harness_error: "驗證工具錯誤",
  not_available: "無法取得",
  timeout: "逾時",
};

function normalizeStatus(value) {
  return String(value || "inconclusive").toLowerCase();
}

function statusLabel(value) {
  const key = normalizeStatus(value);
  return STATUS_COPY[key] || key.replaceAll("_", " ");
}

function statusClass(value) {
  const key = normalizeStatus(value);
  if (["verified_fix", "pass", "passed", "clean", "blocked"].includes(key)) return "status-verified";
  if (["rejected", "fail", "failed", "error", "infra_error", "vulnerable", "finding_present", "harness_error", "timeout"].includes(key)) return "status-rejected";
  if (["inconclusive", "skipped", "not_run", "not_available"].includes(key)) return "status-inconclusive";
  return "";
}

function badge(value) {
  return node("span", `status-badge ${statusClass(value)}`, statusLabel(value));
}

function announce(message) {
  setText(elements.announcer, message, "");
}

function setConnection(mode, label) {
  elements.connectionStatus.classList.remove("is-online", "is-offline", "is-warning");
  if (mode) elements.connectionStatus.classList.add(mode);
  setText(elements.connectionLabel, label);
}

function setRailState(name, message = "") {
  [elements.railLoading, elements.railEmpty, elements.railError, elements.railNoResults].forEach((item) => {
    item.hidden = true;
  });
  elements.runList.hidden = name === "loading" || name === "empty" || name === "error";
  if (name === "loading") elements.railLoading.hidden = false;
  if (name === "empty") elements.railEmpty.hidden = false;
  if (name === "error") {
    elements.railError.hidden = false;
    setText(elements.railErrorMessage, message, "API 暫時無法使用。");
  }
  if (name === "no-results") elements.railNoResults.hidden = false;
}

async function requestJson(url, controller) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal: controller.signal,
  });
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(`伺服器回傳無效 JSON (${response.status})`);
  }
  if (!response.ok) {
    const detail = asObject(payload).error || asObject(payload).message || `HTTP ${response.status}`;
    throw new Error(String(detail));
  }
  return payload;
}

function getSummary(runId = state.selectedRunId) {
  return state.runs.find((run) => String(run.run_id) === String(runId)) || {};
}

function inferRunStatus(run, summary = {}) {
  if (summary.status) return normalizeStatus(summary.status);
  if (run.chosen) return "verified_fix";
  const verdicts = asArray(run.validations).map((validation) => normalizeStatus(validation.overall));
  if (verdicts.includes("infra_error")) return "infra_error";
  if (verdicts.length && verdicts.every((verdict) => verdict === "rejected")) return "rejected";
  return "inconclusive";
}

function renderRunList() {
  const query = elements.runSearch.value.trim().toLowerCase();
  const filter = elements.verdictFilter.value;
  const filtered = state.runs.filter((run) => {
    const haystack = `${run.task_id || ""} ${run.run_id || ""}`.toLowerCase();
    return (!query || haystack.includes(query)) && (filter === "all" || normalizeStatus(run.status) === filter);
  });

  elements.runList.replaceChildren();
  setText(elements.runCount, filtered.length);
  if (!filtered.length && state.runs.length) {
    setRailState("no-results");
    return;
  }
  setRailState("ready");

  const fragment = document.createDocumentFragment();
  filtered.forEach((run) => {
    const button = node("button", "run-item");
    button.type = "button";
    const runId = String(run.run_id || "");
    const selected = runId === String(state.selectedRunId || "");
    button.classList.toggle("is-selected", selected);
    if (selected) button.setAttribute("aria-current", "true");
    button.setAttribute("aria-label", `${run.task_id || "未命名任務"}, ${statusLabel(run.status)}`);

    const top = node("span", "run-item-top");
    top.append(node("span", "run-task", run.task_id || "未命名任務"), badge(run.status));
    const id = node("code", "run-id", runId || "run id unavailable");
    const meta = node("span", "run-item-meta");
    const counts = `${countOf(run.candidates)} candidates / ${countOf(run.validations)} validations`;
    meta.append(node("span", "", counts), node("span", "", formatDate(run.updated_at)));
    button.append(top, id, meta);
    button.addEventListener("click", () => selectRun(runId));
    fragment.append(button);
  });
  elements.runList.append(fragment);
}

async function refreshRuns(options = {}) {
  if (state.refreshing && !options.force) return;
  state.refreshing = true;
  elements.refreshButton.disabled = true;
  elements.refreshButton.textContent = "刷新中";
  elements.runList.setAttribute("aria-busy", "true");
  if (!state.runs.length) setRailState("loading");
  if (state.listController) state.listController.abort();
  const controller = new AbortController();
  state.listController = controller;

  try {
    const payload = await requestJson("/api/runs", controller);
    const runs = asArray(asObject(payload).runs).slice();
    runs.sort((a, b) => {
      const left = new Date(a.updated_at || 0).getTime();
      const right = new Date(b.updated_at || 0).getTime();
      return right - left;
    });
    state.runs = runs;
    const invalidRuns = Math.max(0, numeric(asObject(payload).invalid_runs));
    const truncated = asObject(payload).truncated === true;
    if (invalidRuns || truncated) {
      const notices = [];
      if (invalidRuns) notices.push(`${invalidRuns} 筆無效資料`);
      if (truncated) notices.push("清單已截斷");
      setConnection("is-warning", `API 已連線 / ${notices.join(" / ")}`);
    } else {
      setConnection("is-online", "API 已連線");
    }
    setText(elements.lastSynced, new Intl.DateTimeFormat("zh-TW", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date()));
    if (!runs.length) {
      state.selectedRunId = null;
      state.detail = null;
      elements.runList.replaceChildren();
      setText(elements.runCount, 0);
      setRailState("empty");
      showPlaceholder();
      return;
    }
    if (!runs.some((run) => String(run.run_id) === String(state.selectedRunId))) {
      state.selectedRunId = String(runs[0].run_id || "");
    }
    renderRunList();
    await loadDetail(state.selectedRunId, { quiet: Boolean(options.quiet) });
  } catch (error) {
    if (error.name === "AbortError") return;
    setConnection("is-offline", "API 無法連線");
    if (!state.runs.length) setRailState("error", error.message);
    announce(`刷新失敗: ${error.message}`);
  } finally {
    if (state.listController === controller) state.listController = null;
    state.refreshing = false;
    elements.runList.removeAttribute("aria-busy");
    elements.refreshButton.disabled = false;
    elements.refreshButton.textContent = "立即刷新";
  }
}

async function selectRun(runId) {
  if (!runId) return;
  state.selectedRunId = runId;
  state.selectedCandidateId = null;
  renderRunList();
  await loadDetail(runId);
}

function showPlaceholder() {
  elements.dashboard.hidden = true;
  elements.detailError.hidden = true;
  elements.detailPlaceholder.hidden = false;
}

function showDetailError(message) {
  elements.dashboard.hidden = true;
  elements.detailPlaceholder.hidden = true;
  elements.detailError.hidden = false;
  setText(elements.detailErrorMessage, message, "API 暫時無法使用。");
}

async function loadDetail(runId, options = {}) {
  if (!runId) return;
  if (!options.quiet) {
    elements.detailError.hidden = true;
    elements.detailPlaceholder.hidden = false;
    elements.detailPlaceholder.setAttribute("aria-busy", "true");
  }
  if (state.detailController) state.detailController.abort();
  const controller = new AbortController();
  state.detailController = controller;
  try {
    const payload = await requestJson(`/api/runs/${encodeURIComponent(runId)}`, controller);
    if (String(state.selectedRunId) !== String(runId)) return;
    const run = asObject(asObject(payload).run);
    if (!run.run_id) throw new Error("回應缺少 run_id");
    state.detail = run;
    renderDetail(run);
    announce(`已載入任務 ${run.task_id || run.run_id}`);
  } catch (error) {
    if (error.name === "AbortError") return;
    if (String(state.selectedRunId) === String(runId)) {
      if (options.quiet && state.detail) {
        setConnection("is-warning", "API 已連線 / 細節刷新失敗");
        announce(`細節刷新失敗，保留目前畫面: ${error.message}`);
      } else {
        showDetailError(error.message);
      }
    }
  } finally {
    elements.detailPlaceholder.removeAttribute("aria-busy");
    if (state.detailController === controller) state.detailController = null;
  }
}

function renderDetail(run) {
  const summary = getSummary(run.run_id);
  const candidates = asArray(run.all_candidates);
  const validations = asArray(run.validations);
  const chosen = asObject(run.chosen);
  const chosenId = chosen.candidate_id || asObject(summary.chosen).candidate_id;
  const stillExists = candidates.some((candidate) => String(candidate.candidate_id) === String(state.selectedCandidateId));
  if (!stillExists) state.selectedCandidateId = chosenId || (candidates[0] && candidates[0].candidate_id) || null;

  elements.detailPlaceholder.hidden = true;
  elements.detailError.hidden = true;
  elements.dashboard.hidden = false;

  setText(elements.selectedTaskTitle, run.task_id, "未命名任務");
  setText(elements.selectedRunId, run.run_id);
  const runStatus = inferRunStatus(run, summary);
  elements.selectedStatus.className = `status-badge ${statusClass(runStatus)}`;
  setText(elements.selectedStatus, statusLabel(runStatus));

  renderKpis(run, candidates, validations);
  renderMeta(run);
  renderBaseline(run);
  renderMatrix(candidates, validations, chosenId);
  renderCandidateInspection(candidates, validations);
  renderTrace(asArray(run.trace));
}

function renderKpis(run, candidates, validations) {
  const cost = asObject(run.cost);
  const budget = asObject(run.budget);
  const passing = validations.filter((item) => normalizeStatus(item.overall) === "verified_fix").length;
  setText(elements.kpiCandidates, candidates.length);
  setText(elements.kpiCandidatesNote, `${formatInteger(cost.candidates_seen || candidates.length)} seen`);
  setText(elements.kpiValidations, validations.length);
  setText(elements.kpiValidationsNote, `${passing} verified`);
  setText(elements.kpiModelCalls, formatInteger(cost.model_calls));
  setText(elements.kpiTokenNote, `${formatInteger(numeric(cost.prompt_tokens) + numeric(cost.completion_tokens))} tokens`);
  setText(elements.kpiElapsed, formatDuration(cost.elapsed_seconds));
  setText(elements.kpiRoundsNote, `${formatInteger(cost.rounds)} rounds`);
  setText(elements.kpiCost, formatMoney(cost.cost_usd));
  setText(elements.kpiCostNote, budget.max_cost_usd !== undefined ? `${formatMoney(budget.max_cost_usd)} budget` : "預算未設定");
}

function renderMeta(run) {
  const snapshot = asObject(asObject(run.baseline).snapshot);
  setText(elements.metaTaskId, run.task_id);
  setText(elements.metaRunId, run.run_id);
  setText(elements.metaFingerprint, run.input_fingerprint);
  setText(elements.metaCommit, snapshot.commit, "尚無快照");
  setText(elements.metaTree, snapshot.tree_digest, "尚無快照");
  setText(elements.metaAttempts, formatInteger(run.attempts));
}

function addDefinition(list, term, value) {
  const row = node("div");
  row.append(node("dt", "", term), node("dd", "", value));
  list.append(row);
}

function renderBaseline(run) {
  const baseline = asObject(run.baseline);
  const usable = baseline.usable === true;
  elements.baselineBadge.className = `status-badge ${usable ? "status-verified" : "status-inconclusive"}`;
  setText(elements.baselineBadge, usable ? "基準線可用" : "基準線不可用");
  setText(elements.baselineSummary, baseline.summary, usable ? "基準線已建立。" : "沒有可用的基準線資料。");
  elements.budgetList.replaceChildren();
  const budget = asObject(run.budget);
  const cost = asObject(run.cost);
  if (!Object.keys(budget).length) {
    addDefinition(elements.budgetList, "Budget", "未設定");
    return;
  }
  addDefinition(elements.budgetList, "Rounds", `${formatInteger(cost.rounds)} / ${formatInteger(budget.max_rounds)}`);
  addDefinition(elements.budgetList, "Candidates", `${formatInteger(cost.candidates_seen)} / ${formatInteger(budget.max_candidates)}`);
  addDefinition(elements.budgetList, "Validations", `${formatInteger(cost.candidates_validated)} / ${formatInteger(budget.max_validations)}`);
  addDefinition(elements.budgetList, "Model calls", `${formatInteger(cost.model_calls)} / ${formatInteger(budget.max_model_calls)}`);
  addDefinition(elements.budgetList, "Elapsed", `${formatDuration(cost.elapsed_seconds)} / ${formatDuration(budget.max_elapsed_seconds)}`);
}

function validationFor(validations, candidateId) {
  return validations.find((item) => String(item.candidate_id) === String(candidateId)) || null;
}

function renderMatrix(candidates, validations, chosenId) {
  elements.validationMatrix.replaceChildren();
  setText(elements.matrixSummary, `${candidates.length} CANDIDATES`);
  if (!candidates.length) {
    elements.validationMatrix.append(node("div", "matrix-empty", "此任務沒有產生候選修補。"));
    return;
  }

  const stageNames = [];
  validations.forEach((validation) => {
    asArray(validation.stages).forEach((stage) => {
      if (stage.stage && !stageNames.includes(String(stage.stage))) stageNames.push(String(stage.stage));
    });
  });
  const table = node("table", "validation-table");
  table.append(node("caption", "sr-only", "候選修補的驗證階段與結果"));
  const head = node("thead");
  const headRow = node("tr");
  ["候選", "生成器", "總結", ...stageNames].forEach((label) => {
    const header = node("th", "", label);
    header.scope = "col";
    headRow.append(header);
  });
  head.append(headRow);
  table.append(head);
  const body = node("tbody");

  candidates.forEach((candidate) => {
    const candidateId = String(candidate.candidate_id || "");
    const validation = validationFor(validations, candidateId);
    const row = node("tr", candidateId === String(state.selectedCandidateId) ? "is-selected" : "");
    row.setAttribute("aria-selected", candidateId === String(state.selectedCandidateId) ? "true" : "false");
    const first = node("td");
    const select = node("button", "candidate-select", shortId(candidateId, 18));
    select.type = "button";
    select.title = candidateId;
    select.setAttribute("aria-label", `檢視候選 ${candidateId}`);
    select.addEventListener("click", () => {
      state.selectedCandidateId = candidateId;
      renderMatrix(candidates, validations, chosenId);
      renderCandidateInspection(candidates, validations);
    });
    first.append(select);
    if (candidateId === String(chosenId || "")) first.append(node("div", "run-id", "SELECTED"));
    row.append(first, node("td", "candidate-model", candidate.generated_by || "unknown"));
    const overallCell = node("td");
    overallCell.append(badge(validation ? validation.overall : "not_run"));
    row.append(overallCell);
    stageNames.forEach((stageName) => {
      const stage = validation && asArray(validation.stages).find((item) => String(item.stage) === stageName);
      const cell = node("td");
      const stack = node("div", "stage-cell");
      stack.append(badge(stage ? stage.verdict : "not_run"));
      stack.append(node("small", "", stage ? stage.reason_code || "no reason code" : "not scheduled"));
      cell.append(stack);
      row.append(cell);
    });
    body.append(row);
  });
  table.append(body);
  elements.validationMatrix.append(table);
}

function selectedCandidate(candidates) {
  return candidates.find((candidate) => String(candidate.candidate_id) === String(state.selectedCandidateId)) || null;
}

function renderCandidateInspection(candidates, validations) {
  const candidate = selectedCandidate(candidates);
  const validation = candidate ? validationFor(validations, candidate.candidate_id) : null;
  const baselineStages = asArray(asObject(asObject(state.detail).baseline).stages);
  renderEvidence(candidate, validation, baselineStages);
  renderDiff(candidate);
}

function renderEvidence(candidate, validation, baselineStages) {
  elements.evidenceList.replaceChildren();
  const stages = validation ? asArray(validation.stages) : [];
  setText(elements.evidenceCandidate, candidate ? `Candidate ${shortId(candidate.candidate_id, 18)}` : "尚未選擇候選");
  setText(elements.evidenceCount, `${baselineStages.length + stages.length} STAGES`);
  appendEvidenceGroup("BASELINE EVIDENCE", baselineStages, true);
  if (!candidate) {
    elements.evidenceList.append(node("div", "content-empty", "選擇一筆候選修補以檢視候選證據。"));
    return;
  }
  appendEvidenceGroup("CANDIDATE EVIDENCE", stages, false);
  if (!validation || !stages.length) {
    elements.evidenceList.append(node("div", "content-empty", "此候選尚未產生驗證證據。"));
  }
}

function appendEvidenceGroup(label, stages, baseline) {
  const heading = node("div", "evidence-group-heading");
  heading.append(node("strong", "", label), node("span", "", `${stages.length} STAGES`));
  elements.evidenceList.append(heading);
  if (!stages.length) {
    elements.evidenceList.append(node("p", "evidence-group-empty", baseline ? "沒有基準線階段證據。" : "沒有候選階段證據。"));
    return;
  }
  stages.forEach((stage, index) => {
    const details = node("details", "stage-card");
    const verdict = normalizeStatus(stage.verdict);
    details.open = index === 0 || !["pass", "passed"].includes(verdict);
    const summary = node("summary");
    const title = node("span", "stage-title");
    title.append(node("strong", "", stage.stage || "未命名階段"), badge(stage.verdict));
    summary.append(title);
    details.append(summary);
    const body = node("div", "stage-body");
    if (stage.message) body.append(node("p", "stage-message", stage.message));
    const facts = node("p", "stage-facts");
    facts.append(node("span", "", `reason=${stage.reason_code || "none"}`));
    if (stage.security_outcome) facts.append(node("span", "", `security=${stage.security_outcome}`));
    const command = asObject(stage.command_result);
    if (Object.keys(command).length) {
      facts.append(node("span", "", `returncode=${command.returncode === null || command.returncode === undefined ? "none" : command.returncode}`));
      facts.append(node("span", "", `duration=${formatDuration(command.duration_seconds)}`));
      if (command.truncated) facts.append(node("span", "", "output=truncated"));
    }
    body.append(facts);
    const commandText = formatCommand(command.command);
    if (commandText) body.append(node("code", "command-line", `$ ${commandText}`));
    addOutput(body, "stdout", command.stdout);
    addOutput(body, "stderr", command.stderr);
    const artifacts = asArray(stage.artifacts);
    if (artifacts.length) {
      const list = node("ul", "artifact-list");
      artifacts.forEach((artifact) => {
        const item = node("li");
        item.append(node("code", "", artifact));
        list.append(item);
      });
      body.append(list);
    }
    details.append(body);
    elements.evidenceList.append(details);
  });
}

function formatCommand(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(String).join(" ");
  const command = asObject(value);
  if (Array.isArray(command.argv)) return command.argv.map(String).join(" ");
  if (command.name) return String(command.name);
  if (command.executable) return String(command.executable);
  return "";
}

function addOutput(parent, label, value) {
  if (value === undefined || value === null || String(value) === "") return;
  const details = node("details", "stage-output");
  details.append(node("summary", "", label));
  details.append(node("pre", "", truncate(value, MAX_OUTPUT_CHARS)));
  parent.append(details);
}

function attributePairs(value) {
  if (Array.isArray(value)) {
    return value.flatMap((item) => Array.isArray(item) && item.length >= 2 ? [[item[0], item[1]]] : []);
  }
  return Object.entries(asObject(value));
}

function renderTrace(events) {
  elements.traceList.replaceChildren();
  const sorted = events.slice().sort((a, b) => numeric(a.sequence) - numeric(b.sequence));
  setText(elements.traceCount, `${sorted.length} EVENTS`);
  if (!sorted.length) {
    const item = node("li", "content-empty", "此任務沒有執行軌跡。" );
    elements.traceList.append(item);
    return;
  }
  sorted.forEach((event) => {
    const item = node("li", "trace-event");
    item.append(node("span", "trace-sequence", String(Math.max(0, numeric(event.sequence))).padStart(4, "0")));
    const copy = node("div", "trace-copy");
    copy.append(node("strong", "", event.event || "unknown_event"));
    if (event.message) copy.append(node("p", "", event.message));
    const meta = node("div", "trace-meta");
    if (event.candidate_id) meta.append(node("span", "", `candidate=${shortId(event.candidate_id, 16)}`));
    attributePairs(event.attributes).forEach(([key, value]) => meta.append(node("span", "", `${key}=${value}`)));
    if (meta.childNodes.length) copy.append(meta);
    item.append(copy);
    elements.traceList.append(item);
  });
}

function renderDiff(candidate) {
  elements.diffViewer.replaceChildren();
  elements.diffContext.replaceChildren();
  elements.copyDiff.disabled = true;
  state.currentDiff = "";
  setText(elements.diffCandidate, candidate ? `Candidate ${shortId(candidate.candidate_id, 18)}` : "尚未選擇候選");
  if (!candidate || !candidate.diff) {
    elements.diffViewer.append(node("div", "content-empty", "此候選沒有可顯示的 diff。"));
    setText(elements.diffStats, "+0 / -0");
    return;
  }
  const diff = String(candidate.diff);
  state.currentDiff = diff;
  const allLines = diff.split("\n");
  const visibleLines = allLines.slice(0, MAX_DIFF_LINES);
  let additions = 0;
  let deletions = 0;
  visibleLines.forEach((line) => {
    if (line.startsWith("+") && !line.startsWith("+++")) additions += 1;
    if (line.startsWith("-") && !line.startsWith("---")) deletions += 1;
  });
  setText(elements.diffStats, `+${additions} / -${deletions}`);
  elements.diffContext.append(node("span", "", "Generator "), node("code", "", candidate.generated_by || "unknown"));
  if (candidate.rationale) elements.diffContext.append(node("span", "", candidate.rationale));

  const fragment = document.createDocumentFragment();
  visibleLines.forEach((line, index) => {
    let className = "diff-line";
    if (line.startsWith("@@")) className += " diff-hunk";
    else if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ")) className += " diff-meta";
    else if (line.startsWith("+")) className += " diff-add";
    else if (line.startsWith("-")) className += " diff-delete";
    const row = node("div", className);
    row.append(node("span", "diff-line-number", index + 1), node("span", "diff-line-code", line || " "));
    fragment.append(row);
  });
  elements.diffViewer.append(fragment);
  if (allLines.length > MAX_DIFF_LINES) {
    elements.diffViewer.append(node("div", "diff-truncated", `顯示前 ${MAX_DIFF_LINES} 行，共 ${allLines.length} 行。`));
  }
  elements.copyDiff.disabled = false;
}

async function copyDiff() {
  const value = state.currentDiff;
  if (!value) return;
  try {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      throw new Error("clipboard unavailable");
    }
    await Promise.race([
      navigator.clipboard.writeText(value),
      new Promise((_, reject) => window.setTimeout(() => reject(new Error("clipboard timeout")), 1500)),
    ]);
    elements.copyDiff.textContent = "已複製";
    announce("diff 已複製到剪貼簿");
    window.setTimeout(() => { elements.copyDiff.textContent = "複製 diff"; }, 1600);
  } catch (error) {
    elements.copyDiff.textContent = "複製失敗";
    announce("瀏覽器不允許存取剪貼簿");
    window.setTimeout(() => { elements.copyDiff.textContent = "複製 diff"; }, 1600);
  }
}

function scheduleRefresh() {
  if (state.timer) window.clearInterval(state.timer);
  state.timer = null;
  if (!state.autoRefresh) return;
  state.timer = window.setInterval(() => {
    if (!document.hidden) refreshRuns({ quiet: true });
  }, REFRESH_INTERVAL_MS);
}

function cacheElements() {
  const ids = [
    "announcer", "connection-status", "connection-label", "auto-refresh", "refresh-button", "run-count",
    "run-search", "verdict-filter", "rail-loading", "rail-empty", "rail-error", "rail-error-message",
    "rail-no-results", "rail-retry", "run-list", "last-synced", "detail-placeholder", "detail-error",
    "detail-error-message", "detail-retry", "dashboard", "selected-task-title", "selected-run-id", "selected-status",
    "kpi-candidates", "kpi-candidates-note", "kpi-validations", "kpi-validations-note", "kpi-model-calls",
    "kpi-token-note", "kpi-elapsed", "kpi-rounds-note", "kpi-cost", "kpi-cost-note", "meta-task-id",
    "meta-run-id", "meta-fingerprint", "meta-commit", "meta-tree", "meta-attempts", "baseline-badge",
    "baseline-summary", "budget-list", "matrix-summary", "validation-matrix", "evidence-candidate",
    "evidence-count", "evidence-list", "trace-count", "trace-list", "diff-candidate", "diff-stats",
    "copy-diff", "diff-context", "diff-viewer",
  ];
  ids.forEach((id) => {
    const key = id.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    elements[key] = byId(id);
  });
}

function bindEvents() {
  elements.refreshButton.addEventListener("click", () => refreshRuns({ force: true }));
  elements.railRetry.addEventListener("click", () => refreshRuns({ force: true }));
  elements.detailRetry.addEventListener("click", () => loadDetail(state.selectedRunId));
  elements.runSearch.addEventListener("input", renderRunList);
  elements.verdictFilter.addEventListener("change", renderRunList);
  elements.autoRefresh.addEventListener("change", () => {
    state.autoRefresh = elements.autoRefresh.checked;
    scheduleRefresh();
    announce(state.autoRefresh ? "自動刷新已啟用" : "自動刷新已停用");
  });
  elements.copyDiff.addEventListener("click", copyDiff);
}

function start() {
  cacheElements();
  bindEvents();
  scheduleRefresh();
  refreshRuns({ force: true });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
