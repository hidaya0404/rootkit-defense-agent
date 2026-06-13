const state = {
  alerts: [],
  quarantine: [],
  sandbox: [],
  reports: [],
  remediations: [],
  cases: [],
  activeView: "dashboard",
  quarantineFilter: "ALL",
  statusFilter: "ALL",
  riskFilter: "ALL",
  memberFilter: "ALL",
  typeFilter: "ALL",
  query: "",
  connectionErrors: {},
  refreshInFlight: false
};

const AUTO_REFRESH_MS = 5000;

const fallbackBootChecks = [
  {
    id: "ui",
    label: "dashboard api",
    status: "FAIL",
    line: "/api/boot/checks unavailable; real integration checks could not run"
  }
];

let bootDone = false;
let bootReady = false;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function valueOrDash(value) {
  return value === null || value === undefined || value === "" ? "-" : value;
}

function shortHash(hash, left = 10, right = 6) {
  if (!hash) return "-";
  return hash.length > left + right + 3 ? `${hash.slice(0, left)}...${hash.slice(-right)}` : hash;
}

function normalizeList(payload, key) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload[key])) return payload[key];
  if (payload && Array.isArray(payload.results)) return payload.results;
  return [];
}

async function fetchJson(url, key) {
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const list = normalizeList(await response.json(), key);
    state.connectionErrors[url] = null;
    return list;
  } catch (error) {
    state.connectionErrors[url] = error?.message || "fetch failed";
    return [];
  }
}

function severityClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("critical") || normalized.includes("critique")) return "critical";
  if (normalized.includes("high") || normalized.includes("eleve")) return "high";
  if (normalized.includes("medium") || normalized.includes("moyen")) return "medium";
  if (normalized.includes("low") || normalized.includes("faible")) return "low";
  if (normalized.includes("blocked") || normalized.includes("failed") || normalized.includes("timeout")) return "critical";
  if (normalized.includes("waiting") || normalized.includes("pending") || normalized.includes("progress")) return "medium";
  if (normalized.includes("ready") || normalized.includes("complete") || normalized.includes("ok")) return "ready";
  return "info";
}

function statusDisplay(status) {
  const raw = String(status || "UNKNOWN").toUpperCase();
  if (raw.includes("SHA256") || raw.includes("INTEGRITY")) {
    return { label: "SHA256_INVALID", className: "invalid", message: "L'artefact telecharge ne correspond pas au hash annonce. Analyse bloquee pour raison d'integrite." };
  }
  if (raw.includes("DOWNLOAD")) {
    return { label: "DOWNLOAD_FAILED", className: "critical", message: "Le lien de telechargement fourni par M4 est invalide ou inaccessible." };
  }
  if (raw.includes("WAITING_M4_RESULT")) {
    return { label: "WAITING_M3_ANALYSIS", className: "waiting", message: "Artefact pret, en attente d'un resultat M3 visible dans M4 avec le meme identifiant ou le meme hash." };
  }
  if (raw.includes("RUNNING") || raw.includes("IN_PROGRESS")) {
    return { label: "SANDBOX_RUNNING", className: "info", message: "Analyse sandbox en cours." };
  }
  if (raw.includes("COMPLETED") || raw.includes("DONE") || raw.includes("RESULT_RECEIVED")) {
    return { label: "SANDBOX_COMPLETED", className: "ready", message: "Analyse terminee et resultat disponible." };
  }
  if (raw.includes("FAILED") || raw.includes("ERROR") || raw.includes("TIMEOUT") || raw.includes("REJECTED")) {
    return { label: "SANDBOX_FAILED", className: "critical", message: "Analyse echouee ou bloquee. Verifie les details techniques." };
  }
  if (raw.includes("READY")) {
    return { label: "READY_FOR_ANALYSIS", className: "medium", message: "Artefact pret pour etre pris par le worker M3." };
  }
  if (raw.includes("SENT")) {
    return { label: "RESULT_SENT_TO_M4", className: "ready", message: "Resultat envoye a M4." };
  }
  return { label: raw, className: severityClass(raw), message: raw };
}

function statusBadge(status) {
  const display = statusDisplay(status);
  return `<span class="badge ${display.className}" title="${escapeHtml(display.message)}">${escapeHtml(display.label)}</span>`;
}

function recordText(record) {
  return JSON.stringify(record || {}).toLowerCase();
}

function recordStatus(record) {
  return String(
    record?.status
      || record?.execution_status
      || record?.sandbox_status
      || record?.risk_level
      || record?.severity
      || ""
  ).toUpperCase();
}

function recordRisk(record) {
  return String(record?.risk_level || record?.severity || record?.ai_recommendation?.risk_level || "").toUpperCase();
}

function recordMember(record) {
  const text = recordText(record);
  if (text.includes("sandbox") || text.includes("m3") || text.includes("vmware")) return "M3";
  if (text.includes("quarantine") || text.includes("m2") || text.includes("evidence")) return "M2";
  if (text.includes("remediation") || text.includes("report") || text.includes("m4") || text.includes("yara")) return "M4";
  if (text.includes("agent") || text.includes("monitor") || text.includes("m1")) return "M1";
  return "ALL";
}

function recordType(record) {
  const name = String(record?.filename || record?.artifact_name || record?.original_path || record?.quarantine_path || "").toLowerCase();
  if (name.endsWith(".sh")) return ".sh";
  if (name.endsWith(".ko")) return ".ko";
  if (name.endsWith(".service")) return ".service";
  if (name.endsWith(".json") || name.includes("json")) return "json";
  return "ALL";
}

function advancedFiltersMatch(record) {
  const status = recordStatus(record);
  const risk = recordRisk(record);
  const member = recordMember(record);
  const type = recordType(record);
  const statusOk = state.statusFilter === "ALL"
    || status.includes(state.statusFilter)
    || (state.statusFilter === "READY" && status.includes("READY"))
    || (state.statusFilter === "WAITING" && (status.includes("WAIT") || status.includes("PENDING") || status.includes("PROGRESS")))
    || (state.statusFilter === "COMPLETED" && (status.includes("DONE") || status.includes("COMPLETED") || status.includes("RESULT_RECEIVED")))
    || (state.statusFilter === "FAILED" && (status.includes("FAIL") || status.includes("INVALID") || status.includes("REJECT")));
  const riskOk = state.riskFilter === "ALL" || risk.includes(state.riskFilter);
  const memberOk = state.memberFilter === "ALL" || member === state.memberFilter || recordText(record).includes(state.memberFilter.toLowerCase());
  const typeOk = state.typeFilter === "ALL" || type === state.typeFilter || recordText(record).includes(state.typeFilter.toLowerCase());
  return statusOk && riskOk && memberOk && typeOk;
}

function queryMatches(record) {
  return (!state.query || recordText(record).includes(state.query)) && advancedFiltersMatch(record);
}

function artifactName(record) {
  return record.filename || record.artifact_name || record.original_filename || "artifact.bin";
}

function allIncidents() {
  const alerts = state.alerts.map((alert) => ({
    timestamp: alert.timestamp,
    alert_id: alert.alert_id,
    source: alert.source_module || "agent",
    event: alert.type || "ALERT",
    severity: alert.severity || "MEDIUM",
    action: alert.status || "NEW",
    raw: alert
  }));

  const quarantine = state.quarantine.map((record) => ({
    timestamp: record.created_at,
    alert_id: record.alert_id,
    source: "quarantine",
    event: record.rootkit_category || artifactName(record),
    severity: record.risk_level || "HIGH",
    action: record.status || "READY_FOR_ANALYSIS",
    raw: record
  }));

  const sandbox = state.sandbox.map((result) => ({
    timestamp: result.analysis_finished_at || result.finished_at || result.timestamp,
    alert_id: result.alert_id,
    source: "sandbox",
    event: result.analysis_id || result.artifact_id || "analysis",
    severity: result.execution_status === "FAILED" ? "HIGH" : "LOW",
    action: result.execution_status || result.sandbox_status || "COMPLETED",
    raw: result
  }));

  const remediations = state.remediations.map((plan) => ({
    timestamp: plan.generated_at || plan.created_at,
    alert_id: plan.alert_id,
    source: "remediation",
    event: selectedPlaybook(plan) || "AI remediation",
    severity: plan.risk_level || aiRecommendation(plan).risk_level || "MEDIUM",
    action: remediationDecision(plan) || "PENDING",
    raw: plan
  }));

  return [...alerts, ...quarantine, ...sandbox, ...remediations]
    .filter((item) => queryMatches(item.raw))
    .sort((a, b) => String(b.timestamp || "").localeCompare(String(a.timestamp || "")));
}

function matchingQuarantine() {
  return state.quarantine.filter((record) => {
    const filterOk = state.quarantineFilter === "ALL" || record.status === state.quarantineFilter;
    return filterOk && queryMatches(record);
  });
}

function matchingRemediations() {
  return state.remediations.filter(queryMatches);
}

function matchingCases() {
  return state.cases.filter(queryMatches);
}

function identityTokens(record) {
  const tokens = new Set();
  const add = (value) => {
    if (value !== undefined && value !== null && value !== "") tokens.add(String(value));
  };
  const addHash = (kind, value) => {
    if (value !== undefined && value !== null && value !== "") tokens.add(`${kind}:${String(value).toLowerCase()}`);
  };

  add(record?.artifact_id);
  add(record?.alert_id);
  add(record?.m4_artifact_id);
  add(record?.details?.artifact_id);
  add(record?.details?.m2_artifact_id);
  add(record?.details?.alert_id);

  addHash("sha256", record?.sha256);
  addHash("sha256", record?.artifact_sha256);
  addHash("sha256", record?.downloaded_sha256);
  addHash("sha256", record?.details?.sha256);
  addHash("sha256", record?.hashes?.sha256);
  addHash("md5", record?.md5 || record?.hashes?.md5);
  addHash("sha1", record?.sha1 || record?.hashes?.sha1);
  return tokens;
}

function sameArtifact(left, right) {
  const leftTokens = identityTokens(left);
  const rightTokens = identityTokens(right);
  return [...leftTokens].some((value) => rightTokens.has(value));
}

function linkReason(result, record) {
  if (result?.artifact_id && record?.artifact_id && String(result.artifact_id) === String(record.artifact_id)) return "artifact_id";
  if (result?.alert_id && record?.alert_id && String(result.alert_id) === String(record.alert_id)) return "alert_id";
  const resultHashes = [...identityTokens(result)].filter((token) => token.startsWith("sha"));
  const recordHashes = identityTokens(record);
  if (resultHashes.some((token) => recordHashes.has(token))) return "hash";
  return "correlation";
}

function sandboxDisplayItems() {
  const results = state.sandbox.filter(queryMatches);
  const usedResults = new Set();
  const fromQuarantine = state.quarantine
    .filter((record) => queryMatches(record))
    .filter((record) => record.ready_for_sandbox === true)
    .map((record) => {
      const result = results.find((item, index) => !usedResults.has(index) && sameArtifact(item, record));
      if (result) {
        const index = results.indexOf(result);
        usedResults.add(index);
        return {
          ...result,
          artifact_id: record.artifact_id || result.artifact_id,
          alert_id: record.alert_id || result.alert_id,
          artifact_name: artifactName(record) || result.artifact_name,
          local_artifact_id: record.artifact_id,
          m4_artifact_id: result.artifact_id,
          local_alert_id: record.alert_id,
          m4_alert_id: result.alert_id,
          artifact_sha256: record.sha256 || result.artifact_sha256 || result.sha256,
          quarantine_path: record.quarantine_path || record.artifact_path || result.quarantine_path,
          _linked_by: linkReason(result, record)
        };
      }
      return {
        artifact_id: record.artifact_id,
        alert_id: record.alert_id,
        artifact_name: artifactName(record),
        execution_status: "WAITING_M4_RESULT",
        sandbox_status: "WAITING_M4_RESULT",
        behavior_summary: "Artefact pret pour M3, mais M4 ne montre aucun resultat sandbox correspondant. Verifie que cet artifact_id est expose dans /api/quarantine/ready ou que le hash envoye par M3 est le meme.",
        quarantine_path: record.quarantine_path || record.artifact_path,
        artifact_sha256: record.sha256,
        _placeholder: true
      };
    });
  const unmatchedResults = results.filter((_, index) => !usedResults.has(index));
  return [...fromQuarantine, ...unmatchedResults];
}

function listCount(value) {
  return Array.isArray(value) ? value.length : 0;
}

function asList(...values) {
  for (const value of values) {
    if (Array.isArray(value) && value.length) return value;
  }
  return [];
}

function fileEventList(fileEvents, key) {
  if (!fileEvents) return [];
  if (Array.isArray(fileEvents)) return fileEvents;
  if (Array.isArray(fileEvents[key])) return fileEvents[key];
  return [];
}

function readableEvent(item) {
  if (item === null || item === undefined || item === "") return "-";
  if (typeof item === "string") return item;
  if (typeof item === "number" || typeof item === "boolean") return String(item);
  if (typeof item === "object") {
    const preferred = [
      ["process", "pid", "cmdline"],
      ["pid", "name", "cmdline"],
      ["protocol", "local", "remote", "port"],
      ["remote_addr", "remote_port", "protocol"],
      ["path", "action", "sha256"],
      ["filename", "path", "status"],
      ["name", "value", "status"]
    ];
    for (const keys of preferred) {
      const parts = keys
        .map((key) => item[key])
        .filter((value) => value !== undefined && value !== null && value !== "");
      if (parts.length) return parts.map(String).join(" | ");
    }
    return JSON.stringify(item, null, 2);
  }
  return String(item);
}

function behaviorText(result) {
  const behavior = result?.behavior_summary;
  if (result?._placeholder) {
    return "Pret pour M3. Le dashboard attend encore un resultat sandbox stocke dans M4 avec le meme artifact_id.";
  }
  if (!behavior) {
    const files = asList(result?.files_created, result?.file_events?.created).length
      + asList(result?.files_modified, result?.file_events?.modified).length;
    const networks = asList(result?.network_events, result?.network_connections).length;
    const processes = asList(result?.observed_processes, result?.processes_created, result?.processes).length;
    if (files || networks || processes) {
      return `Analyse terminee: ${processes} processus observes, ${files} evenement(s) fichier, ${networks} connexion(s) reseau.`;
    }
    return "Analyse recue, aucun comportement suspect detaille n'a ete rapporte.";
  }
  if (typeof behavior === "string") return behavior;
  return JSON.stringify(behavior, null, 2);
}

function compactList(items, limit = 8) {
  if (!Array.isArray(items) || !items.length) return [];
  return items.slice(0, limit);
}

function splitNetworkEvents(items) {
  const management = [];
  const suspicious = [];
  for (const item of items || []) {
    const text = readableEvent(item).toLowerCase();
    if (text.includes(":22") || text.includes(" ssh") || text.includes(" port 22") || text.includes("22 ")) {
      management.push(item);
    } else {
      suspicious.push(item);
    }
  }
  return { management, suspicious };
}

function riskScoreBand(score) {
  const value = Number(score || 0);
  if (value >= 81) return { label: "CRITICAL", className: "critical" };
  if (value >= 61) return { label: "HIGH", className: "high" };
  if (value >= 31) return { label: "MEDIUM", className: "medium" };
  return { label: "LOW", className: "low" };
}

function riskBar(score, level) {
  const value = Math.max(0, Math.min(Number(score || 0), 100));
  const band = riskScoreBand(value || (String(level).toUpperCase() === "HIGH" ? 78 : 20));
  return `
    <div class="risk-visual ${band.className}">
      <div><span>Risk score</span><strong>${value || "-"}/100 ${escapeHtml(level || band.label)}</strong></div>
      <div class="score-bar"><span style="width:${value}%"></span></div>
    </div>
  `;
}

function setDonut(id, value, total, offset) {
  const circle = $(id);
  if (!circle) return offset;
  const circumference = 276;
  const length = total ? (value / total) * circumference : 0;
  circle.style.strokeDasharray = `${length} ${circumference - length}`;
  circle.style.strokeDashoffset = String(-offset);
  return offset + length;
}

function renderThreatSummary() {
  const severities = [...state.alerts, ...state.quarantine.map((item) => ({ severity: item.risk_level }))];
  const counts = {
    critical: severities.filter((item) => severityClass(item.severity) === "critical").length,
    high: severities.filter((item) => severityClass(item.severity) === "high").length,
    medium: severities.filter((item) => severityClass(item.severity) === "medium").length,
    low: severities.filter((item) => severityClass(item.severity) === "low").length
  };
  const total = counts.critical + counts.high + counts.medium + counts.low;
  $("#sev-critical").textContent = counts.critical;
  $("#sev-high").textContent = counts.high;
  $("#sev-medium").textContent = counts.medium;
  $("#sev-low").textContent = counts.low;
  $("#donut-total").textContent = total;

  let offset = 0;
  offset = setDonut("#donut-critical", counts.critical, total, offset);
  offset = setDonut("#donut-high", counts.high, total, offset);
  setDonut("#donut-medium", counts.medium, total, offset);

  const typeCounts = {};
  for (const alert of state.alerts) {
    const key = alert.type || "UNKNOWN";
    typeCounts[key] = (typeCounts[key] || 0) + 1;
  }
  for (const record of state.quarantine) {
    const key = record.rootkit_category || "QUARANTINE";
    typeCounts[key] = (typeCounts[key] || 0) + 1;
  }

  const rows = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type, count]) => `
      <div class="type-row">
        <span>${escapeHtml(type)}</span>
        <strong>${count}</strong>
      </div>
    `);
  const sandboxDone = state.sandbox.filter((item) => statusDisplay(item.execution_status || item.sandbox_status).label === "SANDBOX_COMPLETED").length;
  const sandboxFailed = state.sandbox.filter((item) => severityClass(item.execution_status || item.sandbox_status) === "critical").length;
  const generatedReports = state.reports.length;
  const averageRisk = counts.critical ? "CRITICAL" : counts.high ? "HIGH" : counts.medium ? "MEDIUM" : "LOW";
  const globalStats = `
    <div class="global-stats">
      <article><span>Alertes totales</span><strong>${state.alerts.length}</strong></article>
      <article><span>Quarantaine</span><strong>${state.quarantine.length}</strong></article>
      <article><span>Sandbox terminees</span><strong>${sandboxDone}</strong></article>
      <article><span>Sandbox echouees</span><strong>${sandboxFailed}</strong></article>
      <article><span>Rapports</span><strong>${generatedReports}</strong></article>
      <article><span>Risque moyen</span><strong>${averageRisk}</strong></article>
    </div>
  `;
  $("#threat-types").innerHTML = (rows.join("") || `<div class="type-row"><span>NO DATA</span><strong>0</strong></div>`) + globalStats;
}

function renderNetworkMap() {
  const networks = state.sandbox.flatMap((item) => item.network_events || item.network_connections || []);
  $("#network-count").textContent = networks.length;
}

function renderRecentQuarantine() {
  const items = state.quarantine.filter(queryMatches).slice(0, 5);
  $("#recent-quarantine").innerHTML = items.map((record) => `
    <div class="mini-row">
      <span>
        <strong>${escapeHtml(record.alert_id)}</strong><br>
        ${escapeHtml(record.created_at || "-")} / ${escapeHtml(record.rootkit_category || "unclassified")}
      </span>
      <span class="hash">${escapeHtml(shortHash(record.md5 || record.sha256, 8, 4))}<br>${escapeHtml(record.status || "-")}</span>
    </div>
  `).join("") || `<div class="mini-row"><span>NO ARTIFACTS</span><strong>0</strong></div>`;
}

function aiRecommendation(plan) {
  return plan?.ai_recommendation || plan?.analysis?.ai_recommendation || {};
}

function selectedPlaybook(plan) {
  const selected = aiRecommendation(plan).selected_playbook || plan?.selected_playbook || {};
  return selected.title || selected.id || plan?.playbook || "";
}

function remediationDecision(plan) {
  return plan?.decision || aiRecommendation(plan).decision || "";
}

function remediationActions(plan) {
  if (Array.isArray(plan?.actions) && plan.actions.length) {
    return plan.actions.map((action) => ({
      title: action.title || action.status || "action",
      body: action.action || action.command || JSON.stringify(action),
      status: action.status || "RECOMMENDED"
    }));
  }

  const ai = aiRecommendation(plan);
  if (Array.isArray(ai.recommended_actions)) {
    return ai.recommended_actions.map((action) => ({
      title: "Recommandation AI",
      body: action,
      status: "AI_RECOMMENDED"
    }));
  }

  return [];
}

function renderRemediationSummary() {
  const items = matchingRemediations();
  const humanValidation = items.filter((item) => item.requires_human_validation !== false).length;
  const critical = items.filter((item) => severityClass(item.risk_level || aiRecommendation(item).risk_level) === "critical").length;
  const latest = items[0];

  $("#remediation-summary").innerHTML = `
    <div class="remediation-kpis">
      <article><span>plans</span><strong>${items.length}</strong></article>
      <article><span>critical</span><strong>${critical}</strong></article>
      <article><span>human validation</span><strong>${humanValidation}</strong></article>
    </div>
    ${latest ? `
      <div class="remediation-latest">
        <span>${escapeHtml(latest.artifact_id || latest.alert_id || "latest artifact")}</span>
        <strong>${escapeHtml(selectedPlaybook(latest) || "Playbook AI en attente")}</strong>
        <em>${escapeHtml(remediationDecision(latest) || "Decision en attente")}</em>
      </div>
    ` : `<div class="empty-state compact"><strong>Aucun plan</strong><span>en attente de la remediation M4</span></div>`}
  `;
}

function renderTrend() {
  const now = new Date();
  const buckets = Array.from({ length: 24 }, () => 0);
  for (const item of allIncidents()) {
    const timestamp = Date.parse(item.timestamp || "");
    if (Number.isNaN(timestamp)) continue;
    const ageHours = Math.floor((now.getTime() - timestamp) / 3600000);
    if (ageHours >= 0 && ageHours < 24) {
      buckets[23 - ageHours] += 1;
    }
  }
  const max = Math.max(1, ...buckets);
  const bars = buckets.map((count, index) => {
    const hour = new Date(now.getTime() - (23 - index) * 3600000).getHours();
    const height = count ? Math.max(10, Math.round((count / max) * 100)) : 4;
    return `<div class="trend-bar" title="${hour}:00 - ${count} event(s)" style="height:${height}%"></div>`;
  });
  $("#trend-chart").innerHTML = bars.join("");
}

function renderActivityLog() {
  const rows = allIncidents().slice(0, 10).map((item) => `
    <tr>
      <td class="mono">${escapeHtml(item.timestamp || "-")}</td>
      <td>${escapeHtml(item.source)}</td>
      <td>${escapeHtml(item.event)}</td>
      <td><span class="badge ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
      <td>${escapeHtml(item.action)}</td>
    </tr>
  `);
  $("#activity-log").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucun evenement</td></tr>`;
}

function renderOverview() {
  renderThreatSummary();
  renderNetworkMap();
  renderRecentQuarantine();
  renderRemediationSummary();
  renderTrend();
  renderActivityLog();
  const errors = Object.values(state.connectionErrors).filter(Boolean).length;
  const suffix = errors ? ` / API WARN: ${errors}` : " / LIVE";
  $("#last-update").textContent = `LAST UPDATE: ${new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}${suffix}`;
}

function renderAlerts() {
  const rows = state.alerts.filter(queryMatches).map((alert, index) => `
    <tr data-alert-index="${index}">
      <td class="mono">${escapeHtml(alert.alert_id)}</td>
      <td>${escapeHtml(alert.source_module)}</td>
      <td>${escapeHtml(alert.type)}</td>
      <td>${statusBadge(alert.severity)}</td>
      <td>${statusBadge(alert.status || "NEW")}</td>
    </tr>
  `);
  $("#alerts-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucune alerte</td></tr>`;
  $$("#alerts-table tr[data-alert-index]").forEach((row) => {
    row.addEventListener("click", () => {
      $$("#alerts-table tr").forEach((item) => item.classList.remove("selected"));
      row.classList.add("selected");
      renderAlertDetail(state.alerts[Number(row.dataset.alertIndex)]);
    });
  });
  renderAlertDetail(state.alerts.find(queryMatches));
}

function renderAlertDetail(alert) {
  const panel = $("#alert-detail");
  if (!alert) {
    panel.innerHTML = emptyState("Selectionner une alerte", "agent monitor");
    return;
  }
  panel.innerHTML = `
    <div class="detail-stack">
      <div class="detail-title">
        <strong>${escapeHtml(alert.alert_id)}</strong>
        <span>${escapeHtml(alert.description)}</span>
      </div>
      ${detailRow("source", alert.source_module)}
      ${detailRow("type", alert.type)}
      ${detailRow("severity", alert.severity)}
      ${detailRow("timestamp", alert.timestamp)}
      ${detailRow("details", JSON.stringify(alert.details || {}, null, 2), true)}
    </div>
  `;
  bindCopyButtons(panel);
}

function renderCases() {
  const items = matchingCases();
  const rows = items.map((item, index) => `
    <tr data-case-index="${index}">
      <td class="mono">${escapeHtml(item.case_id || "-")}</td>
      <td class="mono">${escapeHtml(item.alert_id || "-")}</td>
      <td class="mono">${escapeHtml(item.artifact_id || item.filename || "-")}</td>
      <td>${statusBadge(item.status || "-")}</td>
      <td>${escapeHtml(item.stopped_at || "flux complet")}</td>
    </tr>
  `);
  $("#cases-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucune case locale</td></tr>`;
  $$("#cases-table tr[data-case-index]").forEach((row) => {
    row.addEventListener("click", () => {
      $$("#cases-table tr").forEach((item) => item.classList.remove("selected"));
      row.classList.add("selected");
      renderCaseDetail(items[Number(row.dataset.caseIndex)]);
    });
  });
  renderCaseDetail(items[0]);
}

function renderCaseDetail(item) {
  const panel = $("#case-detail");
  if (!item) {
    panel.innerHTML = emptyState("Selectionner une case", "alert lifecycle");
    return;
  }
  const timeline = Array.isArray(item.timeline) ? item.timeline : [];
  panel.innerHTML = `
    <div class="detail-stack">
      <div class="detail-title">
        <strong>${escapeHtml(item.case_id || item.artifact_id || item.alert_id || "case")}</strong>
        <span>${escapeHtml(item.filename || "flux alerte vers rapport")}</span>
      </div>
      ${detailRow("status", item.status)}
      ${detailRow("stopped at", item.stopped_at || "flux complet")}
      ${detailRow("reason", item.blocked_reason || "-")}
      ${detailRow("last update", item.last_update || "-")}
      <div class="case-flow">
        ${timeline.map((step) => `
          <article class="case-stage ${severityClass(step.status)}">
            <div>
              <span><b>${escapeHtml(stageToken(step.status))}</b>${escapeHtml(step.label || step.id)}</span>
              ${statusBadge(step.status || "-")}
            </div>
            <p>${escapeHtml(step.detail || "-")}</p>
            <em>${escapeHtml(step.timestamp || "")}</em>
          </article>
        `).join("")}
      </div>
    </div>
  `;
  bindCopyButtons(panel);
}

function stageToken(status) {
  const normalized = String(status || "").toUpperCase();
  if (normalized === "DONE" || normalized === "COMPLETED") return "OK";
  if (normalized.includes("WAIT") || normalized.includes("PENDING") || normalized.includes("PROGRESS")) return "WAIT";
  if (normalized.includes("FAIL") || normalized.includes("BLOCK")) return "FAIL";
  return "INFO";
}

function renderQuarantine() {
  const rows = matchingQuarantine().map((record, index) => `
    <tr data-quarantine-index="${index}">
      <td class="mono">${escapeHtml(record.alert_id)}</td>
      <td>${escapeHtml(artifactName(record))}</td>
      <td>${escapeHtml(record.rootkit_category || "unclassified")}</td>
      <td class="hash mono" title="${escapeHtml(record.sha256 || "")}">${escapeHtml(shortHash(record.sha256))}</td>
      <td>${statusBadge(record.status || "-")}</td>
    </tr>
  `);
  $("#quarantine-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucune preuve</td></tr>`;
  $$("#quarantine-table tr[data-quarantine-index]").forEach((row) => {
    row.addEventListener("click", () => {
      $$("#quarantine-table tr").forEach((item) => item.classList.remove("selected"));
      row.classList.add("selected");
      renderQuarantineDetail(matchingQuarantine()[Number(row.dataset.quarantineIndex)]);
    });
  });
  renderQuarantineDetail(matchingQuarantine()[0]);
}

function renderQuarantineDetail(record) {
  const panel = $("#quarantine-detail");
  if (!record) {
    panel.innerHTML = emptyState("Selectionner une preuve", "evidence vault");
    return;
  }
  const manifestUrl = `/api/quarantine/${encodeURIComponent(record.alert_id)}/manifest`;
  const downloadUrl = `/api/quarantine/${encodeURIComponent(record.alert_id)}/download`;
  const handoffUrl = `/api/quarantine/${encodeURIComponent(record.alert_id)}/handoff`;
  const retryUrl = `/api/quarantine/${encodeURIComponent(record.alert_id)}/retry`;
  panel.innerHTML = `
    <div class="detail-stack">
      <div class="detail-title">
        <strong>${escapeHtml(record.artifact_id || record.alert_id)}</strong>
        <span>${escapeHtml(artifactName(record))}</span>
      </div>
      ${detailRow("status", record.status)}
      ${detailRow("original path", record.original_path, true)}
      ${detailRow("quarantine path", record.quarantine_path || record.artifact_path, true)}
      ${detailRow("sha256", record.sha256, true)}
      ${detailRow("md5", record.md5, true)}
      ${detailRow("sha1", record.sha1, true)}
      ${detailRow("integrity", record.integrity_verified ? "VERIFIED" : "NOT VERIFIED")}
      ${detailRow("profile", record.rootkit_category || "unclassified")}
      <div class="action-row">
        <button class="action-button primary" type="button" data-open="${manifestUrl}">manifest</button>
        <button class="action-button" type="button" data-open="${downloadUrl}" ${record.ready_for_sandbox ? "" : "disabled"}>download</button>
        <button class="action-button" type="button" data-open="${handoffUrl}" ${record.ready_for_sandbox ? "" : "disabled"}>handoff</button>
        <button class="action-button" type="button" data-post="${retryUrl}">relancer sandbox</button>
      </div>
    </div>
  `;
  bindOpenButtons(panel);
  bindPostButtons(panel);
  bindCopyButtons(panel);
}

function renderSandbox() {
  const items = sandboxDisplayItems();
  $("#sandbox-grid").innerHTML = items.map((result, index) => {
    const status = result.execution_status || result.sandbox_status || "UNKNOWN";
    const fileEvents = result.file_events || {};
    const files = fileEventList(fileEvents, "created").length + fileEventList(fileEvents, "modified").length + listCount(result.files_created) + listCount(result.files_modified);
    const networkSplit = splitNetworkEvents(asList(result.network_events, result.network_connections));
    const networks = networkSplit.suspicious.length;
    const processes = asList(result.observed_processes, result.processes_created, result.processes).length;
    return `
      <article class="sandbox-card ${result._placeholder ? "waiting" : ""}" data-sandbox-index="${index}">
        <header>
          <strong>${escapeHtml(result.analysis_id || result.artifact_id || "analysis")}</strong>
          ${statusBadge(status)}
        </header>
        <div class="artifact-line"><span>artifact</span><strong class="mono">${escapeHtml(result.artifact_id || "-")}</strong></div>
        <div class="artifact-line"><span>vm</span><strong>${escapeHtml(result.vm_name || result.sandbox_vm || result.sandbox_id || "-")}</strong></div>
        <div class="artifact-line"><span>summary</span><strong>${escapeHtml(behaviorText(result).slice(0, 92))}</strong></div>
        <div class="artifact-line"><span>exit</span><strong>${escapeHtml(valueOrDash(result.exit_code))}</strong></div>
        <div class="artifact-line"><span>process</span><strong>${processes}</strong></div>
        <div class="artifact-line"><span>files</span><strong>${files}</strong></div>
        <div class="artifact-line"><span>network suspect</span><strong>${networks}</strong></div>
        <small>${escapeHtml(result.finished_at || result.analysis_finished_at || result.received_at || "")}</small>
      </article>
    `;
  }).join("") || `<div class="empty-state"><strong>Aucune analyse sandbox</strong><span>isolated runtime</span></div>`;

  $$("#sandbox-grid .sandbox-card[data-sandbox-index]").forEach((card) => {
    card.addEventListener("click", () => {
      $$("#sandbox-grid .sandbox-card").forEach((item) => item.classList.remove("selected"));
      card.classList.add("selected");
      renderSandboxDetail(items[Number(card.dataset.sandboxIndex)]);
    });
  });
  renderSandboxDetail(items[0]);
}

function renderSandboxDetail(result) {
  const panel = $("#sandbox-detail");
  if (!panel) return;
  if (!result) {
    panel.innerHTML = emptyState("Selectionner une analyse", "sandbox behavior");
    return;
  }

  const status = result.execution_status || result.sandbox_status || "UNKNOWN";
  const processes = compactList(asList(result.observed_processes, result.processes_created, result.processes), 12);
  const networkSplit = splitNetworkEvents(asList(result.network_events, result.network_connections));
  const managementNetworks = compactList(networkSplit.management, 12);
  const suspiciousNetworks = compactList(networkSplit.suspicious, 12);
  const created = compactList(asList(result.files_created, fileEventList(result.file_events, "created")), 12);
  const modified = compactList(asList(result.files_modified, fileEventList(result.file_events, "modified")), 12);
  const risks = compactList(asList(result.risk_observations), 12);
  const stdout = result.stdout ? String(result.stdout).slice(0, 1200) : "";
  const stderr = result.stderr ? String(result.stderr).slice(0, 1200) : "";
  const strace = result.strace_excerpt ? String(result.strace_excerpt).slice(0, 1800) : "";
  const remediation = state.remediations.find((plan) => sameArtifact(plan, result));
  const retryUrl = result.alert_id ? `/api/quarantine/${encodeURIComponent(result.alert_id)}/retry` : "";
  const explanation = result._placeholder
    ? "M3 n'a pas encore un resultat confirme dans M4 pour cet artifact_id. Si Asma voit 'deja traite', elle doit supprimer sandbox/processed_artifacts.json ou relancer le worker apres git pull."
    : behaviorText(result);
  const statusInfo = statusDisplay(status);

  panel.innerHTML = `
    <div class="detail-stack">
      <div class="detail-title">
        <strong>${escapeHtml(result.artifact_id || result.analysis_id || "sandbox")}</strong>
        <span>${escapeHtml(result.artifact_name || result.filename || "Analyse comportementale")}</span>
      </div>
      <section class="m3-summary-card">
        <header>
          <span>Resume M3</span>
          ${statusBadge(status)}
        </header>
        <div class="m3-summary-grid">
          <article><span>VM utilisee</span><strong>${escapeHtml(result.vm_name || result.sandbox_vm || result.sandbox_id || "-")}</strong></article>
          <article><span>Snapshot</span><strong>${escapeHtml(result.snapshot_name || result.snapshot_used || "-")}</strong></article>
          <article><span>Execution</span><strong>${escapeHtml(statusInfo.label)}</strong></article>
          <article><span>Exit code</span><strong>${escapeHtml(valueOrDash(result.exit_code))}</strong></article>
          <article><span>Fichiers crees</span><strong>${created.length}</strong></article>
          <article><span>Fichiers modifies</span><strong>${modified.length}</strong></article>
          <article><span>Connexions suspectes</span><strong>${suspiciousNetworks.length}</strong></article>
          <article><span>Observation</span><strong>${escapeHtml(explanation.slice(0, 120))}</strong></article>
        </div>
      </section>
      ${detailRow("interpretation", statusInfo.message || explanation, true)}
      ${result.m4_artifact_id && result.local_artifact_id && result.m4_artifact_id !== result.local_artifact_id ? detailRow("m4 artifact", result.m4_artifact_id, true) : ""}
      ${result._linked_by ? detailRow("linked by", result._linked_by) : ""}
      ${detailRow("started", result.started_at || result.analysis_started_at)}
      ${detailRow("finished", result.finished_at || result.analysis_finished_at || result.received_at)}
      ${detailRow("sha256", result.artifact_sha256, true)}
      <div class="action-row">
        ${retryUrl ? `<button class="action-button" type="button" data-post="${retryUrl}">relancer sandbox</button>` : ""}
      </div>
      <div class="evidence-tabs" data-tabs>
        <div class="tab-buttons" role="tablist">
          ${["resume", "processus", "fichiers", "reseau", "strace", "logs", "remediation"].map((tab, index) => `
            <button class="tab-button ${index === 0 ? "active" : ""}" type="button" data-tab="${tab}">${tab}</button>
          `).join("")}
        </div>
        <section class="tab-panel active" data-panel="resume">
          ${sandboxListBlock("Risk observations", risks)}
          ${detailRow("logs path", result.logs_path || result.local_result_path, true)}
        </section>
        <section class="tab-panel" data-panel="processus">
          ${sandboxListBlock("Observed processes", processes)}
        </section>
        <section class="tab-panel" data-panel="fichiers">
          ${sandboxListBlock("Files created", created)}
          ${sandboxListBlock("Files modified", modified)}
        </section>
        <section class="tab-panel" data-panel="reseau">
          ${sandboxListBlock("Connexions de gestion sandbox", managementNetworks, "Aucune connexion de gestion observee.")}
          ${sandboxListBlock("Connexions suspectes de l'artefact", suspiciousNetworks, "Aucune connexion suspecte observee.")}
        </section>
        <section class="tab-panel" data-panel="strace">
          ${strace ? detailRow("strace excerpt", strace, true) : emptyState("Aucun strace", "strace.log")}
        </section>
        <section class="tab-panel" data-panel="logs">
          ${detailRow("stdout.log", result.stdout_path || "stdout.log", true)}
          ${detailRow("stderr.log", result.stderr_path || "stderr.log", true)}
          ${detailRow("strace.log", result.strace_path || "strace.log", true)}
          ${detailRow("result.json", result.logs_path || result.local_result_path || "sandbox_result.json", true)}
          ${stdout ? detailRow("stdout", stdout, true) : ""}
          ${stderr ? detailRow("stderr", stderr, true) : ""}
        </section>
        <section class="tab-panel" data-panel="remediation">
          ${remediation ? renderRemediationMini(remediation) : emptyState("Aucune remediation liee", "en attente de M4")}
        </section>
      </div>
    </div>
  `;
  bindCopyButtons(panel);
  bindPostButtons(panel);
  bindTabs(panel);
}

function sandboxListBlock(title, items, empty = "Aucun element observe.") {
  return `
    <div class="sandbox-list-block">
      <span>${escapeHtml(title)}</span>
      ${items.length ? `<ul>${items.map((item) => `<li>${escapeHtml(readableEvent(item))}</li>`).join("")}</ul>` : `<p>${escapeHtml(empty)}</p>`}
    </div>
  `;
}

function renderRemediationMini(plan) {
  const ai = aiRecommendation(plan);
  return `
    <div class="remediation-mini">
      ${riskBar(plan.risk_score || ai.risk_score, plan.risk_level || ai.risk_level)}
      ${detailRow("decision", remediationDecision(plan), true)}
      ${sandboxListBlock("actions", remediationActions(plan).map((action) => `${action.title}: ${action.body}`), "Aucune action disponible.")}
    </div>
  `;
}

function renderIocs() {
  const quarantine = state.quarantine.filter(queryMatches);
  const reports = state.reports.filter(queryMatches);
  const iocs = quarantine.flatMap((record) => [
    record.rootkit_category ? { label: "profile", value: record.rootkit_category } : null,
    record.original_path ? { label: "path", value: record.original_path } : null,
    record.sha256 ? { label: "sha256", value: shortHash(record.sha256, 14, 8) } : null,
    ...(record.suspected_techniques || []).map((technique) => ({ label: "technique", value: technique }))
  ].filter(Boolean)).slice(0, 12);

  $("#ioc-list").innerHTML = iocs.map((ioc) => `
    <article class="ioc-item">
      <span>${escapeHtml(ioc.label)}</span>
      <strong>${escapeHtml(ioc.value)}</strong>
    </article>
  `).join("") || `<div class="empty-state"><strong>Aucun IOC</strong><span>intel database</span></div>`;

  const scoreItems = reports.length ? reports : quarantine.map((record) => ({
    artifact_id: record.artifact_id,
    risk_score: ["CRITICAL", "HIGH"].includes(record.risk_level) ? 82 : record.risk_level === "MEDIUM" ? 48 : 20,
    risk_level: record.risk_level || "MEDIUM"
  }));

  $("#score-board").innerHTML = scoreItems.slice(0, 5).map((item) => {
    const score = Number(item.risk_score || item.score || 0);
    return `
      <article class="score-card">
        <span>${escapeHtml(item.artifact_id || item.alert_id || "artifact")}</span>
        <strong>${score}</strong>
        ${riskBar(score, item.risk_level)}
      </article>
    `;
  }).join("") || `<div class="empty-state"><strong>Aucun score</strong><span>risk engine</span></div>`;
}

function renderReports() {
  const rows = state.reports.filter(queryMatches).map((report) => `
    <tr>
      <td class="mono">${escapeHtml(report.report_id || report.alert_id || "-")}</td>
      <td class="mono">${escapeHtml(report.artifact_id || "-")}</td>
      <td>${escapeHtml(report.timestamp || report.created_at || "-")}</td>
      <td>${
        report.download_url
          ? `<button class="action-button primary" type="button" data-open="${escapeHtml(report.download_url)}">download</button>`
          : report.report_path
            ? `<span class="badge ready">HTML</span>`
            : "-"
      }</td>
      <td>${report.pdf_report_path ? `<span class="badge info">PDF</span>` : "-"}</td>
    </tr>
  `);
  $("#reports-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucun rapport</td></tr>`;
  bindOpenButtons($("#reports-table"));
}

function renderRemediation() {
  const items = matchingRemediations();
  const rows = items.map((plan, index) => {
    const ai = aiRecommendation(plan);
    const riskLevel = plan.risk_level || ai.risk_level || "UNKNOWN";
    const validation = plan.requires_human_validation === false ? "AUTO" : "HUMAN";
    return `
      <tr data-remediation-index="${index}">
        <td class="mono">${escapeHtml(plan.artifact_id || plan.alert_id || "-")}</td>
        <td>${statusBadge(riskLevel)}</td>
        <td>${escapeHtml(remediationDecision(plan) || "-")}</td>
        <td>${escapeHtml(selectedPlaybook(plan) || "-")}</td>
        <td><span class="badge ${validation === "HUMAN" ? "medium" : "ready"}">${validation}</span></td>
      </tr>
    `;
  });

  $("#remediation-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucun plan de remediation recu</td></tr>`;
  $$("#remediation-table tr[data-remediation-index]").forEach((row) => {
    row.addEventListener("click", () => {
      $$("#remediation-table tr").forEach((item) => item.classList.remove("selected"));
      row.classList.add("selected");
      renderRemediationDetail(items[Number(row.dataset.remediationIndex)]);
    });
  });
  renderRemediationDetail(items[0]);
}

function renderRemediationDetail(plan) {
  const panel = $("#remediation-detail");
  if (!plan) {
    panel.innerHTML = emptyState("Selectionner un plan", "AI remediation advisor");
    return;
  }

  const ai = aiRecommendation(plan);
  const model = ai.model || {};
  const selected = ai.selected_playbook || {};
  const actions = remediationActions(plan).slice(0, 12);
  const matchedSignals = Array.isArray(ai.matched_signals) ? ai.matched_signals.join(", ") : "";

  panel.innerHTML = `
    <div class="detail-stack">
      <div class="detail-title">
        <strong>${escapeHtml(plan.artifact_id || plan.alert_id || "remediation")}</strong>
        <span>${escapeHtml(selected.title || selected.id || "AI remediation advisor")}</span>
      </div>
      ${detailRow("model", `${model.name || "RDA-Remediation-AI"} ${model.version || ""}`)}
      ${detailRow("external api", model.external_api === true ? "YES" : "NO")}
      ${detailRow("confidence", valueOrDash(ai.confidence))}
      ${riskBar(plan.risk_score || ai.risk_score, plan.risk_level || ai.risk_level)}
      ${detailRow("decision", remediationDecision(plan), true)}
      ${detailRow("matched signals", matchedSignals || "-", true)}
      <div class="remediation-actions">
        ${actions.map((action) => `
          <article>
            ${statusBadge(action.status)}
            <strong>${escapeHtml(action.title)}</strong>
            <p>${escapeHtml(action.body)}</p>
          </article>
        `).join("") || `<div class="empty-state compact"><strong>Aucune action</strong><span>M4 n'a retourne aucune action</span></div>`}
      </div>
    </div>
  `;
  bindCopyButtons(panel);
}

function detailRow(label, value, mono = false) {
  const text = valueOrDash(value);
  const copyable = mono && text !== "-" && (
    String(label).toLowerCase().includes("path")
    || String(label).toLowerCase().includes(".log")
    || String(label).toLowerCase().includes("result.json")
    || String(text).includes("/")
    || String(text).includes("\\")
  );
  const copy = copyable ? `<button class="copy-button" type="button" data-copy="${escapeHtml(text)}">copy path</button>` : "";
  return `
    <div class="detail-row">
      <span>${escapeHtml(label)}</span>
      <strong class="${mono ? "mono" : ""}">${escapeHtml(text)}</strong>
      ${copy}
    </div>
  `;
}

function emptyState(title, subtitle) {
  return `<div class="empty-state"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(subtitle)}</span></div>`;
}

function bindOpenButtons(root = document) {
  root.querySelectorAll("[data-open]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.open) window.open(button.dataset.open, "_blank", "noopener");
    });
  });
}

function bindCopyButtons(root = document) {
  root.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.dataset.copy || "";
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = "copied";
        window.setTimeout(() => { button.textContent = "copy path"; }, 1200);
      } catch {
        button.textContent = "copy failed";
      }
    });
  });
}

function bindPostButtons(root = document) {
  root.querySelectorAll("[data-post]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.post) return;
      button.disabled = true;
      const oldText = button.textContent;
      button.textContent = "sending...";
      try {
        const response = await fetch(button.dataset.post, { method: "GET", cache: "no-store" });
        if (!response.ok) throw new Error(String(response.status));
        button.textContent = "requested";
        await loadData();
      } catch {
        button.textContent = "failed";
      } finally {
        window.setTimeout(() => {
          button.disabled = false;
          button.textContent = oldText;
        }, 1400);
      }
    });
  });
}

function bindTabs(root = document) {
  root.querySelectorAll("[data-tabs]").forEach((tabs) => {
    tabs.querySelectorAll("[data-tab]").forEach((button) => {
      button.addEventListener("click", () => {
        const target = button.dataset.tab;
        tabs.querySelectorAll("[data-tab]").forEach((item) => item.classList.toggle("active", item === button));
        tabs.querySelectorAll("[data-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === target));
      });
    });
  });
}

function setView(view) {
  state.activeView = view;
  $$(".view").forEach((section) => section.classList.toggle("active", section.id === `${view}-view`));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  const current = $(`#${view}-view`);
  $("#view-title").textContent = current?.dataset.title || "Tableau de bord";
}

function renderAll() {
  renderOverview();
  renderAlerts();
  renderCases();
  renderQuarantine();
  renderSandbox();
  renderIocs();
  renderRemediation();
  renderReports();
}

async function loadData() {
  if (state.refreshInFlight) return;
  state.refreshInFlight = true;
  try {
    const [alerts, quarantine, sandbox, reports, remediations, cases] = await Promise.all([
      fetchJson("/api/alerts", "alerts"),
      fetchJson("/api/quarantine", "quarantine"),
      fetchJson("/api/sandbox/results", "results"),
      fetchJson("/api/reports", "reports"),
      fetchJson("/api/remediation", "remediations"),
      fetchJson("/api/cases", "cases")
    ]);
    state.alerts = alerts;
    state.quarantine = quarantine;
    state.sandbox = sandbox;
    state.reports = reports;
    state.remediations = remediations;
    state.cases = cases;
    renderAll();
  } finally {
    state.refreshInFlight = false;
  }
}

function finishBoot() {
  if (bootDone || !bootReady) return;
  bootDone = true;
  const boot = $("#boot-screen");
  if (!boot) return;
  $("#boot-progress").style.width = "100%";
  const percent = $("#boot-percent");
  if (percent) percent.textContent = "100%";
  $("#boot-status").textContent = "opening dashboard...";
  boot.classList.add("leaving");
  window.setTimeout(() => boot.remove(), 460);
}

function bootStatusClass(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "ok") return "ok";
  if (normalized === "warn" || normalized === "warning") return "warn";
  return "fail";
}

function bootStatusToken(status) {
  const normalized = String(status || "").toUpperCase();
  if (normalized === "OK") return "OK";
  if (normalized === "WARN" || normalized === "WARNING") return "WARN";
  return "FAIL";
}

function setBootModule(check) {
  const moduleStatus = document.getElementById(`boot-${check.id}`);
  if (!moduleStatus) return;
  const token = bootStatusToken(check.status);
  moduleStatus.textContent = `[ ${token} ]`;
  moduleStatus.classList.remove("ok", "warn", "fail");
  moduleStatus.classList.add(bootStatusClass(check.status));
}

async function fetchBootChecks() {
  try {
    const response = await fetch("/api/boot/checks", { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    const payload = await response.json();
    return Array.isArray(payload.checks) ? payload.checks : fallbackBootChecks;
  } catch {
    return fallbackBootChecks;
  }
}

async function runBootSequence() {
  const boot = $("#boot-screen");
  const log = $("#boot-log");
  const progress = $("#boot-progress");
  const status = $("#boot-status");
  const percent = $("#boot-percent");
  const skip = $("#boot-skip");
  if (!boot || !log || !progress || !status) return;

  log.textContent = "root@rda:~$ ./rda-console --real-health-check\n";
  status.textContent = "running real module checks...";

  const checks = await fetchBootChecks();
  const bootSteps = [
    {
      progress: 8,
      status: "connecting to local dashboard API...",
      line: "root@rda:~$ GET /api/boot/checks"
    },
    ...checks.map((check, index) => ({
      progress: Math.min(92, 18 + index * Math.max(12, Math.floor(68 / Math.max(checks.length, 1)))),
      status: `checking ${check.label || check.id}...`,
      line: `[ ${bootStatusToken(check.status)} ] ${check.line || check.label || check.id}`,
      check
    })),
    {
      progress: 100,
      status: "real checks completed.",
      line: "[ READY ] press ENTER to open dashboard"
    }
  ];

  bootSteps.forEach((step, index) => {
    window.setTimeout(() => {
      if (bootDone) return;
      progress.style.width = `${step.progress}%`;
      if (percent) percent.textContent = `${step.progress}%`;
      status.textContent = step.status;
      log.textContent += `${step.line}\n`;
      log.scrollTop = log.scrollHeight;
      if (step.check) {
        setBootModule(step.check);
      }
      if (index === bootSteps.length - 1) {
        bootReady = true;
        skip?.classList.add("ready");
      }
    }, 260 + index * 310);
  });

  skip?.addEventListener("click", () => {
    bootReady = true;
    finishBoot();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Enter") finishBoot();
  });
}

function bindEvents() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });

  $$(".segment").forEach((button) => {
    button.addEventListener("click", () => {
      $$(".segment").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      state.quarantineFilter = button.dataset.filter;
      renderQuarantine();
    });
  });

  $("#global-search").addEventListener("input", (event) => {
    state.query = event.target.value.trim().toLowerCase();
    renderAll();
  });

  [
    ["#status-filter", "statusFilter"],
    ["#risk-filter", "riskFilter"],
    ["#member-filter", "memberFilter"],
    ["#type-filter", "typeFilter"]
  ].forEach(([selector, key]) => {
    const field = $(selector);
    if (!field) return;
    field.addEventListener("change", (event) => {
      state[key] = event.target.value;
      renderAll();
    });
  });

  $("#refresh-data").addEventListener("click", loadData);
}

bindEvents();
runBootSequence();
loadData();
window.setInterval(loadData, AUTO_REFRESH_MS);
