const state = {
  alerts: [],
  quarantine: [],
  sandbox: [],
  reports: [],
  remediations: [],
  cases: [],
  activeView: "dashboard",
  quarantineFilter: "ALL",
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

function recordText(record) {
  return JSON.stringify(record || {}).toLowerCase();
}

function queryMatches(record) {
  return !state.query || recordText(record).includes(state.query);
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
  $("#threat-types").innerHTML = rows.join("") || `<div class="type-row"><span>NO DATA</span><strong>0</strong></div>`;
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
      <td><span class="badge ${severityClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td><span class="badge ${severityClass(alert.status)}">${escapeHtml(alert.status || "NEW")}</span></td>
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
}

function renderCases() {
  const items = matchingCases();
  const rows = items.map((item, index) => `
    <tr data-case-index="${index}">
      <td class="mono">${escapeHtml(item.case_id || "-")}</td>
      <td class="mono">${escapeHtml(item.alert_id || "-")}</td>
      <td class="mono">${escapeHtml(item.artifact_id || item.filename || "-")}</td>
      <td><span class="badge ${severityClass(item.status)}">${escapeHtml(item.status || "-")}</span></td>
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
              <span>${escapeHtml(step.label || step.id)}</span>
              <strong>${escapeHtml(step.status || "-")}</strong>
            </div>
            <p>${escapeHtml(step.detail || "-")}</p>
            <em>${escapeHtml(step.timestamp || "")}</em>
          </article>
        `).join("")}
      </div>
    </div>
  `;
}

function renderQuarantine() {
  const rows = matchingQuarantine().map((record, index) => `
    <tr data-quarantine-index="${index}">
      <td class="mono">${escapeHtml(record.alert_id)}</td>
      <td>${escapeHtml(artifactName(record))}</td>
      <td>${escapeHtml(record.rootkit_category || "unclassified")}</td>
      <td class="hash mono" title="${escapeHtml(record.sha256 || "")}">${escapeHtml(shortHash(record.sha256))}</td>
      <td><span class="badge ${severityClass(record.status)}">${escapeHtml(record.status || "-")}</span></td>
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
      </div>
    </div>
  `;
  bindOpenButtons(panel);
}

function renderSandbox() {
  const items = state.sandbox.filter(queryMatches);
  $("#sandbox-grid").innerHTML = items.map((result) => {
    const status = result.execution_status || result.sandbox_status || "UNKNOWN";
    const fileEvents = result.file_events || {};
    const files = (fileEvents.created?.length || 0) + (fileEvents.modified?.length || 0) + (result.files_created?.length || 0);
    const networks = (result.network_events || result.network_connections || []).length;
    return `
      <article class="sandbox-card">
        <header>
          <strong>${escapeHtml(result.analysis_id || result.artifact_id || "analysis")}</strong>
          <span class="badge ${severityClass(status)}">${escapeHtml(status)}</span>
        </header>
        <div class="artifact-line"><span>artifact</span><strong class="mono">${escapeHtml(result.artifact_id || "-")}</strong></div>
        <div class="artifact-line"><span>vm</span><strong>${escapeHtml(result.vm_name || result.sandbox_vm || result.sandbox_id || "-")}</strong></div>
        <div class="artifact-line"><span>snapshot</span><strong>${escapeHtml(result.snapshot_name || result.snapshot_used || "-")}</strong></div>
        <div class="artifact-line"><span>exit</span><strong>${escapeHtml(valueOrDash(result.exit_code))}</strong></div>
        <div class="artifact-line"><span>files</span><strong>${files}</strong></div>
        <div class="artifact-line"><span>network</span><strong>${networks}</strong></div>
        <small>${escapeHtml(result.logs_path || result.local_result_path || "")}</small>
      </article>
    `;
  }).join("") || `<div class="empty-state"><strong>Aucune analyse sandbox</strong><span>isolated runtime</span></div>`;
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
        <div class="score-bar"><span style="width:${Math.max(0, Math.min(score, 100))}%"></span></div>
        <span class="badge ${severityClass(item.risk_level)}">${escapeHtml(item.risk_level || "UNKNOWN")}</span>
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
      <td>${report.report_path ? `<span class="badge ready">HTML</span>` : "-"}</td>
      <td>${report.pdf_report_path ? `<span class="badge info">PDF</span>` : "-"}</td>
    </tr>
  `);
  $("#reports-table").innerHTML = rows.join("") || `<tr><td class="empty-row" colspan="5">Aucun rapport</td></tr>`;
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
        <td><span class="badge ${severityClass(riskLevel)}">${escapeHtml(riskLevel)}</span></td>
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
      ${detailRow("risk", `${valueOrDash(plan.risk_level || ai.risk_level)} / ${valueOrDash(plan.risk_score || ai.risk_score)}`)}
      ${detailRow("decision", remediationDecision(plan), true)}
      ${detailRow("matched signals", matchedSignals || "-", true)}
      <div class="remediation-actions">
        ${actions.map((action) => `
          <article>
            <span class="badge ${severityClass(action.status)}">${escapeHtml(action.status)}</span>
            <strong>${escapeHtml(action.title)}</strong>
            <p>${escapeHtml(action.body)}</p>
          </article>
        `).join("") || `<div class="empty-state compact"><strong>Aucune action</strong><span>M4 n'a retourne aucune action</span></div>`}
      </div>
    </div>
  `;
}

function detailRow(label, value, mono = false) {
  return `
    <div class="detail-row">
      <span>${escapeHtml(label)}</span>
      <strong class="${mono ? "mono" : ""}">${escapeHtml(valueOrDash(value))}</strong>
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

  $("#refresh-data").addEventListener("click", loadData);
}

bindEvents();
runBootSequence();
loadData();
window.setInterval(loadData, AUTO_REFRESH_MS);
