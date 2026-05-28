const records = [
  {
    alert_id: "ALT-2026-000001",
    artifact_name: "rk_demo.ko",
    original_path: "/tmp/rk_demo.ko",
    evidence_dir: "/var/lib/rootkit-defense/quarantine/ALT-2026-000001",
    artifact_path: "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
    sha256: "9b3a1d9a6f2d5a2f8a66b3f4c3e0154f27a5e779b1db2f7a8bdf6bd463ea2b88",
    rootkit_category: "kernel_module_rootkit_suspect",
    suspected_techniques: ["kernel_module_loading", "kernel_space_hiding"],
    risk_level: "HIGH",
    status: "READY_FOR_ANALYSIS",
    integrity_verified: true,
    ready_for_sandbox: true,
    created_at: "2026-05-28T18:30:12Z",
    audit_log_path: "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/audit.log"
  },
  {
    alert_id: "ALT-2026-000002",
    artifact_name: "missing.sh",
    original_path: "/tmp/missing.sh",
    evidence_dir: "/var/lib/rootkit-defense/quarantine/ALT-2026-000002",
    artifact_path: null,
    sha256: null,
    rootkit_category: null,
    suspected_techniques: [],
    risk_level: "MEDIUM",
    status: "REJECTED",
    integrity_verified: false,
    ready_for_sandbox: false,
    created_at: "2026-05-28T18:34:09Z",
    audit_log_path: "/var/lib/rootkit-defense/quarantine/ALT-2026-000002/audit.log",
    errors: ["Artifact path does not exist"]
  }
];

let currentFilter = "ALL";
const searchInput = document.querySelector("#search");
const recordsBody = document.querySelector("#records");
const details = document.querySelector("#details");

function riskClass(risk) {
  return risk === "HIGH" || risk === "CRITICAL" ? "high" : "";
}

function statusClass(status) {
  return status === "READY_FOR_ANALYSIS" ? "ready" : "rejected";
}

function filteredRecords() {
  const query = searchInput.value.trim().toLowerCase();
  return records.filter((record) => {
    const matchesFilter = currentFilter === "ALL" || record.status === currentFilter;
    const haystack = [
      record.alert_id,
      record.artifact_name,
      record.original_path,
      record.sha256 || "",
      record.status
    ].join(" ").toLowerCase();
    return matchesFilter && haystack.includes(query);
  });
}

function renderMetrics() {
  document.querySelector("#metric-alerts").textContent = records.length;
  document.querySelector("#metric-ready").textContent = records.filter((r) => r.ready_for_sandbox).length;
  document.querySelector("#metric-integrity").textContent = records.filter((r) => r.integrity_verified).length;
  document.querySelector("#metric-high").textContent = records.filter((r) => ["HIGH", "CRITICAL"].includes(r.risk_level)).length;
}

function renderTable() {
  const rows = filteredRecords().map((record) => `
    <tr>
      <td class="mono">${record.alert_id}</td>
      <td>${record.artifact_name}</td>
      <td><span class="badge ${riskClass(record.risk_level)}">${record.risk_level}</span></td>
      <td><span class="badge ${statusClass(record.status)}">${record.status}</span></td>
      <td class="mono hash">${record.sha256 || "-"}</td>
      <td><button class="details-button" type="button" data-alert="${record.alert_id}">Details</button></td>
    </tr>
  `);
  recordsBody.innerHTML = rows.join("");
  document.querySelectorAll(".details-button").forEach((button) => {
    button.addEventListener("click", () => {
      const record = records.find((item) => item.alert_id === button.dataset.alert);
      renderDetails(record);
    });
  });
}

function renderDetails(record) {
  if (!record) {
    return;
  }
  const errorBlock = record.errors?.length
    ? `<div class="detail-row"><span>Erreur</span><strong>${record.errors.join(", ")}</strong></div>`
    : "";

  details.innerHTML = `
    <div class="detail-stack">
      <h2>${record.alert_id}</h2>
      <div class="detail-row">
        <span>Artefact</span>
        <strong>${record.artifact_name}</strong>
      </div>
      <div class="detail-row">
        <span>Chemin original</span>
        <strong class="mono">${record.original_path}</strong>
      </div>
      <div class="detail-row">
        <span>SHA256</span>
        <strong class="mono">${record.sha256 || "-"}</strong>
      </div>
      <div class="detail-row">
        <span>Profil rootkit</span>
        <strong>${record.rootkit_category || "Non classe"}</strong>
      </div>
      <div class="detail-row">
        <span>Techniques suspectees</span>
        <strong>${record.suspected_techniques?.join(", ") || "-"}</strong>
      </div>
      <div class="detail-row">
        <span>Dossier de preuve</span>
        <strong class="mono">${record.evidence_dir}</strong>
      </div>
      <div class="detail-row">
        <span>Journal audit</span>
        <strong class="mono">${record.audit_log_path}</strong>
      </div>
      <div class="detail-row">
        <span>Integrite</span>
        <strong>${record.integrity_verified ? "Validee" : "Non validee"}</strong>
      </div>
      ${errorBlock}
      <div class="action-row">
        <button class="primary-action" type="button" ${record.ready_for_sandbox ? "" : "disabled"}>Sandbox</button>
        <button class="secondary-action" type="button">Manifest</button>
      </div>
    </div>
  `;
}

document.querySelectorAll(".segment").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    currentFilter = button.dataset.filter;
    renderTable();
  });
});

searchInput.addEventListener("input", renderTable);
renderMetrics();
renderTable();
