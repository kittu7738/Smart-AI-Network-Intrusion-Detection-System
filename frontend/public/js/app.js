/**
 * Smart AI NIDS — Security Operations Center (SOC) Application Controller
 * Exact Implementation Matching Enterprise Reference Mockup
 *
 * - 13-Class Frozen Canonical Taxonomy (IDs 0–12)
 * - 5 Specialist Classifiers (IDS2018, CICIoT2023, ARP_Spoofing, IP_Spoofing, DNS_Tunneling)
 * - Multi-mode Playground, Live Telemetry Filtering, Real-time Metrics & Chart.js Distribution
 */

document.addEventListener("DOMContentLoaded", () => {
  const soc = new EnterpriseSocController();
  soc.init();
});

class EnterpriseSocController {
  constructor() {
    this.api = window.apiService;
    this.chart = null;

    // Baseline session metrics matching reference dashboard state
    this.metrics = {
      totalPackets: 12458,
      benignTraffic: 11892,
      maliciousTraffic: 566,
      detectionRate: 98.7,
      activeModels: 5,
      totalModels: 5,
      backendOnline: true,
    };

    // Frozen 13-Class Canonical Taxonomy Specification & Palette
    this.canonicalTaxonomy = [
      { id: 0,  name: "Benign",            color: "#3B82F6", initialCount: 275, severity: "benign" },
      { id: 1,  name: "DDoS",              color: "#EF4444", initialCount: 50,  severity: "critical" },
      { id: 2,  name: "DoS",               color: "#F97316", initialCount: 15,  severity: "critical" },
      { id: 3,  name: "Botnet",            color: "#22C55E", initialCount: 10,  severity: "critical" },
      { id: 4,  name: "Infiltration",      color: "#581C87", initialCount: 10,  severity: "critical" },
      { id: 5,  name: "Brute Force",       color: "#EC4899", initialCount: 18,  severity: "high" },
      { id: 6,  name: "Web Attack",        color: "#D946EF", initialCount: 7,   severity: "high" },
      { id: 7,  name: "DNS Spoofing",      color: "#3B82F6", initialCount: 30,  severity: "suspicious" },
      { id: 8,  name: "IP Spoofing",       color: "#A855F7", initialCount: 12,  severity: "high" },
      { id: 9,  name: "ARP Spoofing",      color: "#F87171", initialCount: 10,  severity: "high" },
      { id: 10, name: "Recon / Port Scan", color: "#4338CA", initialCount: 24,  severity: "suspicious" },
      { id: 11, name: "MITM",              color: "#06B6D4", initialCount: 12,  severity: "critical" },
      { id: 12, name: "DNS Tunneling",     color: "#7C3AED", initialCount: 25,  severity: "high" },
    ];

    this.canonicalCounts = this.canonicalTaxonomy.map((c) => c.initialCount);

    // Initial detection stream matching reference mockup
    this.detections = [
      { time: "11:42:31", source: "192.168.1.23", specialist: "IDS2018", className: "DDoS", classId: 1, confidence: 0.987, isThreat: true },
      { time: "11:42:28", source: "10.0.0.45", specialist: "CICIoT2023", className: "Botnet", classId: 3, confidence: 0.972, isThreat: true },
      { time: "11:42:25", source: "172.16.0.8", specialist: "ARP_Spoofing", className: "ARP Spoofing", classId: 9, confidence: 0.968, isThreat: true },
      { time: "11:42:21", source: "192.168.1.56", specialist: "IDS2018", className: "Benign", classId: 0, confidence: 0.991, isThreat: false },
      { time: "11:42:18", source: "203.0.113.12", specialist: "DNS_Tunneling", className: "DNS Tunneling", classId: 12, confidence: 0.984, isThreat: true },
      { time: "11:42:15", source: "192.168.1.78", specialist: "IDS2018", className: "Recon / Port Scan", classId: 10, confidence: 0.956, isThreat: true },
      { time: "11:42:12", source: "10.0.0.101", specialist: "ARP_Spoofing", className: "Benign", classId: 0, confidence: 0.989, isThreat: false },
      { time: "11:42:08", source: "172.16.0.33", specialist: "CICIoT2023", className: "Web Attack", classId: 6, confidence: 0.978, isThreat: true },
    ];

    // Audit log records
    this.auditEvents = [
      { time: "11:42:31", category: "INFERENCE", details: "IDS2018 classified 192.168.1.23 as DDoS (98.7%)", status: "SUCCESS" },
      { time: "11:42:28", category: "INFERENCE", details: "CICIoT2023 classified 10.0.0.45 as Botnet (97.2%)", status: "SUCCESS" },
      { time: "11:42:25", category: "INFERENCE", details: "ARP specialist classified 172.16.0.8 as ARP Spoofing (96.8%)", status: "SUCCESS" },
      { time: "11:40:00", category: "HEALTH", details: "Unified NIDS engine status: All 5 specialists operational", status: "SUCCESS" },
      { time: "11:38:12", category: "SYSTEM", details: "Security Operations Center initialized successfully", status: "SUCCESS" },
    ];

    // 5 Specialist Catalog metadata
    this.specialistsCatalog = [
      { name: "IDS2018", domain: "Enterprise CSE-CIC-IDS2018 Flows", arch: "Decision Tree / LightGBM", features: 77, acc: "98.77%", f1: "84.15%", status: "ONLINE" },
      { name: "CICIoT2023", domain: "Internet of Things (IoT) Network Traffic", arch: "Random Forest / Extra Trees", features: 46, acc: "99.12%", f1: "87.23%", status: "ONLINE" },
      { name: "ARP_Spoofing", domain: "Layer-2 Address Resolution Protocol", arch: "Decision Tree / Extra Trees", features: 2, acc: "98.45%", f1: "82.67%", status: "ONLINE" },
      { name: "IP_Spoofing", domain: "5G-NIDD GTP Network Intrusion Dataset", arch: "LogisticRegression Scaled", features: 12, acc: "97.80%", f1: "83.10%", status: "ONLINE" },
      { name: "DNS_Tunneling", domain: "DNS Statistical Exfiltration & Tunneling", arch: "Random Forest", features: 12, acc: "98.20%", f1: "85.40%", status: "ONLINE" },
    ];
  }

  async init() {
    this.initClock();
    this.initNavigation();
    this.initChart();
    this.renderOverviewDetections();
    this.renderFullDetections();
    this.renderSpecialistCards();
    this.renderAuditEvents();
    this.renderVerdictCard("Benign", 0, 0.991, "Unified NIDS", []);
    this.bindControls();

    // Verify connection to backend
    await this.checkBackendStatus();
  }

  /**
   * Top Header Real-time Clock
   */
  initClock() {
    const dateEl = document.getElementById("header-live-date");
    const timeEl = document.getElementById("header-live-time");

    const updateClock = () => {
      const now = new Date();
      if (dateEl) {
        dateEl.textContent = now.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
      }
      if (timeEl) {
        timeEl.textContent = now.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
      }
    };

    updateClock();
    setInterval(updateClock, 1000);
  }

  /**
   * Sidebar Navigation Switching
   */
  initNavigation() {
    const navButtons = document.querySelectorAll(".sidebar-nav-list .nav-link-btn");
    const viewPanels = document.querySelectorAll(".view-panel");

    const switchView = (targetViewId) => {
      navButtons.forEach((btn) => {
        if (btn.getAttribute("data-view") === targetViewId) {
          btn.classList.add("active");
        } else {
          btn.classList.remove("active");
        }
      });

      viewPanels.forEach((panel) => {
        if (panel.id === targetViewId) {
          panel.classList.add("active");
        } else {
          panel.classList.remove("active");
        }
      });

      if (targetViewId === "view-overview" && this.chart) {
        setTimeout(() => this.chart.resize(), 50);
      }
    };

    navButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const viewId = btn.getAttribute("data-view");
        if (viewId) switchView(viewId);
      });
    });

    window.switchSocView = switchView;
  }

  /**
   * Chart.js Threat Distribution (13 Classes) matching Reference
   */
  initChart() {
    const canvas = document.getElementById("overviewThreatChart");
    if (!canvas || !window.Chart) return;

    const labels = this.canonicalTaxonomy.map((c) => c.name);
    const colors = this.canonicalTaxonomy.map((c) => c.color);

    const ctx = canvas.getContext("2d");
    this.chart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Packet Count",
          data: [...this.canonicalCounts],
          backgroundColor: colors,
          borderRadius: 2,
          borderSkipped: false,
          maxBarThickness: 24,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0F172A",
            padding: 8,
            titleFont: { family: "'Inter', sans-serif", size: 12, weight: "bold" },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: {
              label: (ctx) => ` Count: ${ctx.parsed.y}`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: "#64748B",
              font: { family: "'Inter', sans-serif", size: 10 },
              maxRotation: 45,
              minRotation: 45,
              autoSkip: false,
            }
          },
          y: {
            beginAtZero: true,
            max: 300,
            ticks: {
              stepSize: 50,
              color: "#64748B",
              font: { family: "'Inter', sans-serif", size: 10 }
            },
            grid: {
              color: "#F1F5F9"
            },
            title: {
              display: true,
              text: "Packet Count",
              color: "#64748B",
              font: { family: "'Inter', sans-serif", size: 11, weight: "500" }
            }
          }
        }
      }
    });
  }

  /**
   * Render Live Network Detections in Overview table
   */
  renderOverviewDetections() {
    const tbody = document.getElementById("overview-detections-tbody");
    if (!tbody) return;

    tbody.innerHTML = "";
    const items = this.detections.slice(0, 8);

    items.forEach((det) => {
      const row = document.createElement("tr");

      const dotClass = det.isThreat ? "red" : "green";
      let classColorClass = "green";
      if (det.className === "DDoS" || det.className === "Botnet" || det.className === "Web Attack") {
        classColorClass = "red";
      } else if (det.className === "ARP Spoofing" || det.className === "Recon / Port Scan") {
        classColorClass = "orange";
      } else if (det.className === "DNS Tunneling") {
        classColorClass = "purple";
      }

      const confText = (det.confidence * 100).toFixed(1) + "%";

      row.innerHTML = `
        <td>
          <span class="time-cell">
            <span class="row-status-dot ${dotClass}"></span>
            ${det.time}
          </span>
        </td>
        <td>${det.source}</td>
        <td>${det.specialist}</td>
        <td><span class="class-text-cell ${classColorClass}">${det.className}</span></td>
        <td style="text-align: right;" class="confidence-cell">${confText}</td>
      `;
      tbody.appendChild(row);
    });
  }

  /**
   * Render Full Live Detections view table
   */
  renderFullDetections() {
    const tbody = document.getElementById("live-detections-full-tbody");
    const countBadge = document.getElementById("live-det-count-badge");
    const searchInput = document.getElementById("filter-search-input");
    const specSelect = document.getElementById("filter-specialist-select");
    const classSelect = document.getElementById("filter-class-select");

    if (countBadge) {
      countBadge.textContent = `${this.detections.length} Detections Recorded`;
    }

    if (!tbody) return;

    const term = searchInput ? searchInput.value.toLowerCase().trim() : "";
    const specVal = specSelect ? specSelect.value : "";
    const classVal = classSelect ? classSelect.value : "";

    const filtered = this.detections.filter((d) => {
      if (specVal && d.specialist !== specVal) return false;
      if (classVal && d.className !== classVal) return false;
      if (term) {
        return d.source.toLowerCase().includes(term) || d.className.toLowerCase().includes(term) || d.specialist.toLowerCase().includes(term);
      }
      return true;
    });

    tbody.innerHTML = "";
    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No matching records found.</td></tr>`;
      return;
    }

    filtered.forEach((det) => {
      const row = document.createElement("tr");
      const dotClass = det.isThreat ? "red" : "green";
      const confText = (det.confidence * 100).toFixed(1) + "%";
      const statusPill = det.isThreat
        ? `<span class="mini-badge-online" style="background:#FEE2E2; color:#DC2626;">THREAT</span>`
        : `<span class="mini-badge-online">BENIGN</span>`;

      row.innerHTML = `
        <td>
          <span class="time-cell">
            <span class="row-status-dot ${dotClass}"></span>
            ${det.time}
          </span>
        </td>
        <td style="font-family: var(--font-mono);">${det.source}</td>
        <td>${det.specialist}</td>
        <td style="font-weight: 600;">${det.className}</td>
        <td class="confidence-cell">${confText}</td>
        <td style="text-align: right;">${statusPill}</td>
      `;
      tbody.appendChild(row);
    });
  }

  /**
   * Render Specialist Models catalog cards
   */
  renderSpecialistCards() {
    const grid = document.getElementById("specialist-models-catalog-grid");
    if (!grid) return;

    grid.innerHTML = "";
    this.specialistsCatalog.forEach((spec) => {
      const card = document.createElement("div");
      card.className = "specialist-mini-card";

      card.innerHTML = `
        <div class="specialist-mini-header">
          <div class="specialist-mini-title-box">
            <div class="specialist-mini-icon blue">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 18px; height: 18px;">
                <ellipse cx="12" cy="5" rx="9" ry="3"/>
                <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
              </svg>
            </div>
            <div class="specialist-mini-name">${spec.name}</div>
          </div>
          <span class="mini-badge-online">${spec.status}</span>
        </div>
        <div class="specialist-mini-sub">${spec.arch}</div>
        <table class="specialist-stat-table">
          <tr>
            <td class="stat-label">Features</td>
            <td class="stat-val">${spec.features}</td>
          </tr>
          <tr>
            <td class="stat-label">Accuracy</td>
            <td class="stat-val">${spec.acc}</td>
          </tr>
          <tr>
            <td class="stat-label">Macro F1</td>
            <td class="stat-val">${spec.f1}</td>
          </tr>
        </table>
      `;
      grid.appendChild(card);
    });
  }

  /**
   * Render Verdict Card in Playground
   */
  renderVerdictCard(className, classId, confidence, specialist, probabilities = []) {
    const bannerBox = document.getElementById("verdict-banner-box");
    const classEl = document.getElementById("verdict-class-name");
    const confVal = document.getElementById("verdict-conf-value");
    const specEl = document.getElementById("verdict-specialist-name");
    const probList = document.getElementById("verdict-prob-list");

    const isBenign = (classId === 0);
    const confPct = (confidence * 100).toFixed(1) + "%";

    if (bannerBox) {
      bannerBox.className = `verdict-banner-box ${isBenign ? "benign" : "threat"}`;
    }
    if (classEl) classEl.textContent = className;
    if (confVal) confVal.textContent = confPct;
    if (specEl) specEl.textContent = specialist;

    if (probList) {
      probList.innerHTML = "";
      this.canonicalTaxonomy.forEach((cls) => {
        let prob = probabilities[cls.id];
        if (prob === undefined) {
          prob = (cls.id === classId) ? confidence : (1 - confidence) / 12;
        }
        const pct = (prob * 100).toFixed(1);

        const item = document.createElement("div");
        item.className = "prob-item";
        item.innerHTML = `
          <div class="prob-labels">
            <span style="${cls.id === classId ? 'font-weight:700; color:var(--color-primary);' : ''}">#${cls.id} ${cls.name}</span>
            <span style="font-family: var(--font-mono); font-weight: 600;">${pct}%</span>
          </div>
          <div class="prob-track">
            <div class="prob-fill" style="width: ${pct}%; background-color: ${cls.color};"></div>
          </div>
        `;
        probList.appendChild(item);
      });
    }
  }

  /**
   * Render Audit Events table
   */
  renderAuditEvents() {
    const tbody = document.getElementById("audit-events-tbody");
    if (!tbody) return;

    tbody.innerHTML = "";
    this.auditEvents.forEach((evt) => {
      const row = document.createElement("tr");
      const statusPill = evt.status === "SUCCESS"
        ? `<span class="mini-badge-online">SUCCESS</span>`
        : `<span class="mini-badge-online" style="background:#FEE2E2; color:#DC2626;">ERROR</span>`;

      row.innerHTML = `
        <td style="font-family: var(--font-mono); color: var(--text-muted);">${evt.time}</td>
        <td><span class="mini-badge-online" style="background:var(--bg-subtle); color:var(--text-main);">${evt.category}</span></td>
        <td style="font-size: 12px;">${evt.details}</td>
        <td style="text-align: right;">${statusPill}</td>
      `;
      tbody.appendChild(row);
    });
  }

  logAuditEvent(category, details, status = "SUCCESS") {
    const time = new Date().toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", second: "2-digit", hour12: false });
    this.auditEvents.unshift({ time, category, details, status });
    this.renderAuditEvents();
  }

  /**
   * Bind Playground and settings controls
   */
  bindControls() {
    // Playground Tabs
    const tabs = document.querySelectorAll(".pg-tab-btn");
    const panes = document.querySelectorAll(".pg-pane");
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        const target = tab.getAttribute("data-tab");
        panes.forEach((p) => {
          p.style.display = p.id === target ? "block" : "none";
        });
      });
    });

    // Preset Chips
    document.querySelectorAll(".preset-chip-btn[data-dns]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const inp = document.getElementById("dns-query-input");
        if (inp) inp.value = btn.getAttribute("data-dns");
      });
    });

    document.querySelectorAll(".preset-chip-btn[data-struct]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const ta = document.getElementById("structured-json-input");
        const spec = document.getElementById("pg-specialist-select");
        try {
          const d = JSON.parse(btn.getAttribute("data-struct"));
          if (ta) ta.value = JSON.stringify(d, null, 2);
          if (spec && d.specialist) spec.value = d.specialist;
        } catch (e) {}
      });
    });

    // Run DNS Inference
    const btnDns = document.getElementById("btn-analyze-dns");
    if (btnDns) {
      btnDns.addEventListener("click", () => this.runDnsInference());
    }

    // Run Structured Inference
    const btnStruct = document.getElementById("btn-run-structured");
    if (btnStruct) {
      btnStruct.addEventListener("click", () => this.runStructuredInference());
    }

    // Run Batch Inference
    const btnBatch = document.getElementById("btn-execute-batch");
    if (btnBatch) {
      btnBatch.addEventListener("click", () => this.runBatchInference());
    }

    // Filter controls
    const searchInp = document.getElementById("filter-search-input");
    const specSel = document.getElementById("filter-specialist-select");
    const classSel = document.getElementById("filter-class-select");
    const clearBtn = document.getElementById("btn-clear-filters");

    if (searchInp) searchInp.addEventListener("input", () => this.renderFullDetections());
    if (specSel) specSel.addEventListener("change", () => this.renderFullDetections());
    if (classSel) classSel.addEventListener("change", () => this.renderFullDetections());
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        if (searchInp) searchInp.value = "";
        if (specSel) specSel.value = "";
        if (classSel) classSel.value = "";
        this.renderFullDetections();
      });
    }

    // Audit clear
    const btnClearAudit = document.getElementById("btn-clear-audit");
    if (btnClearAudit) {
      btnClearAudit.addEventListener("click", () => {
        this.auditEvents = [];
        this.renderAuditEvents();
      });
    }

    // Settings Test & Save
    const btnTest = document.getElementById("btn-settings-test");
    const btnSave = document.getElementById("btn-settings-save");
    const inpUrl = document.getElementById("settings-api-url-input");

    if (inpUrl) inpUrl.value = this.api.getBaseUrl();
    if (btnTest) btnTest.addEventListener("click", () => this.testBackendUrl());
    if (btnSave) btnSave.addEventListener("click", () => this.saveBackendUrl());
  }

  async runDnsInference() {
    const input = document.getElementById("dns-query-input");
    const errBox = document.getElementById("dns-error-box");
    const btn = document.getElementById("btn-analyze-dns");
    if (!input) return;

    const query = input.value.trim();
    if (!query) {
      if (errBox) errBox.textContent = "Please enter a valid domain query.";
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) btn.textContent = "Analyzing...";

    try {
      const resp = await this.api.predict({ query });
      this.recordLiveInference(query, "DNS_Tunneling", resp);
      this.logAuditEvent("INFERENCE", `DNS query "${query}" -> ${resp.predicted_class} (${(resp.confidence * 100).toFixed(1)}%)`, "SUCCESS");
    } catch (err) {
      if (errBox) errBox.textContent = err.message;
      this.logAuditEvent("INFERENCE", `DNS inference failed: ${err.message}`, "ERROR");
    } finally {
      if (btn) btn.textContent = "Analyze Query";
    }
  }

  async runStructuredInference() {
    const textarea = document.getElementById("structured-json-input");
    const errBox = document.getElementById("struct-error-box");
    const btn = document.getElementById("btn-run-structured");
    if (!textarea) return;

    let payload;
    try {
      payload = JSON.parse(textarea.value);
    } catch (e) {
      if (errBox) errBox.textContent = "Invalid JSON format.";
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) btn.textContent = "Processing...";

    try {
      const resp = await this.api.predict(payload);
      const spec = resp.specialist || payload.specialist || "Auto";
      this.recordLiveInference("Structured Flow", spec, resp);
      this.logAuditEvent("INFERENCE", `Structured flow classified: ${resp.predicted_class} (${(resp.confidence * 100).toFixed(1)}%) via ${spec}`, "SUCCESS");
    } catch (err) {
      if (errBox) errBox.textContent = err.message;
      this.logAuditEvent("INFERENCE", `Structured inference failed: ${err.message}`, "ERROR");
    } finally {
      if (btn) btn.textContent = "Run Detection";
    }
  }

  async runBatchInference() {
    const textarea = document.getElementById("batch-json-input");
    const errBox = document.getElementById("batch-error-box");
    const btn = document.getElementById("btn-execute-batch");
    if (!textarea) return;

    let records;
    try {
      records = JSON.parse(textarea.value);
      if (!Array.isArray(records)) throw new Error("Array required");
    } catch (e) {
      if (errBox) errBox.textContent = "Valid JSON array required.";
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) btn.textContent = "Processing Batch...";

    try {
      const resp = await this.api.predictBatch(records, "auto");
      const list = resp.predictions || [];
      list.forEach((item, idx) => {
        const queryText = records[idx].query || `Flow #${idx + 1}`;
        this.recordLiveInference(queryText, item.specialist || "Auto", item);
      });
      this.logAuditEvent("INFERENCE", `Batch processed: ${list.length} records evaluated`, "SUCCESS");
    } catch (err) {
      if (errBox) errBox.textContent = err.message;
      this.logAuditEvent("INFERENCE", `Batch inference failed: ${err.message}`, "ERROR");
    } finally {
      if (btn) btn.textContent = "Execute Batch Inference";
    }
  }

  recordLiveInference(source, specialist, response) {
    const classId = Number(response.predicted_class_id);
    const className = response.predicted_class;
    const confidence = Number(response.confidence) || 0.0;
    const isThreat = classId !== 0;

    // Metrics updates
    this.metrics.totalPackets++;
    if (isThreat) {
      this.metrics.maliciousTraffic++;
    } else {
      this.metrics.benignTraffic++;
    }
    this.metrics.detectionRate = ((this.metrics.benignTraffic / this.metrics.totalPackets) * 100);

    const nowTime = new Date().toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", second: "2-digit", hour12: false });

    // Prepend to detections
    this.detections.unshift({
      time: nowTime,
      source: source,
      specialist: specialist,
      className: className,
      classId: classId,
      confidence: confidence,
      isThreat: isThreat,
    });

    // Update canonical counts & chart
    if (classId >= 0 && classId < 13) {
      this.canonicalCounts[classId]++;
      if (this.chart) {
        this.chart.data.datasets[0].data = [...this.canonicalCounts];
        this.chart.update();
      }
    }

    // Update KPI card DOM
    const elPackets = document.getElementById("kpi-total-packets");
    const elBenign = document.getElementById("kpi-benign-traffic");
    const elMalicious = document.getElementById("kpi-malicious-traffic");
    const elRate = document.getElementById("kpi-detection-rate");

    if (elPackets) elPackets.textContent = this.metrics.totalPackets.toLocaleString();
    if (elBenign) elBenign.textContent = this.metrics.benignTraffic.toLocaleString();
    if (elMalicious) elMalicious.textContent = this.metrics.maliciousTraffic.toLocaleString();
    if (elRate) elRate.textContent = `${this.metrics.detectionRate.toFixed(1)}%`;

    this.renderOverviewDetections();
    this.renderFullDetections();
    this.renderVerdictCard(className, classId, confidence, specialist, response.probabilities || []);
  }

  async checkBackendStatus() {
    const pill = document.getElementById("header-system-pill");
    const text = document.getElementById("header-system-text");
    const badge = document.getElementById("overview-nids-badge");
    const badgeText = document.getElementById("overview-nids-text");

    try {
      const h = await this.api.getHealth();
      if (pill && text) {
        pill.className = "system-status-pill";
        text.textContent = "System Online";
      }
      if (badge && badgeText) {
        badge.className = "nids-status-badge";
        badgeText.textContent = "NIDS ONLINE";
      }
    } catch (e) {
      if (pill && text) {
        pill.className = "system-status-pill";
        pill.style.background = "#FEE2E2";
        pill.style.color = "#DC2626";
        text.textContent = "Backend Offline";
      }
      if (badge && badgeText) {
        badge.className = "nids-status-badge offline";
        badgeText.textContent = "NIDS OFFLINE";
      }
    }
  }

  async testBackendUrl() {
    const inp = document.getElementById("settings-api-url-input");
    const banner = document.getElementById("settings-test-banner");
    if (!inp || !banner) return;

    banner.style.display = "block";
    banner.style.background = "#F1F5F9";
    banner.style.color = "#475569";
    banner.textContent = `Connecting to ${inp.value}/health...`;

    try {
      const res = await fetch(`${inp.value.replace(/\/+$/, "")}/health`);
      const d = await res.json();
      banner.style.background = "#DCFCE7";
      banner.style.color = "#16A34A";
      banner.textContent = `Success: Backend healthy (${d.models_loaded || 5} models ready).`;
    } catch (err) {
      banner.style.background = "#FEE2E2";
      banner.style.color = "#DC2626";
      banner.textContent = `Failed: ${err.message}`;
    }
  }

  saveBackendUrl() {
    const inp = document.getElementById("settings-api-url-input");
    const banner = document.getElementById("settings-test-banner");
    if (!inp) return;

    this.api.setBaseUrl(inp.value);
    if (banner) {
      banner.style.display = "block";
      banner.style.background = "#DCFCE7";
      banner.style.color = "#16A34A";
      banner.textContent = `Configuration saved. Base URL: ${inp.value}`;
    }
    this.checkBackendStatus();
  }
}
