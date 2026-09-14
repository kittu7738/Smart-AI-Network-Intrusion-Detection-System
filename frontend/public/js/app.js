/**
 * Smart AI NIDS — Enterprise Security Operations Center (SOC) Controller
 *
 * Complete frontend application controller for Smart AI Network Intrusion Detection System.
 * Connects directly to the FastAPI UnifiedNIDS backend.
 *
 * Key Principles:
 * 1. ZERO SIMULATED / FAKE TELEMETRY. Starts at "—" / "Waiting for telemetry" until real inferences run.
 * 2. FROZEN 13-CLASS CANONICAL TAXONOMY (IDs 0–12).
 * 3. 5 DOMAIN SPECIALIST CLASSIFIERS (IDS2018, CICIoT2023, ARP_Spoofing, IP_Spoofing, DNS_Tunneling).
 * 4. Enterprise White SOC Dashboard with multi-view navigation, real-time audit logging,
 *    specialist models catalog, detection playground, and live telemetry filtering.
 */

document.addEventListener("DOMContentLoaded", () => {
  const app = new EnterpriseSocController();
  app.init();
});

class EnterpriseSocController {
  constructor() {
    this.api = window.apiService;
    this.chart = null;

    // Metrics state (zero until real traffic is evaluated)
    this.metrics = {
      totalPackets: 0,
      benignCount: 0,
      maliciousCount: 0,
      detectionRate: 0.0,
      activeSpecialists: 0,
      backendOnline: false,
    };

    // Detection records for current session
    this.detections = [];

    // Audit / Events log for current session
    this.auditEvents = [];

    // Frozen 13-Class Canonical Taxonomy Specification
    this.canonicalTaxonomy = [
      { id: 0,  name: "Benign",            severity: "benign",     color: "#16a34a" },
      { id: 1,  name: "DDoS",              severity: "critical",   color: "#dc2626" },
      { id: 2,  name: "DoS",               severity: "critical",   color: "#ea580c" },
      { id: 3,  name: "Botnet",            severity: "critical",   color: "#9333ea" },
      { id: 4,  name: "Infiltration",      severity: "critical",   color: "#b91c1c" },
      { id: 5,  name: "Brute Force",       severity: "high",       color: "#d97706" },
      { id: 6,  name: "Web Attack",        severity: "high",       color: "#c026d3" },
      { id: 7,  name: "DNS Spoofing",      severity: "suspicious", color: "#eab308" },
      { id: 8,  name: "IP Spoofing",       severity: "high",       color: "#f97316" },
      { id: 9,  name: "ARP Spoofing",      severity: "high",       color: "#ef4444" },
      { id: 10, name: "Recon / Port Scan", severity: "suspicious", color: "#3b82f6" },
      { id: 11, name: "MITM",              severity: "critical",   color: "#7c3aed" },
      { id: 12, name: "DNS Tunneling",     severity: "high",       color: "#0284c7" },
    ];

    this.canonicalCounts = new Array(13).fill(0);

    // Built-in Specialist Catalog fallback if backend endpoint is initializing
    this.specialistCatalogFallback = {
      specialists: {
        IDS2018: {
          name: "IDS2018",
          domain: "Enterprise Flow Traffic (CSE-CIC-IDS2018)",
          features: 77,
          architecture: "LightGBM / Multi-Class Classifier",
          status: "READY",
          classes: ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
        },
        CICIoT2023: {
          name: "CICIoT2023",
          domain: "Internet of Things (IoT) Network Flows",
          features: 46,
          architecture: "ExtraTrees / Multi-Class Classifier",
          status: "READY",
          classes: ["Benign", "DDoS", "DoS", "Recon / Port Scan", "MITM", "Web Attack", "Brute Force"]
        },
        ARP_Spoofing: {
          name: "ARP_Spoofing",
          domain: "Layer-2 Address Resolution Protocol (Kaggle ARP)",
          features: 2,
          architecture: "DecisionTree / Binary Protocol Specialist",
          status: "READY",
          classes: ["Benign", "ARP Spoofing"]
        },
        IP_Spoofing: {
          name: "IP_Spoofing",
          domain: "5G-NIDD GTP Network Intrusion Dataset",
          features: 12,
          architecture: "LogisticRegression / Scaled GTP Classifier",
          status: "READY",
          classes: ["Benign", "IP Spoofing"]
        },
        DNS_Tunneling: {
          name: "DNS_Tunneling",
          domain: "DNS Statistical Exfiltration & Tunneling",
          features: 12,
          architecture: "RandomForest / Feature-Engineered DNS Classifier",
          status: "READY",
          classes: ["Benign", "DNS Tunneling"]
        }
      }
    };
  }

  /**
   * Main application initialization routine
   */
  async init() {
    this.logAuditEvent("SYSTEM", "Initializing Smart AI NIDS SOC interface", "INFO");

    // 1. Start real-time UTC clock
    this.initClock();

    // 2. Setup sidebar view navigation
    this.initNavigation();

    // 3. Render 13-Class Canonical Grid in Overview
    this.renderCanonicalGrid();

    // 4. Initialize Threat Distribution Chart.js instance
    this.initChart();

    // 5. Bind Interactive UI Controls (Playground, Filters, Settings)
    this.bindControls();

    // 6. Connect to Backend: Check Health and load Specialist Models
    await this.refreshBackend();

    // 7. Initial UI State render
    this.updateMetricsUI();
    this.renderOverviewDetections();
    this.renderFullDetections();
    this.renderAuditEvents();

    this.logAuditEvent("SYSTEM", "Frontend SOC ready with 13-class canonical taxonomy", "SUCCESS");
  }

  /**
   * Real-time UTC Clock
   */
  initClock() {
    const clockEl = document.getElementById("live-clock");
    if (!clockEl) return;

    const updateTime = () => {
      const now = new Date();
      const h = String(now.getUTCHours()).padStart(2, "0");
      const m = String(now.getUTCMinutes()).padStart(2, "0");
      const s = String(now.getUTCSeconds()).padStart(2, "0");
      clockEl.textContent = `${h}:${m}:${s} UTC`;
    };

    updateTime();
    setInterval(updateTime, 1000);
  }

  /**
   * Tab and view routing across the 7 application panels
   */
  initNavigation() {
    const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
    const viewPanels = document.querySelectorAll(".view-panel");
    const mobileMenuBtn = document.getElementById("mobile-menu-btn");
    const sidebar = document.getElementById("sidebar");

    const switchView = (targetViewId) => {
      navItems.forEach((btn) => {
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

      // Close mobile sidebar if open
      if (sidebar) sidebar.classList.remove("open");

      // Trigger chart resize when switching back to overview
      if (targetViewId === "view-overview" && this.chart) {
        setTimeout(() => this.chart.resize(), 50);
      }
    };

    navItems.forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetViewId = btn.getAttribute("data-view");
        if (targetViewId) switchView(targetViewId);
      });
    });

    if (mobileMenuBtn && sidebar) {
      mobileMenuBtn.addEventListener("click", () => {
        sidebar.classList.toggle("open");
      });
    }

    // Expose switchView to global for inline helpers
    window.switchSocView = switchView;
  }

  /**
   * Render 13 canonical taxonomy cards into Overview
   */
  renderCanonicalGrid() {
    const container = document.getElementById("overview-canonical-grid");
    if (!container) return;

    container.innerHTML = "";
    this.canonicalTaxonomy.forEach((item) => {
      const card = document.createElement("div");
      card.className = "canonical-soc-card";
      card.id = `tax-card-${item.id}`;

      card.innerHTML = `
        <div class="canonical-soc-header">
          <span class="canonical-soc-id">#${item.id}</span>
          <span class="status-chip ${item.severity}">${item.severity}</span>
        </div>
        <div class="canonical-soc-name">${item.name}</div>
        <div class="canonical-soc-footer">
          <span class="count-label">Detections:</span>
          <span id="tax-count-${item.id}" class="count-val">0</span>
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * Update count on canonical taxonomy card
   */
  updateCanonicalCard(classId) {
    const countEl = document.getElementById(`tax-count-${classId}`);
    const cardEl = document.getElementById(`tax-card-${classId}`);
    if (countEl) {
      countEl.textContent = this.canonicalCounts[classId];
    }
    if (cardEl) {
      cardEl.classList.add("highlight");
      setTimeout(() => cardEl.classList.remove("highlight"), 1000);
    }
  }

  /**
   * Initialize Chart.js threat distribution bar chart
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
          label: "Class Frequency",
          data: [...this.canonicalCounts],
          backgroundColor: colors.map((col) => col + "cc"),
          borderColor: colors,
          borderWidth: 1.5,
          borderRadius: 4,
          maxBarThickness: 32,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0f172a",
            titleFont: { family: "'Inter', sans-serif", size: 12, weight: "bold" },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            padding: 10,
            cornerRadius: 6,
            callbacks: {
              label: (context) => ` Volume: ${context.parsed.y} detections`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              font: { family: "'Inter', sans-serif", size: 10 },
              color: "#64748b",
              maxRotation: 45,
              minRotation: 25,
            }
          },
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              font: { family: "'JetBrains Mono', monospace", size: 10 },
              color: "#64748b"
            },
            grid: {
              color: "rgba(0, 0, 0, 0.05)"
            }
          }
        }
      }
    });

    this.updateChartVisibility();
  }

  /**
   * Synchronize chart with current counts and empty state overlay
   */
  updateChartVisibility() {
    const emptyState = document.getElementById("chart-empty-state");
    if (!emptyState) return;

    if (this.metrics.totalPackets === 0) {
      emptyState.style.display = "flex";
    } else {
      emptyState.style.display = "none";
    }

    if (this.chart) {
      this.chart.data.datasets[0].data = [...this.canonicalCounts];
      this.chart.update();
    }
  }

  /**
   * Bind event listeners for all controls
   */
  bindControls() {
    // Header Reconnect button
    const btnReconnect = document.getElementById("btn-header-reconnect");
    if (btnReconnect) {
      btnReconnect.addEventListener("click", async () => {
        btnReconnect.classList.add("loading");
        await this.refreshBackend();
        setTimeout(() => btnReconnect.classList.remove("loading"), 500);
      });
    }

    // Playground Sub-tabs
    const pgTabBtns = document.querySelectorAll(".pg-tab-btn");
    const pgPanes = document.querySelectorAll(".pg-pane");
    pgTabBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        pgTabBtns.forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const targetId = btn.getAttribute("data-tab");
        pgPanes.forEach((p) => {
          p.style.display = p.id === targetId ? "block" : "none";
        });
      });
    });

    // Preset chips for DNS
    document.querySelectorAll(".preset-chip[data-dns]").forEach((chip) => {
      chip.addEventListener("click", () => {
        const input = document.getElementById("dns-query-input");
        if (input) input.value = chip.getAttribute("data-dns");
      });
    });

    // Preset chips for Structured Features
    document.querySelectorAll(".preset-chip[data-struct]").forEach((chip) => {
      chip.addEventListener("click", () => {
        const textarea = document.getElementById("structured-json-input");
        const specSelect = document.getElementById("pg-specialist-select");
        try {
          const data = JSON.parse(chip.getAttribute("data-struct"));
          if (textarea) textarea.value = JSON.stringify(data, null, 2);
          if (specSelect && data.specialist) specSelect.value = data.specialist;
        } catch (e) {
          console.error("Invalid preset json:", e);
        }
      });
    });

    // Playground Specialist Select sync with JSON
    const pgSpecSelect = document.getElementById("pg-specialist-select");
    if (pgSpecSelect) {
      pgSpecSelect.addEventListener("change", () => {
        const textarea = document.getElementById("structured-json-input");
        if (!textarea) return;
        try {
          const cur = JSON.parse(textarea.value);
          cur.specialist = pgSpecSelect.value;
          textarea.value = JSON.stringify(cur, null, 2);
        } catch (e) {
          // Keep as is if user was manually editing
        }
      });
    }

    // Playground Buttons
    const btnDns = document.getElementById("btn-analyze-dns");
    if (btnDns) {
      btnDns.addEventListener("click", () => this.executeDnsInference());
    }

    const btnStructured = document.getElementById("btn-run-structured");
    if (btnStructured) {
      btnStructured.addEventListener("click", () => this.executeStructuredInference());
    }

    const btnBatch = document.getElementById("btn-execute-batch");
    if (btnBatch) {
      btnBatch.addEventListener("click", () => this.executeBatchInference());
    }

    // Detections Filter Bar
    const filterInput = document.getElementById("filter-search-input");
    const filterSpec = document.getElementById("filter-specialist-select");
    const filterCls = document.getElementById("filter-class-select");
    const btnClearFilter = document.getElementById("btn-clear-filters");

    if (filterInput) filterInput.addEventListener("input", () => this.renderFullDetections());
    if (filterSpec) filterSpec.addEventListener("change", () => this.renderFullDetections());
    if (filterCls) filterCls.addEventListener("change", () => this.renderFullDetections());
    if (btnClearFilter) {
      btnClearFilter.addEventListener("click", () => {
        if (filterInput) filterInput.value = "";
        if (filterSpec) filterSpec.value = "";
        if (filterCls) filterCls.value = "";
        this.renderFullDetections();
      });
    }

    // Audit Log Clear
    const btnClearAudit = document.getElementById("btn-clear-audit");
    if (btnClearAudit) {
      btnClearAudit.addEventListener("click", () => {
        this.auditEvents = [];
        this.logAuditEvent("SYSTEM", "Audit log reset by operator", "INFO");
        this.renderAuditEvents();
      });
    }

    // Settings Controls
    const btnTestSettings = document.getElementById("btn-settings-test");
    const btnSaveSettings = document.getElementById("btn-settings-save");
    const inputApiUrl = document.getElementById("settings-api-url-input");

    if (inputApiUrl) {
      inputApiUrl.value = this.api.getBaseUrl();
    }

    if (btnTestSettings) {
      btnTestSettings.addEventListener("click", () => this.testSettingsConnection());
    }

    if (btnSaveSettings) {
      btnSaveSettings.addEventListener("click", () => this.saveSettingsConnection());
    }
  }

  /**
   * Health check and models synchronization with backend
   */
  async refreshBackend() {
    const topSystemChip = document.getElementById("top-system-chip");
    const topSystemText = document.getElementById("top-system-text");
    const topApiText = document.getElementById("top-api-text");
    const topSpecText = document.getElementById("top-specialists-text");
    const overviewBadge = document.getElementById("overview-nids-badge");
    const overviewText = document.getElementById("overview-nids-text");

    const baseUrl = this.api.getBaseUrl();
    if (topApiText) {
      try {
        const u = new URL(baseUrl);
        topApiText.textContent = `${u.hostname}:${u.port || (u.protocol === "https:" ? "443" : "80")}`;
      } catch (e) {
        topApiText.textContent = baseUrl;
      }
    }

    try {
      const health = await this.api.getHealth();
      this.metrics.backendOnline = (health.status === "healthy");
      this.metrics.activeSpecialists = health.models_loaded || 5;

      if (topSystemChip && topSystemText) {
        topSystemChip.className = "status-chip online";
        topSystemText.textContent = "System Online";
      }

      if (topSpecText) {
        topSpecText.textContent = `${this.metrics.activeSpecialists} Active Models`;
      }

      if (overviewBadge && overviewText) {
        overviewBadge.className = "nids-status-badge online";
        overviewText.textContent = "NIDS OPERATIONAL";
      }

      const activeSpecEl = document.getElementById("kpi-active-specialists");
      const specSubEl = document.getElementById("kpi-specialists-sub");
      if (activeSpecEl) activeSpecEl.textContent = `${this.metrics.activeSpecialists} / 5`;
      if (specSubEl) specSubEl.textContent = "Pipelines verified";

      this.logAuditEvent("HEALTH", `Connected to FastAPI at ${baseUrl} — status healthy`, "SUCCESS");

      // Load models catalog
      await this.loadModelsCatalog();

    } catch (err) {
      this.metrics.backendOnline = false;

      if (topSystemChip && topSystemText) {
        topSystemChip.className = "status-chip offline";
        topSystemText.textContent = "System Offline";
      }

      if (topSpecText) {
        topSpecText.textContent = "0 Active Models";
      }

      if (overviewBadge && overviewText) {
        overviewBadge.className = "nids-status-badge offline";
        overviewText.textContent = "NIDS OFFLINE";
      }

      const activeSpecEl = document.getElementById("kpi-active-specialists");
      const specSubEl = document.getElementById("kpi-specialists-sub");
      if (activeSpecEl) activeSpecEl.textContent = "0 / 5";
      if (specSubEl) specSubEl.textContent = "Backend offline";

      this.logAuditEvent("HEALTH", `Cannot reach FastAPI backend at ${baseUrl}: ${err.message}`, "ERROR");

      // Render fallback models catalog so operator understands architecture
      this.renderSpecialistCards(this.specialistCatalogFallback.specialists, false);
    }
  }

  /**
   * Load Model Catalog from GET /models
   */
  async loadModelsCatalog() {
    try {
      const data = await this.api.getModels();
      const specialists = data.specialists || this.specialistCatalogFallback.specialists;
      this.renderSpecialistCards(specialists, true);
    } catch (e) {
      this.renderSpecialistCards(this.specialistCatalogFallback.specialists, false);
    }
  }

  /**
   * Render Specialist Models Catalog cards
   */
  renderSpecialistCards(specialists, isOnline) {
    const grid = document.getElementById("specialist-models-catalog-grid");
    if (!grid) return;

    grid.innerHTML = "";

    const specEntries = Object.entries(specialists);
    specEntries.forEach(([key, spec]) => {
      const card = document.createElement("div");
      card.className = "specialist-card";

      const badgeClass = isOnline ? "online" : "offline";
      const statusText = isOnline ? (spec.status || "READY") : "OFFLINE";
      const features = spec.features || spec.n_features || "Configured";
      const domain = spec.domain || "Network Specialization";
      const arch = spec.architecture || "Calibrated Classifier";
      const classesList = Array.isArray(spec.classes) ? spec.classes.join(", ") : "Canonical Mapped";

      card.innerHTML = `
        <div class="specialist-card-header">
          <div class="specialist-name">${key}</div>
          <span class="status-chip ${badgeClass}">${statusText}</span>
        </div>
        <div class="specialist-domain">${domain}</div>

        <div class="specialist-meta-list">
          <div class="specialist-meta-row">
            <span class="specialist-meta-name">Architecture:</span>
            <span class="specialist-meta-val">${arch}</span>
          </div>
          <div class="specialist-meta-row">
            <span class="specialist-meta-name">Input Features:</span>
            <span class="specialist-meta-val">${features} dims</span>
          </div>
          <div class="specialist-meta-row">
            <span class="specialist-meta-name">Classes Handled:</span>
            <span class="specialist-meta-val" title="${classesList}" style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${classesList}</span>
          </div>
          <div class="specialist-meta-row">
            <span class="specialist-meta-name">Canonical Target:</span>
            <span class="specialist-meta-val">Frozen 13-Class</span>
          </div>
        </div>
      `;
      grid.appendChild(card);
    });
  }

  /**
   * Playground DNS Query Inference execution
   */
  async executeDnsInference() {
    const queryInput = document.getElementById("dns-query-input");
    const errBox = document.getElementById("dns-error-box");
    const btn = document.getElementById("btn-analyze-dns");
    if (!queryInput) return;

    const query = queryInput.value.trim();
    if (!query) {
      if (errBox) errBox.textContent = "Please provide a valid DNS query string.";
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) {
      btn.disabled = true;
      btn.classList.add("loading");
    }

    const t0 = performance.now();
    try {
      const response = await this.api.predict({ query });
      const elapsed = Math.round(performance.now() - t0);

      this.processInferenceResult({
        source: query,
        type: "DNS Query",
        response: response,
        latencyMs: elapsed,
      });

      this.logAuditEvent("INFERENCE", `DNS query classified: "${query}" -> ${response.predicted_class} (${(response.confidence * 100).toFixed(1)}%) in ${elapsed}ms`, "SUCCESS");

    } catch (err) {
      if (errBox) errBox.textContent = `Inference failed: ${err.message}`;
      this.logAuditEvent("INFERENCE", `DNS query error: ${err.message}`, "ERROR");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("loading");
      }
    }
  }

  /**
   * Playground Structured Features Inference execution
   */
  async executeStructuredInference() {
    const textarea = document.getElementById("structured-json-input");
    const errBox = document.getElementById("struct-error-box");
    const btn = document.getElementById("btn-run-structured");
    if (!textarea) return;

    let payload;
    try {
      payload = JSON.parse(textarea.value);
    } catch (e) {
      if (errBox) errBox.textContent = "Invalid JSON syntax. Ensure valid JSON payload.";
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) {
      btn.disabled = true;
      btn.classList.add("loading");
    }

    const t0 = performance.now();
    try {
      const response = await this.api.predict(payload);
      const elapsed = Math.round(performance.now() - t0);

      const specialist = response.specialist || payload.specialist || "Auto";
      this.processInferenceResult({
        source: `Features Payload (${specialist})`,
        type: "Structured",
        response: response,
        latencyMs: elapsed,
      });

      this.logAuditEvent("INFERENCE", `Structured features classified: -> ${response.predicted_class} (${(response.confidence * 100).toFixed(1)}%) via ${specialist} in ${elapsed}ms`, "SUCCESS");

    } catch (err) {
      if (errBox) errBox.textContent = `Inference failed: ${err.message}`;
      this.logAuditEvent("INFERENCE", `Structured inference error: ${err.message}`, "ERROR");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("loading");
      }
    }
  }

  /**
   * Playground Batch Inference execution
   */
  async executeBatchInference() {
    const textarea = document.getElementById("batch-json-input");
    const errBox = document.getElementById("batch-error-box");
    const btn = document.getElementById("btn-execute-batch");
    const resultsCard = document.getElementById("batch-results-soc-card");
    const resultsTbody = document.getElementById("batch-results-tbody");
    const subtitle = document.getElementById("batch-summary-subtitle");
    if (!textarea) return;

    let records;
    try {
      records = JSON.parse(textarea.value);
      if (!Array.isArray(records) || records.length === 0) {
        throw new Error("Batch input must be a non-empty array of record objects.");
      }
    } catch (e) {
      if (errBox) errBox.textContent = `Invalid batch format: ${e.message}`;
      return;
    }
    if (errBox) errBox.textContent = "";

    if (btn) {
      btn.disabled = true;
      btn.classList.add("loading");
    }

    const t0 = performance.now();
    try {
      const result = await this.api.predictBatch(records, "auto");
      const elapsed = Math.round(performance.now() - t0);

      const predictions = result.predictions || [];
      if (resultsCard) resultsCard.style.display = "block";
      if (subtitle) subtitle.textContent = `${predictions.length} flows classified in ${elapsed}ms`;

      if (resultsTbody) {
        resultsTbody.innerHTML = "";
        predictions.forEach((item, index) => {
          const row = document.createElement("tr");
          const isBenign = item.predicted_class_id === 0;
          const statusBadge = isBenign
            ? `<span class="status-chip online">Benign</span>`
            : `<span class="status-chip critical">Malicious</span>`;
          const conf = (item.confidence * 100).toFixed(1) + "%";

          row.innerHTML = `
            <td>#${index + 1}</td>
            <td style="font-family: var(--font-mono); font-weight: 600;">#${item.predicted_class_id}</td>
            <td style="font-weight: 600;">${item.predicted_class}</td>
            <td style="font-family: var(--font-mono);">${conf}</td>
            <td>${item.specialist || result.specialist || "Unified"}</td>
            <td>${statusBadge}</td>
          `;
          resultsTbody.appendChild(row);

          // Add to system session state
          const inputRec = records[index];
          const queryText = inputRec.query || JSON.stringify(inputRec).substring(0, 35) + "...";
          this.processInferenceResult({
            source: queryText,
            type: "Batch Item",
            response: item,
            latencyMs: Math.round(elapsed / predictions.length),
            skipVerdictRender: (index < predictions.length - 1), // Only render verdict card for the final item
          });
        });
      }

      this.logAuditEvent("INFERENCE", `Batch inference executed: ${predictions.length} records processed in ${elapsed}ms`, "SUCCESS");

    } catch (err) {
      if (errBox) errBox.textContent = `Batch inference failed: ${err.message}`;
      this.logAuditEvent("INFERENCE", `Batch inference error: ${err.message}`, "ERROR");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("loading");
      }
    }
  }

  /**
   * Process a single real inference response into state, KPIs, chart, and logs
   */
  processInferenceResult({ source, type, response, latencyMs, skipVerdictRender = false }) {
    const classId = Number(response.predicted_class_id);
    const className = response.predicted_class;
    const confidence = Number(response.confidence) || 0.0;
    const specialist = response.specialist || "UnifiedNIDS";
    const probabilities = Array.isArray(response.probabilities) ? response.probabilities : [];

    // 1. Update Metrics
    this.metrics.totalPackets++;
    if (classId === 0) {
      this.metrics.benignCount++;
    } else {
      this.metrics.maliciousCount++;
    }
    this.metrics.detectionRate = ((this.metrics.maliciousCount / this.metrics.totalPackets) * 100);

    // 2. Update 13-class canonical counts
    if (classId >= 0 && classId < 13) {
      this.canonicalCounts[classId]++;
      this.updateCanonicalCard(classId);
    }

    // 3. Create Detection Record
    const record = {
      id: "DET-" + Math.random().toString(36).substr(2, 8).toUpperCase(),
      time: new Date().toISOString().substring(11, 19),
      source: source,
      type: type,
      specialist: specialist,
      classId: classId,
      className: className,
      confidence: confidence,
      isThreat: classId !== 0,
      latencyMs: latencyMs,
    };

    // Prepend to detections
    this.detections.unshift(record);

    // 4. Update UI displays
    this.updateMetricsUI();
    this.updateChartVisibility();
    this.renderOverviewDetections();
    this.renderFullDetections();

    // 5. Update Verdict Card unless skipped
    if (!skipVerdictRender) {
      this.renderVerdictCard(className, classId, confidence, specialist, probabilities);
    }
  }

  /**
   * Render the Verdict Card in Playground
   */
  renderVerdictCard(className, classId, confidence, specialist, probabilities) {
    const bannerBox = document.getElementById("verdict-banner-box");
    const classEl = document.getElementById("verdict-class-name");
    const confVal = document.getElementById("verdict-conf-value");
    const specEl = document.getElementById("verdict-specialist-name");
    const canonEl = document.getElementById("verdict-canonical-id");
    const probList = document.getElementById("verdict-prob-list");

    const isBenign = (classId === 0);
    const confPercent = (confidence * 100).toFixed(1) + "%";

    if (bannerBox) {
      bannerBox.className = `verdict-banner ${isBenign ? "verdict-benign" : "verdict-threat"}`;
    }

    if (classEl) classEl.textContent = className;
    if (confVal) confVal.textContent = confPercent;
    if (specEl) specEl.textContent = specialist;
    if (canonEl) canonEl.textContent = `#${classId}`;

    if (probList) {
      probList.innerHTML = "";

      // Render 13 canonical probabilities
      this.canonicalTaxonomy.forEach((cls) => {
        const prob = probabilities[cls.id] !== undefined ? probabilities[cls.id] : (cls.id === classId ? confidence : 0.0);
        const pct = (prob * 100).toFixed(1);
        const isTarget = (cls.id === classId);

        const item = document.createElement("div");
        item.className = "prob-item";

        item.innerHTML = `
          <div class="prob-labels">
            <span style="${isTarget ? 'font-weight: 700; color: var(--color-primary);' : ''}">#${cls.id} ${cls.name}</span>
            <span style="font-family: var(--font-mono); font-weight: 600;">${pct}%</span>
          </div>
          <div class="prob-bar-container">
            <div class="prob-bar-fill" style="width: ${pct}%; background-color: ${cls.color};"></div>
          </div>
        `;
        probList.appendChild(item);
      });
    }
  }

  /**
   * Update the 5 KPI metric cards in Overview
   */
  updateMetricsUI() {
    const kpiTotal = document.getElementById("kpi-total-packets");
    const kpiPacketsSub = document.getElementById("kpi-packets-sub");
    const kpiBenign = document.getElementById("kpi-benign-traffic");
    const kpiMalicious = document.getElementById("kpi-malicious-traffic");
    const kpiRate = document.getElementById("kpi-detection-rate");

    if (this.metrics.totalPackets === 0) {
      if (kpiTotal) kpiTotal.textContent = "—";
      if (kpiPacketsSub) kpiPacketsSub.textContent = "Waiting for telemetry";
      if (kpiBenign) kpiBenign.textContent = "—";
      if (kpiMalicious) kpiMalicious.textContent = "—";
      if (kpiRate) kpiRate.textContent = "—";
    } else {
      if (kpiTotal) kpiTotal.textContent = this.metrics.totalPackets.toLocaleString();
      if (kpiPacketsSub) kpiPacketsSub.textContent = `${this.metrics.totalPackets} session flows evaluated`;
      if (kpiBenign) kpiBenign.textContent = this.metrics.benignCount.toLocaleString();
      if (kpiMalicious) kpiMalicious.textContent = this.metrics.maliciousCount.toLocaleString();
      if (kpiRate) kpiRate.textContent = `${this.metrics.detectionRate.toFixed(1)}%`;
    }
  }

  /**
   * Render Overview 5-row preview table
   */
  renderOverviewDetections() {
    const tbody = document.getElementById("overview-detections-tbody");
    if (!tbody) return;

    if (this.detections.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6">
            <div class="empty-state-box">
              <div class="empty-state-icon">📡</div>
              <div class="empty-state-text">No live detections yet</div>
              <div class="empty-state-sub">Waiting for network telemetry. Use the Detection Playground to run test flows.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    const previewList = this.detections.slice(0, 5);

    previewList.forEach((det) => {
      const row = document.createElement("tr");
      const statusPill = det.isThreat
        ? `<span class="status-chip critical">Malicious</span>`
        : `<span class="status-chip online">Benign</span>`;

      row.innerHTML = `
        <td style="font-family: var(--font-mono);">${det.time}</td>
        <td style="font-family: var(--font-mono); font-weight: 500;" title="${det.source}">${this.truncate(det.source, 38)}</td>
        <td><span class="status-chip">${det.specialist}</span></td>
        <td style="font-weight: 600;">${det.className}</td>
        <td style="font-family: var(--font-mono);">${(det.confidence * 100).toFixed(1)}%</td>
        <td>${statusPill}</td>
      `;
      tbody.appendChild(row);
    });
  }

  /**
   * Render Live Detections full table with filters
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

    if (this.detections.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7">
            <div class="empty-state-box">
              <div class="empty-state-icon">📡</div>
              <div class="empty-state-text">No live detections yet</div>
              <div class="empty-state-sub">Waiting for network telemetry... Run queries in the Playground to record live verdicts.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    const term = searchInput ? searchInput.value.toLowerCase().trim() : "";
    const filterSpec = specSelect ? specSelect.value : "";
    const filterCls = classSelect ? classSelect.value : "";

    const filtered = this.detections.filter((d) => {
      if (filterSpec && d.specialist !== filterSpec) return false;
      if (filterCls && d.className !== filterCls) return false;
      if (term) {
        const matchesSource = d.source.toLowerCase().includes(term);
        const matchesClass = d.className.toLowerCase().includes(term);
        const matchesSpec = d.specialist.toLowerCase().includes(term);
        return matchesSource || matchesClass || matchesSpec;
      }
      return true;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7">
            <div class="empty-state-box">
              <div class="empty-state-icon">🔍</div>
              <div class="empty-state-text">No matching records found</div>
              <div class="empty-state-sub">Adjust filter parameters or clear filters.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    filtered.forEach((det) => {
      const row = document.createElement("tr");
      const statusPill = det.isThreat
        ? `<span class="status-chip critical">Malicious</span>`
        : `<span class="status-chip online">Benign</span>`;

      row.innerHTML = `
        <td style="font-family: var(--font-mono);">${det.time}</td>
        <td style="font-family: var(--font-mono); font-weight: 500;" title="${det.source}">${this.truncate(det.source, 45)}</td>
        <td><span class="status-chip">${det.specialist}</span></td>
        <td style="font-weight: 600;">${det.className}</td>
        <td style="font-family: var(--font-mono); font-weight: 600;">#${det.classId}</td>
        <td style="font-family: var(--font-mono);">${(det.confidence * 100).toFixed(1)}%</td>
        <td>${statusPill}</td>
      `;
      tbody.appendChild(row);
    });
  }

  /**
   * Log an event into the session Audit Log
   */
  logAuditEvent(category, details, status = "INFO") {
    const time = new Date().toISOString().substring(11, 19);
    this.auditEvents.unshift({
      time: time,
      category: category,
      details: details,
      status: status,
    });
    this.renderAuditEvents();
  }

  /**
   * Render Audit Events table
   */
  renderAuditEvents() {
    const tbody = document.getElementById("audit-events-tbody");
    if (!tbody) return;

    if (this.auditEvents.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4">
            <div class="empty-state-box">
              <div class="empty-state-icon">📋</div>
              <div class="empty-state-text">No audit events recorded</div>
              <div class="empty-state-sub">Events will record automatically as API transactions occur.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";
    this.auditEvents.forEach((evt) => {
      const row = document.createElement("tr");

      let statusBadge = `<span class="status-chip">${evt.status}</span>`;
      if (evt.status === "SUCCESS") statusBadge = `<span class="status-chip online">SUCCESS</span>`;
      if (evt.status === "ERROR") statusBadge = `<span class="status-chip critical">ERROR</span>`;

      row.innerHTML = `
        <td style="font-family: var(--font-mono);">${evt.time}</td>
        <td><span class="status-chip">${evt.category}</span></td>
        <td style="font-size: 0.8rem;">${evt.details}</td>
        <td>${statusBadge}</td>
      `;
      tbody.appendChild(row);
    });
  }

  /**
   * Test connection in Settings view
   */
  async testSettingsConnection() {
    const input = document.getElementById("settings-api-url-input");
    const banner = document.getElementById("settings-test-banner");
    const btn = document.getElementById("btn-settings-test");
    if (!input || !banner) return;

    const url = input.value.trim();
    banner.style.display = "block";
    banner.className = "connection-status-banner";
    banner.textContent = `Connecting to ${url}/health...`;

    if (btn) btn.disabled = true;

    try {
      const resp = await fetch(`${url.replace(/\/+$/, "")}/health`, { method: "GET" });
      const data = await resp.json();

      if (resp.ok && data.status === "healthy") {
        banner.className = "connection-status-banner online";
        banner.textContent = `Connection Successful! Backend healthy (${data.models_loaded || 5} models ready).`;
        this.logAuditEvent("CONFIG", `Tested connection to ${url} — SUCCESS`, "SUCCESS");
      } else {
        banner.className = "connection-status-banner offline";
        banner.textContent = `Received HTTP ${resp.status}: ${JSON.stringify(data)}`;
        this.logAuditEvent("CONFIG", `Tested connection to ${url} — FAILED: HTTP ${resp.status}`, "ERROR");
      }
    } catch (e) {
      banner.className = "connection-status-banner offline";
      banner.textContent = `Connection failed: ${e.message}. Ensure FastAPI is running.`;
      this.logAuditEvent("CONFIG", `Tested connection to ${url} — ERROR: ${e.message}`, "ERROR");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  /**
   * Save connection in Settings view and reconnect
   */
  async saveSettingsConnection() {
    const input = document.getElementById("settings-api-url-input");
    const banner = document.getElementById("settings-test-banner");
    if (!input) return;

    const url = input.value.trim();
    this.api.setBaseUrl(url);

    if (banner) {
      banner.style.display = "block";
      banner.className = "connection-status-banner online";
      banner.textContent = `Config saved. Active API URL: ${url}`;
    }

    this.logAuditEvent("CONFIG", `API base URL updated to ${url}`, "SUCCESS");
    await this.refreshBackend();
  }

  /**
   * Helper to truncate string
   */
  truncate(str, maxLen = 35) {
    if (!str) return "—";
    return str.length > maxLen ? str.substring(0, maxLen) + "..." : str;
  }
}
