/**
 * Smart AI NIDS - Dashboard Application Controller
 * 
 * Orchestrates API communication, 3D visualization triggers, 13-class analytics,
 * metrics state, recent detections logging, and interactive testing playground.
 * 
 * Zero simulated / fake detection data. All metrics and detections derive
 * exclusively from real FastAPI / UnifiedNIDS backend responses.
 */

document.addEventListener("DOMContentLoaded", () => {
  const app = new DashboardController();
  app.init();
});

class DashboardController {
  constructor() {
    this.api = window.apiService;
    this.pipeline3d = null;
    this.chart = null;

    // Metrics State (starts at zero / waiting for live traffic)
    this.metrics = {
      packetsAnalyzed: 0,
      threatsDetected: 0,
      benignCount: 0,
      threatRate: 0.0,
      currentThreatLevel: "WAITING",
      activeSpecialist: "Idle",
      isLiveTraffic: false,
    };

    // Session-only Detection History
    this.detections = [];

    // Frozen 13-Class Canonical Taxonomy Specification
    this.canonicalTaxonomy = [
      { id: 0,  name: "Benign",            severity: "benign" },
      { id: 1,  name: "DDoS",              severity: "critical" },
      { id: 2,  name: "DoS",               severity: "critical" },
      { id: 3,  name: "Botnet",            severity: "critical" },
      { id: 4,  name: "Infiltration",      severity: "critical" },
      { id: 5,  name: "Brute Force",       severity: "high" },
      { id: 6,  name: "Web Attack",        severity: "high" },
      { id: 7,  name: "DNS Spoofing",      severity: "suspicious" },
      { id: 8,  name: "IP Spoofing",       severity: "high" },
      { id: 9,  name: "ARP Spoofing",      severity: "high" },
      { id: 10, name: "Recon / Port Scan", severity: "suspicious" },
      { id: 11, name: "MITM",              severity: "critical" },
      { id: 12, name: "DNS Tunneling",     severity: "high" },
    ];

    this.canonicalClasses = this.canonicalTaxonomy.map((c) => c.name);
    this.canonicalClassCounts = new Array(13).fill(0);
  }

  async init() {
    // 1. Render 13-Class Canonical Grid
    this.renderCanonicalGrid();

    // 2. Initialize 3D Cyber Topology Visualizer
    try {
      this.pipeline3d = new Pipeline3D("pipeline3d-canvas-container");
    } catch (e) {
      console.warn("Pipeline3D initialization failed:", e);
    }

    // 3. Initialize 13-Class Analytics Chart
    this.initAnalyticsChart();

    // 4. Bind UI Controls
    this.bindEvents();

    // 5. Check Backend Health & Load Model Catalog
    await this.checkBackendStatus();
    await this.loadModelCatalog();

    // 6. Render Initial Metrics State
    this.updateMetricsUI();
  }

  /**
   * Render the dedicated 13-class canonical detection panel cards.
   */
  renderCanonicalGrid() {
    const container = document.getElementById("canonical-grid");
    if (!container) return;

    container.innerHTML = "";
    this.canonicalTaxonomy.forEach((cls) => {
      const card = document.createElement("div");
      card.className = "canonical-card";
      card.id = `canonical-card-${cls.id}`;

      const sevClass = `severity-${cls.severity}`;
      const count = this.canonicalClassCounts[cls.id];

      card.innerHTML = `
        <div class="canonical-card-header">
          <span class="canonical-id-badge">[${cls.id}]</span>
          <span class="severity-pill ${sevClass}">${cls.severity}</span>
        </div>
        <div class="canonical-name">${cls.name}</div>
        <div class="canonical-meta">
          <span>Detections:</span>
          <span id="canonical-count-${cls.id}" class="canonical-count ${count > 0 ? "has-detections" : ""}">${count}</span>
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * Update count and visual highlight on a canonical class card.
   */
  updateCanonicalGrid(classId) {
    const countEl = document.getElementById(`canonical-count-${classId}`);
    const cardEl = document.getElementById(`canonical-card-${classId}`);
    if (countEl) {
      const count = this.canonicalClassCounts[classId];
      countEl.textContent = count;
      countEl.className = `canonical-count ${count > 0 ? "has-detections" : ""}`;
    }
    if (cardEl) {
      cardEl.classList.add("active-verdict");
      setTimeout(() => cardEl.classList.remove("active-verdict"), 1500);
    }
  }

  /**
   * Query GET /health and update status badges & overview cards.
   */
  async checkBackendStatus() {
    const statusDot = document.getElementById("backend-status-dot");
    const statusText = document.getElementById("backend-status-text");
    const engineBadge = document.getElementById("engine-readiness-badge");
    const systemVal = document.getElementById("metric-system-status");
    const systemSub = document.getElementById("metric-system-sub");
    const unifiedVal = document.getElementById("metric-unified-status");
    const unifiedSub = document.getElementById("metric-unified-sub");

    const t0 = performance.now();
    try {
      const health = await this.api.getHealth();
      const latency = Math.round(performance.now() - t0);

      if (statusDot && statusText) {
        statusDot.className = "status-dot";
        document.getElementById("backend-status-badge").className = "badge badge-status-online";
        statusText.textContent = "ONLINE";
      }
      if (engineBadge) {
        engineBadge.textContent = health.engine_ready ? "UnifiedNIDS: Ready" : "UnifiedNIDS: Initializing";
      }
      if (systemVal) {
        systemVal.textContent = "CONNECTED";
        systemVal.style.color = "var(--status-benign)";
      }
      if (systemSub) {
        systemSub.textContent = `FastAPI v${health.version || "1.0.0"} (${latency}ms)`;
      }
      if (unifiedVal) {
        unifiedVal.textContent = health.engine_ready ? "OPERATIONAL" : "INITIALIZING";
        unifiedVal.style.color = health.engine_ready ? "var(--accent-cyan)" : "var(--status-medium)";
      }
      if (unifiedSub) {
        unifiedSub.textContent = "13-Class Canonical Engine";
      }
    } catch (err) {
      if (statusDot && statusText) {
        document.getElementById("backend-status-badge").className = "badge badge-status-offline";
        statusText.textContent = "OFFLINE";
      }
      if (engineBadge) {
        engineBadge.textContent = "UnifiedNIDS: Offline";
      }
      if (systemVal) {
        systemVal.textContent = "OFFLINE";
        systemVal.style.color = "var(--status-critical)";
      }
      if (systemSub) {
        systemSub.textContent = "FastAPI Backend Service";
      }
      if (unifiedVal) {
        unifiedVal.textContent = "UNAVAILABLE";
        unifiedVal.style.color = "var(--status-critical)";
      }
      if (unifiedSub) {
        unifiedSub.textContent = "Connection Refused";
      }
    }
  }

  /**
   * Query GET /models and render specialist models catalog.
   */
  async loadModelCatalog() {
    const container = document.getElementById("specialists-grid");
    const specStatusVal = document.getElementById("metric-specialist-status");
    const specCountBadge = document.getElementById("specialists-count-badge");

    if (!container) return;

    try {
      const catalog = await this.api.getModels();
      container.innerHTML = "";

      const specEntries = Object.entries(catalog.specialists);
      const totalSpecs = specEntries.length;

      if (specStatusVal) {
        specStatusVal.textContent = `${totalSpecs} / 5`;
        specStatusVal.style.color = "var(--accent-blue)";
      }
      if (specCountBadge) {
        specCountBadge.textContent = `Specialists: ${totalSpecs} Ready`;
      }

      specEntries.forEach(([specId, detail]) => {
        const card = document.createElement("div");
        card.className = "specialist-card";
        
        const tags = (detail.canonical_classes || [])
          .map((c) => `<span class="tag-class">${c}</span>`)
          .join("");

        card.innerHTML = `
          <div class="specialist-title">
            <span>${specId}</span>
            <span style="font-size: 0.7rem; color: #34d399; font-family: var(--font-mono);">&bull; Ready</span>
          </div>
          <div class="specialist-desc">${detail.description}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 0.3rem;">
            Model: ${detail.model_name || "Optimized Classifier"} &bull; Features: ${detail.feature_count ?? "Dynamic Auto-Routed"}
          </div>
          <div class="specialist-tags">${tags}</div>
        `;
        container.appendChild(card);
      });
    } catch (err) {
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; padding: 1rem;">Unable to load model catalog — ensure the FastAPI service is running.</div>`;
      if (specStatusVal) {
        specStatusVal.textContent = "0 / 5";
        specStatusVal.style.color = "var(--text-muted)";
      }
      if (specCountBadge) {
        specCountBadge.textContent = "Specialists: Offline";
      }
    }
  }

  /**
   * Initialize the 13-class posterior distribution chart.
   */
  initAnalyticsChart() {
    const ctx = document.getElementById("analyticsChart");
    if (!ctx || typeof Chart === "undefined") return;

    const colors = [
      "#10b981", "#ef4444", "#f43f5e", "#a855f7", "#f59e0b",
      "#f97316", "#fb923c", "#eab308", "#f97316",
      "#d946ef", "#06b6d4", "#3b82f6", "#8b5cf6"
    ];

    this.chart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: this.canonicalClasses,
        datasets: [{
          label: "Class Posterior Probability",
          data: new Array(13).fill(0.0),
          backgroundColor: colors.map((c) => c + "cc"),
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 4,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ` Probability: ${(ctx.parsed.x * 100).toFixed(2)}%`
            }
          }
        },
        scales: {
          x: {
            min: 0,
            max: 1.0,
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: {
              color: "#94a3b8",
              font: { family: "monospace", size: 10 },
              callback: (val) => `${(val * 100).toFixed(0)}%`
            }
          },
          y: {
            grid: { display: false },
            ticks: {
              color: "#f8fafc",
              font: { family: "monospace", size: 11 }
            }
          }
        }
      }
    });
  }

  updateAnalyticsChart(probabilities) {
    if (!this.chart || !Array.isArray(probabilities) || probabilities.length !== 13) return;
    this.chart.data.datasets[0].data = probabilities;
    this.chart.update();
  }

  bindEvents() {
    // 1. Reset 3D Camera View
    const resetBtn = document.getElementById("btn-reset-cam");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        if (this.pipeline3d) this.pipeline3d.resetCamera();
      });
    }

    // 2. Reconnect Backend Button
    const reconnectBtn = document.getElementById("btn-reconnect");
    if (reconnectBtn) {
      reconnectBtn.addEventListener("click", async () => {
        reconnectBtn.classList.add("btn-loading");
        await this.checkBackendStatus();
        await this.loadModelCatalog();
        reconnectBtn.classList.remove("btn-loading");
      });
    }

    // 3. Tab Navigation
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach((btn) => {
      btn.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach((p) => (p.style.display = "none"));

        btn.classList.add("active");
        const targetId = btn.getAttribute("data-target");
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.style.display = "block";
      });
    });

    // 4. Preset Attack Injector Buttons
    document.querySelectorAll(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const payloadStr = btn.getAttribute("data-payload");
        if (payloadStr) {
          try {
            const payload = JSON.parse(payloadStr);
            btn.classList.add("btn-loading");
            await this.handleSinglePrediction(payload);
            btn.classList.remove("btn-loading");
          } catch (e) {
            console.error("Malformed preset payload:", e);
            btn.classList.remove("btn-loading");
          }
        }
      });
    });

    // 5. Custom JSON Send Button
    const sendCustomBtn = document.getElementById("btn-send-custom");
    if (sendCustomBtn) {
      sendCustomBtn.addEventListener("click", async () => {
        const textarea = document.getElementById("custom-payload-json");
        const errorBox = document.getElementById("custom-json-error");
        errorBox.textContent = "";

        try {
          const payload = JSON.parse(textarea.value);
          sendCustomBtn.classList.add("btn-loading");
          sendCustomBtn.textContent = "Classifying...";
          await this.handleSinglePrediction(payload);
        } catch (err) {
          errorBox.textContent = `JSON Error: ${err.message}`;
        } finally {
          sendCustomBtn.classList.remove("btn-loading");
          sendCustomBtn.textContent = "Classify via POST /predict";
        }
      });
    }

    // 6. Batch Send Button
    const sendBatchBtn = document.getElementById("btn-send-batch");
    if (sendBatchBtn) {
      sendBatchBtn.addEventListener("click", async () => {
        const textarea = document.getElementById("batch-payload-json");
        const errorBox = document.getElementById("batch-json-error");
        errorBox.textContent = "";

        try {
          const batch = JSON.parse(textarea.value);
          sendBatchBtn.classList.add("btn-loading");
          sendBatchBtn.textContent = "Executing Batch...";
          await this.handleBatchPrediction(batch);
        } catch (err) {
          errorBox.textContent = `Batch Error: ${err.message}`;
        } finally {
          sendBatchBtn.classList.remove("btn-loading");
          sendBatchBtn.textContent = "Execute POST /predict/batch";
        }
      });
    }

    // 7. Settings Modal
    const settingsBtn = document.getElementById("btn-settings");
    const modal = document.getElementById("settings-modal");
    const closeBtn = document.getElementById("btn-close-modal");
    const saveUrlBtn = document.getElementById("btn-save-api-url");
    const urlInput = document.getElementById("api-base-url-input");

    if (settingsBtn && modal) {
      settingsBtn.addEventListener("click", () => {
        if (urlInput) urlInput.value = this.api.getBaseUrl();
        modal.style.display = "flex";
      });
    }
    if (closeBtn && modal) {
      closeBtn.addEventListener("click", () => (modal.style.display = "none"));
    }
    if (saveUrlBtn && modal && urlInput) {
      saveUrlBtn.addEventListener("click", async () => {
        this.api.setBaseUrl(urlInput.value);
        modal.style.display = "none";
        await this.checkBackendStatus();
        await this.loadModelCatalog();
      });
    }
  }

  /**
   * Execute POST /predict and update all dashboard components with real API results.
   */
  async handleSinglePrediction(payload) {
    const banner = document.getElementById("live-result-banner");
    const resultClass = document.getElementById("result-predicted-class");
    const resultConf = document.getElementById("result-confidence");
    const resultSpec = document.getElementById("result-specialist");
    const resultId = document.getElementById("result-canonical-id");

    try {
      const res = await this.api.predict(payload);

      // 1. Update Metrics
      this.metrics.packetsAnalyzed++;
      this.metrics.isLiveTraffic = true;
      this.metrics.activeSpecialist = res.specialist;

      if (res.predicted_class_id === 0) {
        this.metrics.benignCount++;
      } else {
        this.metrics.threatsDetected++;
      }
      this.metrics.threatRate = (this.metrics.threatsDetected / this.metrics.packetsAnalyzed) * 100;
      this.metrics.currentThreatLevel = this.deriveThreatLevel(res.predicted_class_id, res.confidence);

      this.canonicalClassCounts[res.predicted_class_id]++;
      this.updateMetricsUI();
      this.updateCanonicalGrid(res.predicted_class_id);

      // 2. Dispatch 3D Particle
      if (this.pipeline3d) {
        this.pipeline3d.dispatchPacket(res.specialist, res.predicted_class_id, res.confidence);
      }

      // 3. Update Result Banner
      if (banner) {
        banner.style.display = "block";
        if (resultClass) resultClass.textContent = res.predicted_class;
        if (resultConf) resultConf.textContent = `Confidence: ${(res.confidence * 100).toFixed(1)}%`;
        if (resultSpec) resultSpec.textContent = `Specialist: ${res.specialist}`;
        if (resultId) resultId.textContent = `Canonical ID: ${res.predicted_class_id}`;

        if (resultClass) {
          resultClass.style.color = res.predicted_class_id === 0 ? "var(--status-benign)" : "var(--status-critical)";
        }
      }

      // 4. Update 13-Class Analytics Chart
      if (res.probabilities) {
        this.updateAnalyticsChart(res.probabilities);
      }

      // 5. Add to Recent Detections
      const inputSummary = payload.query ? `DNS: ${payload.query}` : `Flow (${res.specialist})`;
      this.addDetectionRecord({
        timestamp: new Date().toLocaleTimeString(),
        source: inputSummary,
        predictedClass: res.predicted_class,
        canonicalId: res.predicted_class_id,
        confidence: res.confidence,
        specialist: res.specialist,
        severity: this.metrics.currentThreatLevel,
      });

    } catch (err) {
      alert(`Prediction Error: ${err.message}`);
    }
  }

  /**
   * Execute POST /predict/batch and render batch results table.
   */
  async handleBatchPrediction(batch) {
    try {
      const records = Array.isArray(batch) ? batch : batch.records;
      if (!records || records.length === 0) {
        throw new Error("Batch cannot be empty. At least one flow record is required.");
      }

      const res = await this.api.predictBatch(records);

      // Update metrics for every evaluated record
      res.predictions.forEach((pred, idx) => {
        this.metrics.packetsAnalyzed++;
        this.metrics.isLiveTraffic = true;
        this.metrics.activeSpecialist = pred.specialist;

        if (pred.predicted_class_id === 0) {
          this.metrics.benignCount++;
        } else {
          this.metrics.threatsDetected++;
        }
        this.canonicalClassCounts[pred.predicted_class_id]++;
        this.updateCanonicalGrid(pred.predicted_class_id);

        // Dispatch 3D particle for the first few items
        if (idx < 5 && this.pipeline3d) {
          setTimeout(() => {
            this.pipeline3d.dispatchPacket(pred.specialist, pred.predicted_class_id, pred.confidence);
          }, idx * 350);
        }

        // Add to recent detections table
        this.addDetectionRecord({
          timestamp: new Date().toLocaleTimeString(),
          source: `Batch #${idx + 1} (${pred.specialist})`,
          predictedClass: pred.predicted_class,
          canonicalId: pred.predicted_class_id,
          confidence: pred.confidence,
          specialist: pred.specialist,
          severity: this.deriveThreatLevel(pred.predicted_class_id, pred.confidence),
        });
      });

      this.metrics.threatRate = (this.metrics.threatsDetected / this.metrics.packetsAnalyzed) * 100;
      this.updateMetricsUI();

      if (res.predictions.length > 0 && res.predictions[0].probabilities) {
        this.updateAnalyticsChart(res.predictions[0].probabilities);
      }

      // Render Batch Results Table
      const resultsContainer = document.getElementById("batch-results-container");
      const resultsTitle = document.getElementById("batch-results-title");
      const resultsSpec = document.getElementById("batch-results-spec");
      const tbody = document.getElementById("batch-table-body");

      if (resultsContainer && tbody) {
        tbody.innerHTML = "";
        res.predictions.forEach((pred, idx) => {
          const sev = this.deriveThreatLevel(pred.predicted_class_id, pred.confidence);
          const sevClass = `severity-${sev.toLowerCase()}`;
          const row = document.createElement("tr");
          row.innerHTML = `
            <td>#${idx + 1}</td>
            <td><span class="canonical-id-badge">[${pred.predicted_class_id}]</span></td>
            <td style="font-weight: 600; color: var(--text-primary);">${pred.predicted_class}</td>
            <td>${(pred.confidence * 100).toFixed(1)}%</td>
            <td><span class="tag-class">${pred.specialist}</span></td>
            <td><span class="severity-pill ${sevClass}">${sev}</span></td>
          `;
          tbody.appendChild(row);
        });

        resultsContainer.style.display = "block";
        if (resultsTitle) resultsTitle.textContent = `Batch Evaluated (${res.count} records)`;
        if (resultsSpec) resultsSpec.textContent = `Specialist: ${res.specialist}`;
      }

    } catch (err) {
      alert(`Batch Classification Error: ${err.message}`);
    }
  }

  deriveThreatLevel(classId, confidence) {
    if (classId === 0) return "BENIGN";
    if ([1, 2, 3, 4, 11].includes(classId)) {
      return confidence > 0.8 ? "CRITICAL" : "HIGH";
    }
    if ([5, 6, 8, 9, 12].includes(classId)) {
      return "HIGH";
    }
    return "SUSPICIOUS";
  }

  addDetectionRecord(rec) {
    this.detections.unshift(rec);
    if (this.detections.length > 30) this.detections.pop();

    const tbody = document.getElementById("detections-table-body");
    if (!tbody) return;

    // Remove empty placeholder row if present
    if (this.detections.length === 1 && tbody.children.length === 1 && tbody.children[0].children.length === 1) {
      tbody.innerHTML = "";
    }

    const row = document.createElement("tr");
    const isBenign = rec.canonicalId === 0;
    const severityColor = isBenign ? "var(--status-benign)" : "var(--status-critical)";

    row.innerHTML = `
      <td>${rec.timestamp}</td>
      <td style="color: var(--text-primary); font-weight: 500;">${rec.source}</td>
      <td style="color: ${severityColor}; font-weight: 700;">${rec.predictedClass} [ID ${rec.canonicalId}]</td>
      <td>${(rec.confidence * 100).toFixed(1)}%</td>
      <td><span class="tag-class">${rec.specialist}</span></td>
      <td style="color: ${severityColor}; font-weight: 600;">${rec.severity}</td>
      <td><span style="color: #34d399;">PROCESSED</span></td>
    `;

    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 30) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  updateMetricsUI() {
    const elTrafficVal = document.getElementById("metric-traffic-status");
    const elLiveIndicator = document.getElementById("metric-status-sub");
    const elDetectionVal = document.getElementById("metric-threat-level");
    const elDetectionSub = document.getElementById("metric-detection-sub");

    if (!this.metrics.isLiveTraffic) {
      if (elTrafficVal) elTrafficVal.textContent = "WAITING";
      if (elLiveIndicator) elLiveIndicator.textContent = "Waiting for live traffic";
      if (elDetectionVal) {
        elDetectionVal.textContent = "WAITING";
        elDetectionVal.className = "metric-value threat-low";
      }
      if (elDetectionSub) elDetectionSub.textContent = "No detections yet";
      return;
    }

    if (elTrafficVal) elTrafficVal.textContent = `${this.metrics.packetsAnalyzed.toLocaleString()} Flows`;
    if (elLiveIndicator) elLiveIndicator.textContent = `Active: ${this.metrics.activeSpecialist}`;
    if (elDetectionVal) {
      elDetectionVal.textContent = `${this.metrics.threatsDetected} Threats`;
      elDetectionVal.className = this.metrics.threatsDetected > 0 ? "metric-value" : "metric-value threat-low";
      if (this.metrics.threatsDetected > 0) {
        elDetectionVal.style.color = "var(--status-critical)";
      }
    }
    if (elDetectionSub) {
      elDetectionSub.textContent = `${this.metrics.threatRate.toFixed(1)}% malicious (${this.metrics.benignCount} Benign)`;
    }
  }
}
