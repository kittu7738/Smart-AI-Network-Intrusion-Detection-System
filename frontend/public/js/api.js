/**
 * Smart AI NIDS - API Service Layer
 * 
 * Provides unified HTTP client functions to interact with the FastAPI backend.
 * Endpoints:
 * - GET  /health
 * - GET  /models
 * - POST /predict
 * - POST /predict/batch
 * 
 * Centralizes base URL configuration, timeouts, error parsing, and security validation.
 */

class ApiService {
  constructor() {
    this._defaultUrl = "http://localhost:8000";
  }

  /**
   * Resolve the active API base URL.
   * Priority: window.ENV.VITE_API_BASE_URL -> window.SAI_CONFIG -> localStorage -> default localhost.
   */
  getBaseUrl() {
    if (typeof window !== "undefined") {
      // If deployed in an all-in-one environment (e.g. Render / Railway serving both frontend & backend)
      if (window.location && window.location.origin && window.location.protocol.startsWith("http")) {
        const host = window.location.hostname;
        if (!host.includes("localhost") && !host.includes("127.0.0.1") && !host.includes("vercel.app")) {
          const stored = localStorage.getItem("VITE_API_BASE_URL");
          if (stored && stored.trim()) return stored.trim().replace(/\/+$/, "");
          return window.location.origin;
        }
      }

      if (window.ENV && window.ENV.VITE_API_BASE_URL) {
        return window.ENV.VITE_API_BASE_URL.replace(/\/+$/, "");
      }
      if (window.SAI_CONFIG && window.SAI_CONFIG.API_BASE_URL) {
        return window.SAI_CONFIG.API_BASE_URL.replace(/\/+$/, "");
      }
      const stored = localStorage.getItem("VITE_API_BASE_URL") || localStorage.getItem("SAI_API_BASE_URL");
      if (stored && stored.trim()) {
        return stored.trim().replace(/\/+$/, "");
      }
    }
    return this._defaultUrl;
  }

  /**
   * Update the active API base URL in localStorage.
   * @param {string} url 
   */
  setBaseUrl(url) {
    if (!url || !url.trim()) {
      localStorage.removeItem("VITE_API_BASE_URL");
      localStorage.removeItem("SAI_API_BASE_URL");
    } else {
      const cleanUrl = url.trim().replace(/\/+$/, "");
      localStorage.setItem("VITE_API_BASE_URL", cleanUrl);
      localStorage.setItem("SAI_API_BASE_URL", cleanUrl);
    }
  }

  /**
   * Generic fetch wrapper with timeout and standardized error handling.
   * @param {string} endpoint 
   * @param {object} options 
   * @param {number} timeoutMs 
   */
  async _request(endpoint, options = {}, timeoutMs = 10000) {
    const url = `${this.getBaseUrl()}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const defaultHeaders = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...(options.headers || {}),
      },
      signal: controller.signal,
    };

    try {
      const response = await fetch(url, config);
      clearTimeout(timeoutId);

      let data = null;
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        data = await response.json();
      } else {
        const text = await response.text();
        data = { detail: text || `HTTP ${response.status} ${response.statusText}` };
      }

      if (!response.ok) {
        const errorMessage = data && data.detail ? data.detail : `HTTP Error ${response.status}`;
        const error = new Error(errorMessage);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        const timeoutError = new Error(`Request timed out after ${timeoutMs / 1000}s while contacting backend.`);
        timeoutError.status = 504;
        throw timeoutError;
      }
      if (!err.status) {
        const networkError = new Error("Backend unavailable — start the FastAPI service at " + this.getBaseUrl());
        networkError.status = 0;
        networkError.originalError = err;
        throw networkError;
      }
      throw err;
    }
  }

  /**
   * GET /health
   * Check backend service status, version, and model readiness.
   */
  async getHealth() {
    return this._request("/health", { method: "GET" }, 5000);
  }

  /**
   * GET /models
   * Retrieve catalog of 5 specialist models and the frozen 13-class canonical taxonomy.
   */
  async getModels() {
    return this._request("/models", { method: "GET" }, 5000);
  }

  /**
   * POST /predict
   * Execute unified inference on a single feature dictionary or raw DNS query.
   * @param {object} payload - Either { features: {...}, specialist: "auto" } or flat feature dict.
   */
  async predict(payload) {
    if (!payload || typeof payload !== "object") {
      throw new Error("Prediction payload must be a non-empty object.");
    }
    return this._request("/predict", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  /**
   * POST /predict/batch
   * Execute inference on multiple network records.
   * @param {Array<object>} records - Array of feature dictionaries.
   * @param {string} specialist - Optional specialist name or 'auto'.
   */
  async predictBatch(records, specialist = "auto") {
    if (!Array.isArray(records) || records.length === 0) {
      throw new Error("Batch payload must be a non-empty array of records.");
    }
    return this._request("/predict/batch", {
      method: "POST",
      body: JSON.stringify({ records, specialist }),
    });
  }

  /**
   * GET /sensor/status
   * Retrieve operational status and telemetry counters of the live network sensor.
   */
  async getSensorStatus() {
    return this._request("/sensor/status", { method: "GET" }, 5000);
  }

  /**
   * GET /sensor/events
   * Retrieve stream of live network flows and alerts captured by the sensor.
   * @param {number} limit 
   */
  async getSensorEvents(limit = 50) {
    return this._request(`/sensor/events?limit=${limit}`, { method: "GET" }, 5000);
  }

  /**
   * GET /compare/metrics
   * Retrieve full verified comparative evaluation artifacts and reconciled metrics.
   */
  async getComparativeMetrics() {
    return this._request("/compare/metrics", { method: "GET" }, 10000);
  }

  /**
   * GET /suricata/status
   * Retrieve installation, version, and signature coverage metadata for Suricata.
   */
  async getSuricataStatus() {
    return this._request("/suricata/status", { method: "GET" }, 8000);
  }

  /**
   * GET /compare/sample
   * Run head-to-head comparison on genuine benchmark PCAP.
   */
  async runComparisonSample() {
    return this._request("/compare/sample", { method: "GET" }, 30000);
  }

  /**
   * POST /compare/pcap
   * Upload and evaluate a PCAP/PCAPNG file through both Suricata and Smart AI-NIDS.
   */
  async runComparisonPcap(file) {
    const formData = new FormData();
    formData.append("file", file);
    const url = `${this.getBaseUrl()}/compare/pcap`;
    const response = await fetch(url, {
      method: "POST",
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: "PCAP comparison failed" }));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }
    return response.json();
  }
}

// Export singleton to global scope for application access
window.apiService = new ApiService();
