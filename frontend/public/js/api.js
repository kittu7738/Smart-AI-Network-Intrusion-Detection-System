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
}

// Export singleton to global scope for application access
window.apiService = new ApiService();
