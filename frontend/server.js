/**
 * Smart AI NIDS - Frontend Web Server
 * 
 * Lightweight standalone HTTP server for hosting the NIDS dashboard.
 * Uses native Node.js standard library (http, fs, path) with zero external runtime dependencies.
 * Easily deployable to Vercel, Render, Heroku, or any cloud/on-prem container.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

const server = http.createServer((req, res) => {
  // Normalize request URL
  let safePath = path.normalize(req.url.split("?")[0]);
  if (safePath === "/" || safePath === "") {
    safePath = "/index.html";
  }

  // Dynamic environment configuration endpoint
  if (safePath === "/env.js") {
    const apiUrl = process.env.VITE_API_BASE_URL || "http://localhost:8000";
    res.writeHead(200, {
      "Content-Type": "application/javascript; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
    });
    res.end(`window.ENV = Object.assign(window.ENV || {}, { VITE_API_BASE_URL: ${JSON.stringify(apiUrl)} });\n`);
    return;
  }

  const filePath = path.join(PUBLIC_DIR, safePath);

  // Prevent path traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("403 Forbidden");
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for SPA routing
      const indexPath = path.join(PUBLIC_DIR, "index.html");
      fs.readFile(indexPath, (readErr, content) => {
        if (readErr) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          res.end("404 Not Found");
        } else {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(content);
        }
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("500 Internal Server Error");
      } else {
        res.writeHead(200, {
          "Content-Type": contentType,
          "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600",
        });
        res.end(content);
      }
    });
  });
});

server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  Smart AI NIDS Dashboard Running`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`📁 Static Directory: ${PUBLIC_DIR}`);
  console.log(`=======================================================`);
});
