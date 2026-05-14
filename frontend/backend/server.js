// const express = require("express");
// const cors = require("cors");
// const fs = require("fs");
// const path = require("path");

// const app = express();
// app.use(cors());
// app.use(express.json());

// const ROOT = path.join(__dirname, "..", "..");
// const TRACE_PATH = path.join(ROOT, "data", "traces.ndjson");
// const ASSET_PATH = path.join(ROOT, "data", "managed_assets.json");
// // How many lines from the end of traces.ndjson to read per request.
// // Clamp to between 1000 and 2000 to keep per-request latency bounded.
// const TRACE_TAIL_LINES = Math.max(1000, Math.min(2000, parseInt(process.env.TRACE_TAIL_LINES || "1500", 10)));

// function readJsonl(filePath) {
//   if (!fs.existsSync(filePath)) return [];
//   // default: read full file
//   try {
//     return fs
//       .readFileSync(filePath, "utf8")
//       .split("\n")
//       .map((line) => line.trim())
//       .filter(Boolean)
//       .map((line) => {
//         try {
//           return JSON.parse(line);
//         } catch {
//           return null;
//         }
//       })
//       .filter(Boolean);
//   } catch (e) {
//     return [];
//   }
// }

// // Read last N lines quickly using system tail when possible (faster for large files)
// function readJsonlTail(filePath, tailLines = TRACE_TAIL_LINES) {
//   if (!fs.existsSync(filePath)) return [];
//   // enforce safety bounds
//   tailLines = Math.max(1000, Math.min(2000, parseInt(tailLines || TRACE_TAIL_LINES, 10)));
//   try {
//     const { execSync } = require("child_process");
//     const out = execSync(`tail -n ${tailLines} ${filePath}`, { encoding: "utf8" });
//     return out
//       .split("\n")
//       .map((line) => line.trim())
//       .filter(Boolean)
//       .map((line) => {
//         try {
//           return JSON.parse(line);
//         } catch {
//           return null;
//         }
//       })
//       .filter(Boolean);
//   } catch (e) {
//     // fallback to full read if tail isn't available
//     return readJsonl(filePath);
//   }
// }

// function readAssets() {
//   if (!fs.existsSync(ASSET_PATH)) return [];
//   try {
//     return JSON.parse(fs.readFileSync(ASSET_PATH, "utf8"));
//   } catch {
//     return [];
//   }
// }

// // Serve recent raw logs (used by LiveFeed component)
// app.get("/api/logs/recent", (req, res) => {
//   const n = Math.max(1, Math.min(1000, parseInt(req.query.n || "50", 10)));
//   const LOG_PATH = path.join(ROOT, "data", "logs.ndjson");
//   const logs = readJsonl(LOG_PATH);
//   // return last n entries
//   res.json(logs.slice(-n));
// });

// // Simple polling endpoint for new logs (returns last 10 by default)
// app.get("/api/logs/new", (req, res) => {
//   const limit = Math.max(1, Math.min(500, parseInt(req.query.n || "10", 10)));
//   const LOG_PATH = path.join(ROOT, "data", "logs.ndjson");
//   const logs = readJsonl(LOG_PATH);
//   res.json(logs.slice(-limit));
// });

// function loadIncidents() {
//   return readJsonlTail(TRACE_PATH).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
// }

// function verdictColor(verdict) {
//   if (verdict === "malicious") return "malicious";
//   if (verdict === "suspicious") return "suspicious";
//   return "benign";
// }

// function formatIncident(trace) {
//   const raw = trace.raw_event || {};
//   const detection = trace.detection_result || {};
//   const planner = trace.planner_result || {};
//   const response = trace.response_result || {};
//   const traceId =
//     trace.trace_metadata?.trace_id ||
//     [trace.event_id, trace.trace_metadata?.logged_at || trace.trace_metadata?.processed_at || trace.timestamp]
//       .filter(Boolean)
//       .join(":");
//   return {
//     id: traceId,
//     sourceEventId: trace.event_id,
//     timestamp: trace.timestamp,
//     severity: verdictColor(detection.verdict),
//     headline: trace.story?.headline || `${raw.src_ip || "unknown"} -> ${raw.dest_ip || "unknown"}`,
//     summary: trace.story?.summary || "Incident processed by AutoSentry",
//     attackSource: raw.src_ip || "unknown",
//     targetAsset: trace.asset_context?.target_asset?.hostname || raw.dest_ip || "unknown",
//     classificationPath: `${planner.route || "skip"} -> ${detection.method || "rule"} -> ${response.action || "notify_operator"}`,
//     confidence: detection.confidence ?? 0,
//     verdict: detection.verdict || "benign",
//     priority: planner.priority || "low",
//     planner,
//     detection,
//     response,
//     rawEvent: raw,
//     normalizedFeatures: trace.normalized_features || {},
//     assetContext: trace.asset_context || {},
//     traceMetadata: trace.trace_metadata || {},
//   };
// }

// function buildOverview(incidents, assets) {
//   const malicious = incidents.filter((i) => i.verdict === "malicious").length;
//   const suspicious = incidents.filter((i) => i.verdict === "suspicious").length;
//   const benign = incidents.filter((i) => i.verdict === "benign").length;
//   const responses = incidents.filter((i) => i.response?.status && i.response.status !== "skipped");
//   const responseSuccess = responses.filter((i) => ["completed", "dry_run", "pending_remote_execution"].includes(i.response.status)).length;

//   const buckets = new Map();
//   incidents.slice().reverse().forEach((incident) => {
//     const bucketKey = new Date(incident.timestamp).toISOString().slice(0, 16);
//     if (!buckets.has(bucketKey)) {
//       buckets.set(bucketKey, { ts: bucketKey, malicious: 0, suspicious: 0, benign: 0 });
//     }
//     buckets.get(bucketKey)[incident.verdict] += 1;
//   });

//   return {
//     total: incidents.length,
//     activeIncidents: malicious + suspicious,
//     malicious,
//     suspicious,
//     benign,
//     defendedAssets: assets.length,
//     responseSuccess,
//     responseCoverage: responses.length,
//     topSource: incidents[0]?.attackSource || "n/a",
//     trend: Array.from(buckets.values()).slice(-12),
//     lastUpdated: incidents[0]?.timestamp || null,
//   };
// }

// function buildGraph(incidents) {
//   const nodes = [];
//   const edges = [];
//   const seen = new Set();

//   function addNode(id, label, group, meta = {}) {
//     if (seen.has(id)) return;
//     seen.add(id);
//     nodes.push({ id, label, group, meta });
//   }

//   incidents.slice(0, 20).forEach((incident) => {
//     const sourceNode = `src:${incident.attackSource}`;
//     const assetNode = `asset:${incident.targetAsset}`;
//     const incidentNode = `incident:${incident.id}`;
//     const responseNode = `response:${incident.id}`;

//     addNode(sourceNode, incident.attackSource, "source");
//     addNode(assetNode, incident.targetAsset, "asset");
//     addNode(incidentNode, incident.verdict.toUpperCase(), incident.severity, { confidence: incident.confidence });
//     addNode(responseNode, incident.response?.action || "notify_operator", "response");

//     edges.push({ from: sourceNode, to: incidentNode });
//     edges.push({ from: incidentNode, to: assetNode });
//     edges.push({ from: incidentNode, to: responseNode });
//   });

//   return { nodes, edges };
// }

// function buildAssetFleet(incidents, assets) {
//   return assets.map((asset) => {
//     const related = incidents.filter(
//       (incident) =>
//         incident.targetAsset === asset.hostname ||
//         incident.rawEvent?.dest_ip === asset.ip ||
//         incident.rawEvent?.src_ip === asset.ip
//     );
//     const lastIncident = related[0];
//     return {
//       assetId: asset.asset_id,
//       hostname: asset.hostname,
//       ip: asset.ip,
//       owner: asset.asset_owner,
//       criticality: asset.criticality,
//       osType: asset.os_type,
//       responseSurface: asset.allowed_actions || [],
//       recentThreats: related.length,
//       lastStatus: lastIncident?.verdict || "nominal",
//       lastAction: lastIncident?.response?.action || "none",
//       lastSeen: lastIncident?.timestamp || null,
//     };
//   });
// }

// function buildHealth(incidents) {
//   const latest = incidents[0];
//   const latency = latest?.traceMetadata?.latency_ms ?? null;
//   const recentAgeSeconds = latest ? Math.max(0, Math.floor((Date.now() - new Date(latest.timestamp).getTime()) / 1000)) : null;

//   return {
//     ingest: { status: latest ? "running" : "idle", lagSeconds: recentAgeSeconds },
//     preprocess: { status: latest?.normalizedFeatures?.feature_version ? "running" : "idle", featureVersion: latest?.normalizedFeatures?.feature_version || null },
//     planner: { status: latest?.planner?.route ? "running" : "idle", lastRoute: latest?.planner?.route || null },
//     detector: { status: latest?.detection?.method ? "running" : "idle", model: latest?.detection?.evidence?.model_name || null },
//     responder: { status: latest?.response?.status || "idle", mode: latest?.response?.mode || null },
//     pipelineLatencyMs: latency,
//     queueDepth: Math.min(incidents.length, 50),
//   };
// }

// app.get("/api/metrics/overview", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   const assets = readAssets();
//   res.json(buildOverview(incidents, assets));
// });

// app.get("/api/incidents/live", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   res.json(incidents.slice(0, 60));
// });

// app.get("/api/incidents/:id", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   const incident = incidents.find((item) => item.id === req.params.id);
//   if (!incident) {
//     res.status(404).json({ error: "Incident not found" });
//     return;
//   }
//   res.json(incident);
// });

// app.get("/api/assets", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   res.json(buildAssetFleet(incidents, readAssets()));
// });

// app.get("/api/responses", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   res.json(
//     incidents
//       .filter((incident) => incident.response?.action)
//       .map((incident) => ({
//         id: incident.id,
//         timestamp: incident.timestamp,
//         verdict: incident.verdict,
//         targetAsset: incident.targetAsset,
//         ...incident.response,
//       }))
//       .slice(0, 40)
//   );
// });

// app.get("/api/system/health", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   res.json(buildHealth(incidents));
// });

// app.get("/api/graph", (req, res) => {
//   const incidents = loadIncidents().map(formatIncident);
//   res.json(buildGraph(incidents));
// });

// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(`AutoSentry backend running at http://localhost:${PORT}`));



const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

const ROOT = path.join(__dirname, "..", "..");
const TRACE_PATH = process.env.AUTOSENTRY_TRACE_LOG_PATH || path.join(ROOT, "data", "traces.ndjson");
const ASSET_PATH = process.env.AUTOSENTRY_ASSET_INVENTORY_PATH || path.join(ROOT, "data", "managed_assets.json");

const TRACE_CACHE_LIMIT = Number(process.env.AUTOSENTRY_API_TRACE_CACHE_LIMIT || 5000);
const TAIL_READ_CHUNK_BYTES = 1024 * 1024;
const MAX_TAIL_READ_BYTES = Number(process.env.AUTOSENTRY_API_MAX_TAIL_BYTES || 128 * 1024 * 1024);
const MAX_INCREMENTAL_READ_BYTES = Number(process.env.AUTOSENTRY_API_MAX_INCREMENTAL_BYTES || 64 * 1024 * 1024);

let traceCache = [];
let traceOffset = 0;
let tracePartialLine = "";
let traceInitialized = false;
let traceFileSize = 0;
let traceFileMtimeMs = 0;

let assetCache = { mtimeMs: 0, rows: [] };

function resetCachesForTests() {
  traceCache = [];
  traceOffset = 0;
  tracePartialLine = "";
  traceInitialized = false;
  traceFileSize = 0;
  traceFileMtimeMs = 0;
  assetCache = { mtimeMs: 0, rows: [] };
}

function parseJsonLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function appendTraceRows(rows) {
  if (!rows.length) return;
  traceCache.push(...rows);
  if (traceCache.length > TRACE_CACHE_LIMIT) {
    traceCache = traceCache.slice(traceCache.length - TRACE_CACHE_LIMIT);
  }
}

function readTailJsonl(filePath, maxRows) {
  if (!fs.existsSync(filePath)) return { rows: [], offset: 0 };

  const stat = fs.statSync(filePath);
  if (stat.size === 0) return { rows: [], offset: 0 };

  const fd = fs.openSync(filePath, "r");
  const chunks = [];
  let position = stat.size;
  let bytesReadTotal = 0;
  let lineCount = 0;

  try {
    while (position > 0 && lineCount <= maxRows && bytesReadTotal < MAX_TAIL_READ_BYTES) {
      const readSize = Math.min(TAIL_READ_CHUNK_BYTES, position, MAX_TAIL_READ_BYTES - bytesReadTotal);
      position -= readSize;

      const buffer = Buffer.allocUnsafe(readSize);
      const bytesRead = fs.readSync(fd, buffer, 0, readSize, position);
      const text = buffer.subarray(0, bytesRead).toString("utf8");

      chunks.unshift(text);
      bytesReadTotal += bytesRead;
      lineCount += (text.match(/\n/g) || []).length;
    }
  } finally {
    fs.closeSync(fd);
  }

  let text = chunks.join("");

  if (position > 0) {
    const firstBreak = text.indexOf("\n");
    text = firstBreak >= 0 ? text.slice(firstBreak + 1) : "";
  }

  const rows = text
    .split(/\r?\n/)
    .map(parseJsonLine)
    .filter(Boolean)
    .slice(-maxRows);

  return { rows, offset: stat.size };
}

function initializeTraceCache() {
  const stat = fs.existsSync(TRACE_PATH) ? fs.statSync(TRACE_PATH) : null;

  if (!stat) {
    traceCache = [];
    traceOffset = 0;
    tracePartialLine = "";
    traceInitialized = true;
    traceFileSize = 0;
    traceFileMtimeMs = 0;
    return;
  }

  const { rows, offset } = readTailJsonl(TRACE_PATH, TRACE_CACHE_LIMIT);

  traceCache = rows;
  traceOffset = offset;
  tracePartialLine = "";
  traceInitialized = true;
  traceFileSize = stat.size;
  traceFileMtimeMs = stat.mtimeMs;
}

function refreshTraceCache() {
  if (!traceInitialized) {
    initializeTraceCache();
    return;
  }

  if (!fs.existsSync(TRACE_PATH)) {
    initializeTraceCache();
    return;
  }

  const stat = fs.statSync(TRACE_PATH);

  if (stat.size < traceOffset) {
    initializeTraceCache();
    return;
  }

  if (stat.size === traceFileSize && stat.mtimeMs === traceFileMtimeMs) {
    return;
  }

  const bytesToRead = stat.size - traceOffset;

  if (bytesToRead <= 0) {
    traceFileSize = stat.size;
    traceFileMtimeMs = stat.mtimeMs;
    return;
  }

  if (bytesToRead > MAX_INCREMENTAL_READ_BYTES) {
    initializeTraceCache();
    return;
  }

  const fd = fs.openSync(TRACE_PATH, "r");

  try {
    const buffer = Buffer.allocUnsafe(bytesToRead);
    const bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, traceOffset);

    const text = tracePartialLine + buffer.subarray(0, bytesRead).toString("utf8");
    const lines = text.split(/\r?\n/);

    if (text.endsWith("\n") || text.endsWith("\r\n")) {
      tracePartialLine = "";
    } else {
      tracePartialLine = lines.pop() || "";
    }

    appendTraceRows(lines.map(parseJsonLine).filter(Boolean));

    traceOffset = stat.size;
    traceFileSize = stat.size;
    traceFileMtimeMs = stat.mtimeMs;
  } finally {
    fs.closeSync(fd);
  }
}

function readAssets() {
  if (!fs.existsSync(ASSET_PATH)) return [];

  const stat = fs.statSync(ASSET_PATH);

  if (assetCache.rows.length && assetCache.mtimeMs === stat.mtimeMs) {
    return assetCache.rows;
  }

  try {
    assetCache = {
      mtimeMs: stat.mtimeMs,
      rows: JSON.parse(fs.readFileSync(ASSET_PATH, "utf8")),
    };
    return assetCache.rows;
  } catch {
    return [];
  }
}

function loadIncidents() {
  refreshTraceCache();
  return traceCache
    .map(formatIncident)
    .sort((a, b) => incidentSortTime(b) - incidentSortTime(a));
}

function verdictColor(verdict) {
  if (verdict === "malicious") return "malicious";
  if (verdict === "suspicious") return "suspicious";
  return "benign";
}

function traceDisplayTimestamp(trace) {
  return (
    trace.trace_metadata?.logged_at ||
    trace.trace_metadata?.processed_at ||
    trace.trace_metadata?.ingested_at ||
    trace.timestamp ||
    null
  );
}

function incidentSortTime(incident) {
  const value =
    incident.traceMetadata?.logged_at ||
    incident.traceMetadata?.processed_at ||
    incident.timestamp;

  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
}

function formatIncident(trace) {
  const raw = trace.raw_event || {};
  const detection = trace.detection_result || {};
  const planner = trace.planner_result || {};
  const response = trace.response_result || {};
  const displayTimestamp = traceDisplayTimestamp(trace);

  const traceId =
    trace.trace_metadata?.trace_id ||
    [trace.event_id, displayTimestamp].filter(Boolean).join(":");

  return {
    id: traceId,
    sourceEventId: trace.event_id,
    timestamp: displayTimestamp,
    eventTimestamp: trace.timestamp,
    severity: verdictColor(detection.verdict),
    headline:
      trace.story?.headline ||
      `${raw.src_ip || "unknown"} -> ${raw.dest_ip || "unknown"}`,
    summary: trace.story?.summary || "Incident processed by AutoSentry",
    attackSource: raw.src_ip || "unknown",
    targetAsset:
      trace.asset_context?.target_asset?.hostname ||
      raw.dest_ip ||
      "unknown",
    classificationPath: `${planner.route || "skip"} -> ${
      detection.method || "rule"
    } -> ${response.action || "notify_operator"}`,
    confidence: detection.confidence ?? 0,
    verdict: detection.verdict || "benign",
    priority: planner.priority || "low",
    planner,
    detection,
    response,
    rawEvent: raw,
    normalizedFeatures: trace.normalized_features || {},
    assetContext: trace.asset_context || {},
    traceMetadata: trace.trace_metadata || {},
  };
}

function buildOverview(incidents, assets) {
  const malicious = incidents.filter((i) => i.verdict === "malicious").length;
  const suspicious = incidents.filter((i) => i.verdict === "suspicious").length;
  const benign = incidents.filter((i) => i.verdict === "benign").length;

  const responses = incidents.filter(
    (i) => i.response?.status && i.response.status !== "skipped"
  );

  const responseSuccess = responses.filter((i) =>
    ["completed", "dry_run", "pending_remote_execution"].includes(
      i.response.status
    )
  ).length;

  const buckets = new Map();

  incidents.slice().reverse().forEach((incident) => {
    const bucketKey = new Date(incident.timestamp)
      .toISOString()
      .slice(0, 16);

    if (!buckets.has(bucketKey)) {
      buckets.set(bucketKey, {
        ts: bucketKey,
        malicious: 0,
        suspicious: 0,
        benign: 0,
      });
    }

    buckets.get(bucketKey)[incident.verdict] += 1;
  });

  return {
    total: incidents.length,
    activeIncidents: malicious + suspicious,
    malicious,
    suspicious,
    benign,
    defendedAssets: assets.length,
    responseSuccess,
    responseCoverage: responses.length,
    topSource: incidents[0]?.attackSource || "n/a",
    trend: Array.from(buckets.values()).slice(-12),
    lastUpdated: incidents[0]?.timestamp || null,
    cacheWindow: incidents.length,
    cacheLimit: TRACE_CACHE_LIMIT,
  };
}

function buildGraph(incidents) {
  const nodes = [];
  const edges = [];
  const seen = new Set();

  function addNode(id, label, group, meta = {}) {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, group, meta });
  }

  incidents.slice(0, 20).forEach((incident) => {
    const sourceNode = `src:${incident.attackSource}`;
    const assetNode = `asset:${incident.targetAsset}`;
    const incidentNode = `incident:${incident.id}`;
    const responseNode = `response:${incident.id}`;

    addNode(sourceNode, incident.attackSource, "source");
    addNode(assetNode, incident.targetAsset, "asset");
    addNode(
      incidentNode,
      incident.verdict.toUpperCase(),
      incident.severity,
      { confidence: incident.confidence }
    );
    addNode(
      responseNode,
      incident.response?.action || "notify_operator",
      "response"
    );

    edges.push({ from: sourceNode, to: incidentNode });
    edges.push({ from: incidentNode, to: assetNode });
    edges.push({ from: incidentNode, to: responseNode });
  });

  return { nodes, edges };
}

function buildAssetFleet(incidents, assets) {
  return assets.map((asset) => {
    const related = incidents.filter(
      (incident) =>
        incident.targetAsset === asset.hostname ||
        incident.rawEvent?.dest_ip === asset.ip ||
        incident.rawEvent?.src_ip === asset.ip
    );

    const lastIncident = related[0];

    return {
      assetId: asset.asset_id,
      hostname: asset.hostname,
      ip: asset.ip,
      owner: asset.asset_owner,
      criticality: asset.criticality,
      osType: asset.os_type,
      responseSurface: asset.allowed_actions || [],
      recentThreats: related.length,
      lastStatus: lastIncident?.verdict || "nominal",
      lastAction: lastIncident?.response?.action || "none",
      lastSeen: lastIncident?.timestamp || null,
    };
  });
}

function buildHealth(incidents) {
  const latest = incidents[0];

  const latency = latest?.traceMetadata?.latency_ms ?? null;

  const recentAgeSeconds = latest
    ? Math.max(
        0,
        Math.floor(
          (Date.now() - new Date(latest.timestamp).getTime()) / 1000
        )
      )
    : null;

  const sourceEventAgeSeconds = latest?.eventTimestamp
    ? Math.max(
        0,
        Math.floor(
          (Date.now() - new Date(latest.eventTimestamp).getTime()) / 1000
        )
      )
    : null;

  return {
    ingest: { status: latest ? "running" : "idle", lagSeconds: recentAgeSeconds },
    preprocess: {
      status: latest?.normalizedFeatures?.feature_version
        ? "running"
        : "idle",
      featureVersion:
        latest?.normalizedFeatures?.feature_version || null,
    },
    planner: {
      status: latest?.planner?.route ? "running" : "idle",
      lastRoute: latest?.planner?.route || null,
    },
    detector: {
      status: latest?.detection?.method ? "running" : "idle",
      model: latest?.detection?.evidence?.model_name || null,
    },
    responder: {
      status: latest?.response?.status || "idle",
      mode: latest?.response?.mode || null,
    },
    pipelineLatencyMs: latency,
    queueDepth: Math.min(incidents.length, 50),
    sourceEventAgeSeconds,
    traceCache: {
      status: "bounded",
      rows: incidents.length,
      limit: TRACE_CACHE_LIMIT,
      fileSizeBytes: traceFileSize,
    },
  };
}

/* ================= ROUTES ================= */

app.get("/api/metrics/overview", (req, res) => {
  const incidents = loadIncidents();
  const assets = readAssets();
  res.json(buildOverview(incidents, assets));
});

app.get("/api/incidents/live", (req, res) => {
  const incidents = loadIncidents();
  res.json(incidents.slice(0, 60));
});

app.get("/api/incidents/:id", (req, res) => {
  const incidents = loadIncidents();
  const incident = incidents.find((item) => item.id === req.params.id);

  if (!incident) {
    res.status(404).json({ error: "Incident not found" });
    return;
  }

  res.json(incident);
});

app.get("/api/assets", (req, res) => {
  const incidents = loadIncidents();
  res.json(buildAssetFleet(incidents, readAssets()));
});

app.get("/api/responses", (req, res) => {
  const incidents = loadIncidents();

  res.json(
    incidents
      .filter((incident) => incident.response?.action)
      .map((incident) => ({
        id: incident.id,
        timestamp: incident.timestamp,
        verdict: incident.verdict,
        targetAsset: incident.targetAsset,
        ...incident.response,
      }))
      .slice(0, 40)
  );
});

app.get("/api/system/health", (req, res) => {
  const incidents = loadIncidents();
  res.json(buildHealth(incidents));
});

app.get("/api/graph", (req, res) => {
  const incidents = loadIncidents();
  res.json(buildGraph(incidents));
});

/* ================= SERVER ================= */

if (require.main === module) {
  const PORT = process.env.PORT || 5000;

  app.listen(PORT, () => {
    console.log(`AutoSentry backend running at http://localhost:${PORT}`);
  });
}

module.exports = {
  app,
  resetCachesForTests,
  parseJsonLine,
  formatIncident,
  buildOverview,
  buildGraph,
  buildAssetFleet,
  buildHealth,
};
