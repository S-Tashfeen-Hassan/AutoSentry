const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

const LOG_PATH = path.join(__dirname, "..", "..", "data", "detection_output.ndjson");

// State
let lastPos = 0;
let allLogs = [];

// Read new lines from detection_output.ndjson
function readNewLines() {
  if (!fs.existsSync(LOG_PATH)) return [];

  const fd = fs.openSync(LOG_PATH, "r");
  const stats = fs.fstatSync(fd);
  const size = stats.size;

  if (size <= lastPos) {
    fs.closeSync(fd);
    return [];
  }

  const length = size - lastPos;
  const buffer = Buffer.alloc(length);
  fs.readSync(fd, buffer, 0, length, lastPos);
  lastPos = size;
  fs.closeSync(fd);

  const raw = buffer.toString();
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);

  const parsed = [];
  for (const line of lines) {
    try {
      const json = JSON.parse(line);

      const det = json.detection_result || {};
      const is_anomaly = det.is_anomaly ?? false;
      const anomaly_score = det.anomaly_score ?? 0;
      const ts = det.timestamp ? new Date(det.timestamp * 1000).toISOString() : new Date().toISOString();

      parsed.push({
        log_id: `log-${Date.now()}-${Math.floor(Math.random() * 9999)}`,
        logged_at: ts,
        detection: {
          verdict: is_anomaly ? "malicious" : "benign",
          is_anomaly,
          anomaly_score
        }
      });

    } catch (e) {
      // ignore malformed lines
    }
  }

  return parsed;
}

function ingestNew() {
  const newEntries = readNewLines();
  if (newEntries.length > 0) {
    allLogs = allLogs.concat(newEntries);
    if (allLogs.length > 5000) {
      allLogs = allLogs.slice(allLogs.length - 5000);
    }
  }
  return newEntries;
}

setInterval(ingestNew, 1000);

// === ROUTES ===

// fetch only new logs
app.get("/api/logs/new", (req, res) => {
  const newEntries = ingestNew();
  res.json(newEntries);
});

// fetch last N logs
app.get("/api/logs/recent", (req, res) => {
  const n = parseInt(req.query.n || "50", 10);
  res.json(allLogs.slice(-n));
});

// stats endpoint (simplified)
app.get("/api/stats", (req, res) => {
  let malicious = 0, benign = 0;

  allLogs.forEach(log => {
    if (log.detection.verdict === "malicious") malicious++;
    else benign++;
  });

  res.json({
    total: allLogs.length,
    malicious,
    benign
  });
});

// correlation graph (simple)
app.get("/api/graph", (req, res) => {
  const logs = allLogs.slice(-200);
  const nodes = [];
  const edges = [];
  const map = {};

  function addNode(id, label, group) {
    if (!map[id]) {
      map[id] = true;
      nodes.push({ id, label, group });
    }
  }

  logs.forEach(log => {
    const lid = log.log_id;
    addNode(lid, `Log ${lid}`, "log");

    const dNode = `detection:${lid}`;
    addNode(dNode, `Detection (${log.detection.verdict})`, "detection");

    edges.push({ from: lid, to: dNode });
  });

  res.json({ nodes, edges });
});

// health
app.get("/api/health", (req, res) => {
  const now = Date.now();
  const last = allLogs.length ? new Date(allLogs[allLogs.length - 1].logged_at).getTime() : 0;
  const secs = last ? Math.floor((now - last) / 1000) : 99999;

  const alive = secs < 10;

  res.json({
    detection: {
      status: alive ? "running" : "stalled",
      last_seen_seconds_ago: secs
    }
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running at http://localhost:${PORT}`));
