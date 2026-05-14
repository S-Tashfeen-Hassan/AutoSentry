import React, { startTransition, useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Background, Controls, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const API_BASE = "http://localhost:5000";

const PAGES = [
  ["mission", "Mission Control"],
  ["investigation", "Investigation"],
  ["responses", "Response Ops"],
  ["assets", "Asset Fleet"],
  ["health", "System Health"],
];

const SEVERITY_COLORS = {
  malicious: "#ff7a59",
  suspicious: "#ffd166",
  benign: "#54f2c1",
};

const PIE_COLORS = ["#ff7a59", "#ffd166", "#54f2c1"];

function fmtPercent(value) {
  return `${Math.round((value || 0) * 100)}%`;
}

function fmtDate(value) {
  if (!value) return "n/a";
  return new Date(value).toLocaleString();
}

function confidenceLabel(incident) {
  const method = incident?.detection?.method;
  const verdict = incident?.verdict;
  if (method === "rule" && verdict === "benign") return "Rule-based";
  if (method === "rule" && verdict === "malicious") return "High certainty";
  return fmtPercent(incident?.confidence || 0);
}

function summarizeMaliciousThreats(incidents) {
  const grouped = new Map();
  incidents.forEach((incident) => {
    const key = incident.sourceEventId || incident.id;
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, { ...incident, replayCount: 1, latestTraceId: incident.id });
      return;
    }
    grouped.set(key, {
      ...existing,
      replayCount: existing.replayCount + 1,
      latestTraceId: incident.id,
      timestamp: new Date(incident.timestamp) > new Date(existing.timestamp) ? incident.timestamp : existing.timestamp,
      response: incident.response || existing.response,
    });
  });
  return Array.from(grouped.values()).sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp));
}

function graphLayout(data) {
  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  
  const groups = { source: [], malicious: [], suspicious: [], benign: [], asset: [], response: [] };
  nodes.forEach((n) => {
    const g = n.group in groups ? n.group : "suspicious";
    groups[g].push(n);
  });
  
  const incidents = [...groups.malicious, ...groups.suspicious, ...groups.benign];
  const positionedNodes = [];
  const positionedIds = new Set();

  const addNode = (node, x, y) => {
    if (positionedIds.has(node.id)) return;
    positionedNodes.push({ node, x, y });
    positionedIds.add(node.id);
  };

  // 1. Assets in a tight center core
  groups.asset.forEach((a, i) => {
    const coreAngle = (Math.PI * 2 * i) / (groups.asset.length || 1);
    const coreRadius = groups.asset.length > 1 ? 40 : 0;
    addNode(a, Math.cos(coreAngle) * coreRadius, Math.sin(coreAngle) * coreRadius);
  });

  // 2. Radially position Incidents on spokes
  incidents.forEach((inc, i) => {
    const angle = incidents.length === 1 ? -Math.PI / 2 : (Math.PI * 2 * i) / incidents.length;
    addNode(inc, Math.cos(angle) * 220, Math.sin(angle) * 220);

    // Find sources pointing to this incident, place them exactly outward on the same spoke
    const connectedSources = groups.source.filter(s => edges.some(e => e.from === s.id && e.to === inc.id));
    connectedSources.forEach((s, si) => {
      const sRadius = 380 + (si * 120);
      addNode(s, Math.cos(angle - 0.08) * sRadius, Math.sin(angle - 0.08) * sRadius);
    });

    // Find responses, place them slightly offset on the same spoke
    const connectedResponses = groups.response.filter(r => edges.some(e => e.from === inc.id && e.to === r.id));
    connectedResponses.forEach((r, ri) => {
      const rRadius = 380 + (ri * 120);
      addNode(r, Math.cos(angle + 0.08) * rRadius, Math.sin(angle + 0.08) * rRadius);
    });
  });

  // Catch any unconnected sources/responses
  groups.source.forEach((s, i) => addNode(s, -450, (i * 80) - 200));
  groups.response.forEach((r, i) => addNode(r, 450, (i * 80) - 200));

  return {
    nodes: positionedNodes.map(({ node, x, y }) => ({
      id: node.id,
      data: { label: node.label },
      position: { x, y },
      style: {
        background:
          node.group === "source"
            ? "rgba(74, 125, 255, 0.14)"
            : node.group === "asset"
              ? "rgba(84, 242, 193, 0.14)"
              : node.group === "response"
                ? "rgba(255, 122, 89, 0.14)"
                : "rgba(255, 209, 102, 0.12)",
        color: "#f4f7fb",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 18,
        padding: "14px 18px",
        minWidth: 150,
        boxShadow: "0 20px 50px rgba(0,0,0,0.22)",
      },
    })),
    edges: edges.map((edge, index) => ({
      id: `edge-${index}`,
      source: edge.from,
      target: edge.to,
      animated: true,
      style: { stroke: "rgba(123, 176, 255, 0.45)", strokeWidth: 2 },
    })),
  };
}

function MetricCard({ label, value, accent, sublabel }) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={{ color: accent }}>{value}</div>
      <div className="metric-sublabel">{sublabel}</div>
    </div>
  );
}

function IncidentList({ incidents, selectedId, onSelect, title, subtitle, className = "" }) {
  const [filter, setFilter] = useState("all");

  const filtered = useMemo(() => {
    if (filter === "malicious") return incidents.filter((incident) => incident.verdict === "malicious");
    if (filter === "suspicious") return incidents.filter((incident) => incident.verdict === "suspicious");
    return incidents;
  }, [filter, incidents]);

  return (
    <section className={`panel panel-stack ${className}`}>
      <div className="section-heading">
        <div>
          <h3>{title}</h3>
          <p>{subtitle}</p>
        </div>
      </div>
      <div className="filter-row">
        <button className={`filter-pill ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>All</button>
        <button className={`filter-pill ${filter === "suspicious" ? "active" : ""}`} onClick={() => setFilter("suspicious")}>Suspicious</button>
        <button className={`filter-pill ${filter === "malicious" ? "active" : ""}`} onClick={() => setFilter("malicious")}>Malicious</button>
      </div>
      <div className="incident-list incident-scroll">
        {filtered.length ? (
          filtered.map((incident) => (
            <button
              key={incident.id}
              className={`incident-card ${selectedId === incident.id ? "active" : ""}`}
              onClick={() => onSelect(incident.id)}
            >
              <div className="incident-card-top">
                <span className={`severity-pill ${incident.severity}`}>{incident.verdict}</span>
                <span className="incident-time">{fmtDate(incident.timestamp)}</span>
              </div>
              <div className="incident-headline">{incident.headline}</div>
              <div className="incident-summary">{incident.summary}</div>
              <div className="incident-meta">
                <span>{incident.attackSource}</span>
                <span>{incident.targetAsset}</span>
                <span>{confidenceLabel(incident)}</span>
              </div>
            </button>
          ))
        ) : (
          <div className="empty-state compact-empty">No incidents match the current filter.</div>
        )}
      </div>
    </section>
  );
}

function Spotlight({ selectedIncident }) {
  return (
    <section className="panel spotlight">
      <div className="section-heading">
        <div>
          <h3>Threat Spotlight</h3>
          <p>The selected incident with its path, evidence, and response story.</p>
        </div>
      </div>
      {selectedIncident ? (
        <div className="spotlight-grid">
          <div>
            <div className="spotlight-headline">{selectedIncident.headline}</div>
            <div className="spotlight-summary">{selectedIncident.summary}</div>
            <div className="story-grid">
              <div>
                <span className="story-label">Attack Source</span>
                <strong>{selectedIncident.attackSource}</strong>
              </div>
              <div>
                <span className="story-label">Target Asset</span>
                <strong>{selectedIncident.targetAsset}</strong>
              </div>
              <div>
                <span className="story-label">Classification Path</span>
                <strong>{selectedIncident.classificationPath}</strong>
              </div>
              <div>
                <span className="story-label">Autonomous Response</span>
                <strong>{selectedIncident.response?.command_summary || "No action taken"}</strong>
              </div>
            </div>
          </div>
          <div className={`hud-readout ${selectedIncident.severity}`}>
            <div className="hud-brackets">
              <span className="hud-score">
                {selectedIncident.detection?.method === "rule" && selectedIncident.verdict === "benign"
                  ? "RULE"
                  : fmtPercent(selectedIncident.confidence)}
              </span>
            </div>
            <div className="hud-label">
              {selectedIncident.detection?.method === "rule" && selectedIncident.verdict === "benign"
                ? "DETERMINISTIC PATH"
                : "DETECTION CONFIDENCE"}
            </div>
            <div className="hud-tags">
              <span className="hud-tag">{selectedIncident.verdict.toUpperCase()}</span>
              <span className="hud-separator">///</span>
              <span className="hud-tag">{(selectedIncident.detection?.method || "unknown").toUpperCase()}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty-state">Run the pipeline to surface incidents.</div>
      )}
    </section>
  );
}

function CriticalThreats({ incidents, onSelect }) {
  return (
    <section className="panel panel-stack critical-threats">
      <div className="section-heading">
        <div>
          <h3>Malicious Threats</h3>
          <p>Dedicated workspace for confirmed malicious incidents and what the responder did about them.</p>
        </div>
      </div>
      {incidents.length ? (
        <div className="table-list">
          {incidents.map((incident) => (
            <button key={incident.sourceEventId || incident.id} className="table-row interactive-row" onClick={() => onSelect(incident.latestTraceId || incident.id)}>
              <div>
                <div className="table-title">{incident.headline}</div>
                <div className="table-subtitle">
                  {incident.response?.command_summary || "No response summary"}
                  {incident.replayCount > 1 ? ` • replayed ${incident.replayCount} times` : ""}
                </div>
              </div>
              <div>{incident.attackSource}</div>
              <div>{incident.targetAsset}</div>
              <div className={`severity-pill ${incident.severity}`}>{incident.response?.status || "pending"}</div>
            </button>
          ))}
        </div>
      ) : (
        <div className="empty-state compact-empty">
          No malicious incidents are present in the current trace window yet.
        </div>
      )}
    </section>
  );
}

function MissionControl({ overview, selectedIncident, responses, maliciousIncidents, onSelect }) {
  const pieData = [
    { name: "Malicious", value: overview?.malicious || 0 },
    { name: "Suspicious", value: overview?.suspicious || 0 },
    { name: "Benign", value: overview?.benign || 0 },
  ];

  return (
    <div className="page-grid">
      <section className="hero panel">
        <div className="hero-copy">
          <h1>Mission Control</h1>
          <p>Autonomous Detection and Response</p>
        </div>
        <div className="hero-metrics">
          <MetricCard label="Active Incidents" value={overview?.activeIncidents ?? 0} accent="#ff7a59" sublabel="malicious + suspicious" />
          <MetricCard label="Defended Assets" value={overview?.defendedAssets ?? 0} accent="#7bb0ff" sublabel="managed and watched" />
          <MetricCard label="Response Success" value={overview?.responseSuccess ?? 0} accent="#54f2c1" sublabel="completed or ready" />
          <MetricCard label="Top Source" value={overview?.topSource || "n/a"} accent="#ffd166" sublabel="most recent attacker" />
        </div>
      </section>

      <Spotlight selectedIncident={selectedIncident} />

      <section className="panel chart-panel">
        <div className="section-heading">
          <div>
            <h3>Attack Tempo</h3>
            <p>Trend of malicious, suspicious, and benign activity across recent trace buckets.</p>
          </div>
        </div>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={overview?.trend || []}>
              <defs>
                <linearGradient id="maliciousFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#ff7a59" stopOpacity={0.7} />
                  <stop offset="95%" stopColor="#ff7a59" stopOpacity={0.05} />
                </linearGradient>
                <linearGradient id="suspiciousFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#ffd166" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#ffd166" stopOpacity={0.04} />
                </linearGradient>
                <linearGradient id="benignFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#54f2c1" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="#54f2c1" stopOpacity={0.04} />
                </linearGradient>
              </defs>
              <XAxis dataKey="ts" tick={{ fill: "#9bb0c8", fontSize: 11 }} />
              <YAxis tick={{ fill: "#9bb0c8", fontSize: 11 }} />
              <Tooltip />
              <Area type="monotone" dataKey="malicious" stroke="#ff7a59" fill="url(#maliciousFill)" strokeWidth={2} />
              <Area type="monotone" dataKey="suspicious" stroke="#ffd166" fill="url(#suspiciousFill)" strokeWidth={2} />
              <Area type="monotone" dataKey="benign" stroke="#54f2c1" fill="url(#benignFill)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="panel chart-panel">
        <div className="section-heading">
          <div>
            <h3>Severity Distribution</h3>
            <p>How the pipeline is classifying the active trace universe.</p>
          </div>
        </div>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={pieData} dataKey="value" innerRadius={70} outerRadius={110}>
                {pieData.map((entry, index) => (
                  <Cell key={entry.name} fill={PIE_COLORS[index]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </section>

      <CriticalThreats incidents={maliciousIncidents} onSelect={onSelect} />

      <section className="panel response-spotlight">
        <div className="section-heading">
          <div>
            <h3>Autonomous Response Moments</h3>
            <p>Managed-asset actions rendered as high-signal operational milestones.</p>
          </div>
        </div>
        <div className="response-list">
          {responses.slice(0, 5).map((response) => (
            <div key={response.audit_id} className="response-item">
              <div className={`response-status ${response.status}`}>{response.status}</div>
              <div>
                <div className="response-title">{response.action}</div>
                <div className="response-subtitle">{response.command_summary}</div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}


function Investigation({ selectedIncident, graphData }) {
  const graph = useMemo(() => graphLayout(graphData), [graphData]);

  return (
    <div className="page-grid investigation-layout">
      <section className="panel graph-panel">
        <div className="section-heading">
          <div>
            <h3>Incident Constellation</h3>
            <p>Attack source, defended asset, detection verdict, and response action in one topology.</p>
          </div>
        </div>
        <div className="graph-wrap">
          <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView>
            <Background color="rgba(123,176,255,0.12)" />
            <Controls />
          </ReactFlow>
        </div>
      </section>
      <section className="panel detail-panel">
        <div className="section-heading">
          <div>
            <h3>Analyst Drilldown</h3>
            <p>Evidence, model outputs, and response audit for the selected incident.</p>
          </div>
        </div>
        {selectedIncident ? (
          <div className="detail-stack">
            <div className="detail-block">
              <div className="detail-label">Evidence Highlights</div>
              <div className="badge-row">
                <span className={`severity-pill ${selectedIncident.severity}`}>{selectedIncident.verdict}</span>
                <span className="neutral-pill">{selectedIncident.detection?.method}</span>
                <span className="neutral-pill">{selectedIncident.priority}</span>
              </div>
              <pre>{JSON.stringify(selectedIncident.detection?.evidence || {}, null, 2)}</pre>
            </div>
            <div className="detail-block">
              <div className="detail-label">Normalized Features</div>
              <pre>{JSON.stringify(selectedIncident.normalizedFeatures?.features || {}, null, 2)}</pre>
            </div>
            <div className="detail-block">
              <div className="detail-label">Raw Event</div>
              <pre>{JSON.stringify(selectedIncident.rawEvent || {}, null, 2)}</pre>
            </div>
            <div className="detail-block">
              <div className="detail-label">Response Audit</div>
              <pre>{JSON.stringify(selectedIncident.response || {}, null, 2)}</pre>
            </div>
          </div>
        ) : (
          <div className="empty-state">Select an incident to inspect its pipeline evidence.</div>
        )}
      </section>
    </div>
  );
}

function ResponseOps({ responses }) {
  const aggregatedData = useMemo(() => {
    const counts = {};
    responses.forEach((r) => {
      const action = r.action || "unknown";
      if (!counts[action]) counts[action] = { action, count: 0, completed: 0, dry_run: 0 };
      counts[action].count += 1;
      if (r.status === "completed") counts[action].completed += 1;
      else if (r.status === "dry_run") counts[action].dry_run += 1;
    });
    return Object.values(counts).sort((a, b) => b.count - a.count).slice(0, 8);
  }, [responses]);

  return (
    <div className="page-grid two-col">
      <section className="panel panel-stack">
        <div className="section-heading">
          <div>
            <h3>Response Ledger</h3>
            <p>What the system proposed or executed on your managed infrastructure.</p>
          </div>
        </div>
        <div className="table-list">
          {responses.length ? responses.map((response) => (
            <div key={response.audit_id || response.id || `${response.action}-${response.timestamp}`} className="table-row">
              <div>
                <div className="table-title">{response.action}</div>
                <div className="table-subtitle">{response.targetAsset || "No target asset"}</div>
              </div>
              <div>{response.executor}</div>
              <div>{response.mode}</div>
              <div className={`response-status ${response.status}`}>{response.status}</div>
            </div>
          )) : (
            <div className="empty-state compact-empty">No response actions have been planned or executed yet.</div>
          )}
        </div>
      </section>
      <section className="panel chart-panel">
        <div className="section-heading">
          <div>
            <h3>Action Distribution</h3>
            <p>Volume of autonomous countermeasures grouped by action type.</p>
          </div>
        </div>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={aggregatedData}>
              <XAxis dataKey="action" tick={{ fill: "#9bb0c8", fontSize: 11 }} interval={0} angle={-15} textAnchor="end" height={60} />
              <YAxis tick={{ fill: "#9bb0c8", fontSize: 11 }} allowDecimals={false} width={30} />
              <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} contentStyle={{ background: "#0a192f", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px" }} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {aggregatedData.map((entry) => (
                  <Cell key={entry.action} fill={entry.dry_run > entry.completed ? "#b3cde0" : "#90b4ce"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}

function AssetFleet({ assets }) {
  if (!assets.length) {
    return <div className="empty-state">No managed assets are available yet.</div>;
  }

  return (
    <div className="asset-grid">
      {assets.map((asset) => (
        <section key={asset.assetId} className="panel asset-card">
          <div className="asset-top">
            <div>
              <div className="asset-name">{asset.hostname}</div>
              <div className="asset-ip">{asset.ip}</div>
            </div>
            <span className={`severity-pill ${asset.lastStatus === "malicious" ? "malicious" : asset.lastStatus === "suspicious" ? "suspicious" : "benign"}`}>
              {asset.lastStatus}
            </span>
          </div>
          <div className="asset-meta" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span>{asset.owner}</span>
            <span>&bull;</span>
            <span>{asset.osType}</span>
            <span>&bull;</span>
            <span>{asset.criticality}</span>
          </div>
          <div className="asset-stats">
            <div>
              <span className="story-label">Recent Threats</span>
              <strong>{asset.recentThreats}</strong>
            </div>
            <div>
              <span className="story-label">Last Action</span>
              <strong>{asset.lastAction}</strong>
            </div>
            <div>
              <span className="story-label">Last Seen</span>
              <strong>{asset.lastSeen ? fmtDate(asset.lastSeen) : "n/a"}</strong>
            </div>
          </div>
          <div className="capability-row">
            {asset.responseSurface.map((capability) => (
              <span key={capability} className="neutral-pill">{capability}</span>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function SystemHealth({ health, overview }) {
  const stageRows = Object.entries(health || {}).filter(([key]) => key !== "pipelineLatencyMs" && key !== "queueDepth");
  return (
    <div className="page-grid two-col">
      <section className="panel panel-stack">
        <div className="section-heading">
          <div>
            <h3>Pipeline Health</h3>
            <p>Realtime stage health, lag, and mode awareness for the NDR runtime.</p>
          </div>
        </div>
        <table className="health-table">
          <tbody>
            {stageRows.map(([stage, value]) => (
              <tr key={stage} className="interactive-row">
                <td className="table-title">{stage}</td>
                <td style={{ textAlign: "left" }}>
                  <span className={`health-status ${value.status || ""}`}>{value.status || "n/a"}</span>
                </td>
                <td style={{ textAlign: "right", color: "#8b9cba" }}>
                  {value.mode || value.model || value.lastRoute || value.featureVersion || value.lagSeconds || "n/a"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="panel panel-stack">
        <div className="section-heading">
          <div>
            <h3>Operational Pulse</h3>
            <p>Latency and queue load in the same command surface as threat volume.</p>
          </div>
        </div>
        <div className="pulse-metrics">
          <MetricCard label="Pipeline Latency" value={`${health?.pipelineLatencyMs ?? 0} ms`} accent="#7bb0ff" sublabel="latest end-to-end trace" />
          <MetricCard label="Queue Depth" value={health?.queueDepth ?? 0} accent="#ffd166" sublabel="recent incident surface" />
          <MetricCard label="Last Updated" value={fmtDate(overview?.lastUpdated)} accent="#54f2c1" sublabel="overview refresh marker" />
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("mission");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [overview, setOverview] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [assets, setAssets] = useState([]);
  const [responses, setResponses] = useState([]);
  const [health, setHealth] = useState(null);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const [overviewRes, incidentsRes, assetsRes, responsesRes, healthRes, graphRes] = await Promise.all([
          axios.get(`${API_BASE}/api/metrics/overview`),
          axios.get(`${API_BASE}/api/incidents/live`),
          axios.get(`${API_BASE}/api/assets`),
          axios.get(`${API_BASE}/api/responses`),
          axios.get(`${API_BASE}/api/system/health`),
          axios.get(`${API_BASE}/api/graph`),
        ]);

        if (!mounted) return;
        startTransition(() => {
          setOverview(overviewRes.data);
          setIncidents(incidentsRes.data);
          setAssets(assetsRes.data);
          setResponses(responsesRes.data);
          setHealth(healthRes.data);
          setGraph(graphRes.data);
          setSelectedIncidentId((current) =>
            current && incidentsRes.data.some((incident) => incident.id === current)
              ? current
              : incidentsRes.data.find((incident) => incident.verdict !== "benign")?.id || incidentsRes.data[0]?.id || null
          );
        });
      } catch (error) {
        console.error("AutoSentry data fetch failed", error);
      }
    };

    fetchData();
    const timer = setInterval(fetchData, 4500);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId) || incidents[0] || null;
  const maliciousIncidents = incidents.filter((incident) => incident.verdict === "malicious");
  const maliciousThreats = useMemo(() => summarizeMaliciousThreats(maliciousIncidents), [maliciousIncidents]);

  const hasMalicious = maliciousIncidents.length > 0;
  const hasSuspicious = incidents.some((incident) => incident.verdict === "suspicious");

  return (
    <div className="app-shell">
      <div className={`suspicious-backdrop ${hasSuspicious ? "active" : ""}`} />
      <div className={`malicious-backdrop ${hasMalicious ? "active" : ""}`} />
      <div className="ambient-glow ambient-one" />
      <div className="ambient-glow ambient-two" />
      
      <div 
        className={`mobile-overlay ${isMobileMenuOpen ? "open" : ""}`} 
        onClick={() => setIsMobileMenuOpen(false)}
      />

      <aside className={`side-rail ${isMobileMenuOpen ? "open" : ""}`}>
        <div className="brand-block">
          <div className="brand-mark">AS</div>
          <div>
            <div className="brand-title">AutoSentry</div>
          </div>
        </div>
        <nav className="nav-stack">
          {PAGES.map(([id, label]) => (
            <button key={id} className={`nav-link ${page === id ? "active" : ""}`} onClick={() => { setPage(id); setIsMobileMenuOpen(false); }}>
              {label}
            </button>
          ))}
        </nav>
        <div className="rail-footer">
          <div className="neutral-pill">API: localhost:5000</div>
          <div className="neutral-pill">Response: {responses[0]?.mode || "dry_run"}</div>
        </div>
      </aside>

      <main className="main-stage">
        <header className="topbar panel">
          <div className="topbar-header">
            <button className="mobile-menu-btn" onClick={() => setIsMobileMenuOpen(true)}>
              ☰
            </button>
            <div>
              <div className="hero-kicker">Active Threat Monitoring & Response</div>
              <h2>AutoSentry</h2>
            </div>
          </div>
        </header>

        <div className="content-grid">
          <IncidentList
            incidents={incidents}
            selectedId={selectedIncidentId}
            onSelect={setSelectedIncidentId}
            title="Incident Stream"
            subtitle="Scrollable live incident history with cleaner spacing and easier backtracking."
          />
          <section className="page-surface">
            {page === "mission" && (
            <MissionControl
              overview={overview}
              selectedIncident={selectedIncident}
              responses={responses}
              maliciousIncidents={maliciousThreats}
              onSelect={setSelectedIncidentId}
            />
          )}

            {page === "investigation" && <Investigation selectedIncident={selectedIncident} graphData={graph} />}
            {page === "responses" && <ResponseOps responses={responses} />}
            {page === "assets" && <AssetFleet assets={assets} />}
            {page === "health" && <SystemHealth health={health} overview={overview} />}
          </section>
        </div>
      </main>
    </div>
  );
}
