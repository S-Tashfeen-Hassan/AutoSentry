import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import App from "./App";

vi.mock("axios");

vi.mock("recharts", () => {
  const Chart = () => <div data-testid="chart" />;
  const Primitive = () => null;
  return {
    Area: Primitive,
    AreaChart: Chart,
    Bar: Primitive,
    BarChart: Chart,
    Cell: Primitive,
    Pie: Primitive,
    PieChart: Chart,
    ResponsiveContainer: Chart,
    Tooltip: Primitive,
    XAxis: Primitive,
    YAxis: Primitive,
  };
});

vi.mock("@xyflow/react", () => ({
  Background: () => <div data-testid="flow-background" />,
  Controls: () => <div data-testid="flow-controls" />,
  ReactFlow: ({ nodes = [], edges = [] }) => (
    <div data-testid="react-flow">
      {nodes.length} nodes / {edges.length} edges
    </div>
  ),
}));

const overview = {
  total: 2,
  activeIncidents: 1,
  malicious: 1,
  suspicious: 0,
  benign: 1,
  defendedAssets: 1,
  responseSuccess: 1,
  responseCoverage: 1,
  topSource: "203.0.113.99",
  trend: [{ ts: "2026-04-14T12:01", malicious: 1, suspicious: 0, benign: 1 }],
  lastUpdated: "2026-04-14T12:01:00Z",
};

const incidents = [
  {
    id: "trace-mal",
    sourceEventId: "event-mal",
    timestamp: "2026-04-14T12:01:00Z",
    severity: "malicious",
    headline: "203.0.113.99 targeted app-server",
    summary: "High priority event classified as malicious via hybrid",
    attackSource: "203.0.113.99",
    targetAsset: "app-server",
    classificationPath: "propose_response -> hybrid -> block_source_ip_on_firewall",
    confidence: 0.94,
    verdict: "malicious",
    priority: "high",
    planner: { route: "propose_response", priority: "high", reasons: ["high_signal:sql injection"] },
    detection: { method: "hybrid", reasons: ["known_attack_pattern"], evidence: { model_name: "autosentry-hybrid-v2" } },
    response: { action: "block_source_ip_on_firewall", status: "dry_run", mode: "dry_run", command_summary: "DRY RUN via ssh" },
    rawEvent: { src_ip: "203.0.113.99", dest_ip: "192.168.56.10" },
    normalizedFeatures: { feature_summary: { threat_cues: 1 } },
    assetContext: {},
    traceMetadata: { latency_ms: 12 },
  },
  {
    id: "trace-benign",
    sourceEventId: "event-benign",
    timestamp: "2026-04-14T12:00:00Z",
    severity: "benign",
    headline: "Management metrics request",
    summary: "Low priority event classified as benign via rule",
    attackSource: "192.168.56.1",
    targetAsset: "app-server",
    classificationPath: "skip -> rule -> notify_operator",
    confidence: 0.94,
    verdict: "benign",
    priority: "low",
    planner: { route: "skip", priority: "low", reasons: ["known_benign_management_path"] },
    detection: { method: "rule", reasons: ["planner_skip"], evidence: { model_name: "planner" } },
    response: { action: "notify_operator", status: "skipped", mode: "dry_run", command_summary: "No autonomous response required" },
    rawEvent: { src_ip: "192.168.56.1", dest_ip: "192.168.56.10" },
    normalizedFeatures: { feature_summary: { threat_cues: 0 } },
    assetContext: {},
    traceMetadata: { latency_ms: 8 },
  },
];

const assets = [
  {
    assetId: "app-server",
    hostname: "app-server",
    ip: "192.168.56.10",
    owner: "platform",
    criticality: "critical",
    osType: "linux",
    responseSurface: ["block_source_ip_on_host"],
    recentThreats: 1,
    lastStatus: "malicious",
    lastAction: "block_source_ip_on_firewall",
    lastSeen: "2026-04-14T12:01:00Z",
  },
];

const responses = [
  {
    id: "trace-mal",
    timestamp: "2026-04-14T12:01:00Z",
    verdict: "malicious",
    targetAsset: "app-server",
    action: "block_source_ip_on_firewall",
    status: "dry_run",
    mode: "dry_run",
    command_summary: "DRY RUN via ssh",
  },
];

const health = {
  ingest: { status: "running", lagSeconds: 2 },
  preprocess: { status: "running", featureVersion: "autosentry-feature-v2" },
  planner: { status: "running", lastRoute: "propose_response" },
  detector: { status: "running", model: "autosentry-hybrid-v2" },
  responder: { status: "dry_run", mode: "dry_run" },
  pipelineLatencyMs: 12,
  queueDepth: 2,
};

const graph = {
  nodes: [{ id: "src:203.0.113.99", label: "203.0.113.99", group: "source" }],
  edges: [{ from: "src:203.0.113.99", to: "incident:trace-mal" }],
};

function mockApi(payload = {}) {
  const data = {
    overview,
    incidents,
    assets,
    responses,
    health,
    graph,
    ...payload,
  };
  axios.get.mockImplementation((url) => {
    if (url.includes("/api/metrics/overview")) return Promise.resolve({ data: data.overview });
    if (url.includes("/api/incidents/live")) return Promise.resolve({ data: data.incidents });
    if (url.includes("/api/assets")) return Promise.resolve({ data: data.assets });
    if (url.includes("/api/responses")) return Promise.resolve({ data: data.responses });
    if (url.includes("/api/system/health")) return Promise.resolve({ data: data.health });
    if (url.includes("/api/graph")) return Promise.resolve({ data: data.graph });
    return Promise.reject(new Error(`Unhandled URL: ${url}`));
  });
}

describe("AutoSentry dashboard", () => {
  beforeEach(() => {
    mockApi();
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("loads incident data and allows page navigation", async () => {
    render(<App />);

    await waitFor(() => expect(screen.getAllByText("203.0.113.99 targeted app-server").length).toBeGreaterThan(0));

    expect(screen.getByText("Incident Stream")).toBeTruthy();
    expect(screen.getAllByText("DRY RUN via ssh").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Investigation" }));
    expect(await screen.findByText("Incident Constellation")).toBeTruthy();
    expect(screen.getByTestId("react-flow").textContent).toContain("nodes");

    fireEvent.click(screen.getByRole("button", { name: "Response Ops" }));
    expect(await screen.findByText("Response Ledger")).toBeTruthy();
    expect(screen.getByText("block_source_ip_on_firewall")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Asset Fleet" }));
    await waitFor(() => expect(screen.getAllByText("app-server").length).toBeGreaterThan(0));

    fireEvent.click(screen.getByRole("button", { name: "System Health" }));
    expect(await screen.findByText("Pipeline Latency")).toBeTruthy();
  });

  it("renders stable empty states when the API has no incidents", async () => {
    mockApi({
      overview: { ...overview, total: 0, activeIncidents: 0, malicious: 0, benign: 0, topSource: "n/a", trend: [] },
      incidents: [],
      assets: [],
      responses: [],
      graph: { nodes: [], edges: [] },
    });

    render(<App />);

    await waitFor(() => expect(screen.getByText("No incidents match the current filter.")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: "Asset Fleet" }));
    expect(await screen.findByText("No managed assets are available yet.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Response Ops" }));
    expect(await screen.findByText("No response actions have been planned or executed yet.")).toBeTruthy();
  });

  it("keeps the shell visible when API calls fail", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    axios.get.mockRejectedValue(new Error("offline"));

    render(<App />);

    await waitFor(() => expect(errorSpy).toHaveBeenCalled());
    expect(screen.getAllByText("AutoSentry").length).toBeGreaterThan(0);
    expect(screen.getByText("Incident Stream")).toBeTruthy();

    errorSpy.mockRestore();
  });
});
