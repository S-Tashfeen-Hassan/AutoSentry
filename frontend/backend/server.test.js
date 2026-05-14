const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "autosentry-backend-"));
process.env.AUTOSENTRY_TRACE_LOG_PATH = path.join(tmpDir, "traces.ndjson");
process.env.AUTOSENTRY_ASSET_INVENTORY_PATH = path.join(tmpDir, "managed_assets.json");
process.env.AUTOSENTRY_API_TRACE_CACHE_LIMIT = "3";

const request = require("supertest");
const { app, resetCachesForTests } = require("./server");

function writeFixture({ traces = [], assets = [] } = {}) {
  fs.writeFileSync(
    process.env.AUTOSENTRY_TRACE_LOG_PATH,
    `${traces.map((trace) => JSON.stringify(trace)).join("\n")}\n{bad-json\n`,
    "utf8"
  );
  fs.writeFileSync(process.env.AUTOSENTRY_ASSET_INVENTORY_PATH, JSON.stringify(assets), "utf8");
  resetCachesForTests();
}

function trace(id, verdict, loggedAt, overrides = {}) {
  return {
    event_id: `event-${id}`,
    timestamp: "2026-04-14T12:00:00Z",
    raw_event: {
      src_ip: overrides.srcIp || "203.0.113.99",
      dest_ip: overrides.destIp || "192.168.56.10",
    },
    normalized_features: { feature_version: "autosentry-feature-v2" },
    planner_result: { route: overrides.route || "fast_detect", priority: overrides.priority || "medium" },
    detection_result: {
      verdict,
      method: overrides.method || "hybrid",
      confidence: overrides.confidence ?? 0.82,
      evidence: { model_name: "autosentry-hybrid-v2" },
    },
    response_result: {
      action: overrides.action || "notify_operator",
      status: overrides.status || "completed",
      mode: "dry_run",
      command_summary: "Escalated incident to operator queue",
    },
    asset_context: overrides.assetContext || {},
    trace_metadata: {
      trace_id: `trace-${id}`,
      logged_at: loggedAt,
      processed_at: loggedAt,
      latency_ms: 12,
    },
  };
}

test("dashboard API returns overview, incidents, details, graph, assets, responses, and health", async () => {
  writeFixture({
    traces: [
      trace("old", "benign", "2026-04-14T12:00:00Z"),
      trace("new", "malicious", "2026-04-14T12:01:00Z", {
        action: "block_source_ip_on_firewall",
        status: "dry_run",
        assetContext: { target_asset: { hostname: "app-server" } },
      }),
    ],
    assets: [
      {
        asset_id: "app-server",
        hostname: "app-server",
        ip: "192.168.56.10",
        asset_owner: "platform",
        criticality: "critical",
        os_type: "linux",
        allowed_actions: ["block_source_ip_on_host"],
      },
    ],
  });

  const overview = await request(app).get("/api/metrics/overview").expect(200);
  assert.equal(overview.body.total, 2);
  assert.equal(overview.body.malicious, 1);
  assert.equal(overview.body.benign, 1);
  assert.equal(overview.body.defendedAssets, 1);

  const live = await request(app).get("/api/incidents/live").expect(200);
  assert.equal(live.body[0].id, "trace-new");
  assert.equal(live.body[0].verdict, "malicious");

  const detail = await request(app).get("/api/incidents/trace-new").expect(200);
  assert.equal(detail.body.sourceEventId, "event-new");

  await request(app).get("/api/incidents/missing").expect(404);

  const assets = await request(app).get("/api/assets").expect(200);
  assert.equal(assets.body[0].assetId, "app-server");
  assert.equal(assets.body[0].recentThreats, 2);

  const responses = await request(app).get("/api/responses").expect(200);
  assert.equal(responses.body[0].action, "block_source_ip_on_firewall");

  const health = await request(app).get("/api/system/health").expect(200);
  assert.equal(health.body.ingest.status, "running");
  assert.equal(health.body.traceCache.limit, 3);

  const graph = await request(app).get("/api/graph").expect(200);
  assert.ok(graph.body.nodes.length > 0);
  assert.ok(graph.body.edges.length > 0);
});

test("dashboard API returns stable empty contracts", async () => {
  writeFixture();

  const overview = await request(app).get("/api/metrics/overview").expect(200);
  const incidents = await request(app).get("/api/incidents/live").expect(200);
  const assets = await request(app).get("/api/assets").expect(200);
  const health = await request(app).get("/api/system/health").expect(200);

  assert.equal(overview.body.total, 0);
  assert.deepEqual(incidents.body, []);
  assert.deepEqual(assets.body, []);
  assert.equal(health.body.ingest.status, "idle");
});
