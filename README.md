# AutoSentry

AutoSentry is a demo-grade agentic Network Detection and Response (NDR) system. It ingests network/security events, normalizes them into flow features, routes them through planner and detection agents, records response decisions, and exposes the resulting incident traces to a React dashboard.

The project is designed for local experimentation and demos. By default, response execution runs in `dry_run` mode and the pipeline can replay sample NDJSON logs from `data/logs.ndjson`.

## Features

- Event ingestion from local NDJSON logs or checkpointed batches.
- Preprocessing and feature normalization for network events.
- Planner, detection, and response runtimes coordinated through a graph pipeline.
- Rule/ML-oriented anomaly detection with optional LLM escalation.
- Dashboard-ready trace persistence in `data/traces.ndjson`.
- Express API and Vite React frontend for incident, asset, response, health, and graph views.
- Python and JavaScript test coverage for pipeline, runtime, API, and frontend behavior.

## Project Structure

```text
AutoSentry/
├── agents/
│   ├── ingest_service.py              # Reads and replays raw NDJSON events
│   ├── preprocessor_runtime.py        # Runtime preprocessing/feature extraction
│   ├── planner_runtime.py             # Routing and prioritization logic
│   ├── detection_runtime.py           # Detection verdict and confidence logic
│   ├── response_runtime.py            # Response selection and dry-run execution
│   ├── *_agent.py                     # Agent-facing wrappers/legacy entry points
│   └── preprocessor_agent/            # Saved preprocessing pipeline and configs
├── anomaly_detection/                 # Model artifacts, notebooks, and detector experiments
├── core/
│   ├── graph.py                       # End-to-end agent graph orchestration
│   └── state.py                       # Shared pipeline state helpers
├── data/
│   ├── logs.ndjson                    # Raw demo/source events
│   ├── traces.ndjson                  # Pipeline trace output consumed by the dashboard
│   ├── managed_assets.json            # Local asset inventory
│   └── model_training/                # Training and cleaned datasets
├── frontend/
│   ├── backend/
│   │   ├── server.js                  # Express API for dashboard data
│   │   └── server.test.js             # Node API tests
│   └── frontend/
│       ├── src/                       # React dashboard source
│       ├── vite.config.js             # Vite configuration
│       └── src/App.test.jsx           # Vitest frontend tests
├── llm/                               # Prompt templates for planner/detection reasoning
├── tests/                             # Python pytest suite
├── tools/
│   └── seed_demo_logs.py              # Adds demo malicious events to data/logs.ndjson
├── utils/
│   ├── config.py                      # Environment-backed runtime settings
│   ├── db_logger.py                   # Trace/action persistence helpers
│   ├── schema.py                      # Event/trace schema helpers
│   └── asset_inventory.py             # Asset lookup and enrichment helpers
├── main.py                            # Python pipeline CLI
├── requirements.txt                   # Python runtime dependencies
└── .env.example                       # Example environment configuration
```

## Requirements

- Python 3.12+ or 3.13
- Node.js 20+ and npm
- Optional: an Ollama-compatible LLM endpoint if `AUTOSENTRY_ENABLE_LLM_ESCALATION=true`

## Setup

Create and activate a Python virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest
```

Install the dashboard dependencies:

```bash
cd frontend/backend
npm install

cd ../frontend
npm install
```

Optional environment setup:

```bash
cp .env.example .env
```

Most settings have defaults in `utils/config.py`. The most commonly changed values are:

```text
AUTOSENTRY_RESPONSE_MODE=dry_run
AUTOSENTRY_MAX_EVENTS_PER_RUN=150
AUTOSENTRY_ENABLE_LLM_ESCALATION=false
AUTOSENTRY_TRACE_LOG_PATH=data/traces.ndjson
AUTOSENTRY_ASSET_INVENTORY_PATH=data/managed_assets.json
```

## Running the Pipeline

Run a one-shot replay of recent local events:

```bash
python main.py
```

Run a smaller batch and clear the existing trace output first:

```bash
python main.py --fresh --limit 25
```

Process unread events using the ingest checkpoint:

```bash
python main.py --checkpoint --limit 25
```

Run continuously so the dashboard updates as trace data changes:

```bash
python main.py --live --mode replay --interval 3
```

Seed extra demo malicious events into `data/logs.ndjson`:

```bash
python tools/seed_demo_logs.py
```

Pipeline output is written to `data/traces.ndjson` by default.

## Running the Dashboard

Start the Express API from `frontend/backend`:

```bash
cd frontend/backend
npm install
node server.js
```

The API listens on `http://localhost:5000` unless `PORT` is set.

Start the React dashboard from `frontend/frontend`:

```bash
cd frontend/frontend
npm install
npm run dev
```

Vite prints the local dashboard URL, usually `http://localhost:5173`.

For the best live demo experience, run these in separate terminals:

1. `python main.py --live --mode replay --interval 3`
2. `cd frontend/backend && node server.js`
3. `cd frontend/frontend && npm run dev`

## Running Tests

Run the Python test suite from the repository root:

```bash
pytest
```

Print demo-friendly evidence while running Python tests:

```bash
pytest --demo-output
```

Run the backend API tests:

```bash
cd frontend/backend
npm test
```

Run the frontend tests:

```bash
cd frontend/frontend
npm test
```

Run frontend linting:

```bash
cd frontend/frontend
npm run lint
```

## Notes

- `data/*.ndjson` and `data/*.log` files are local runtime artifacts used by the pipeline and dashboard.
- Response actions default to dry-run behavior. Review `AUTOSENTRY_RESPONSE_MODE` before connecting real response execution.
- The dashboard reads incident traces through the backend API, so generate or seed trace data before expecting rich UI results.
