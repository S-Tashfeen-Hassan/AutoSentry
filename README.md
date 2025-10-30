AgenticNDR/
│
├── core/
│   ├── graph.py                 # LangGraph orchestration (planner → detection → response)
│   ├── state.py                 # Agent state management + message context
│
├── agents/
│   ├── planner_agent.py         # Coordinates workflow, queries detection, triggers response
│   ├── detection_agent.py       # Uses ML + LLM via LangChain
│   ├── response_agent.py        # Executes actions, logs back to Graylog
│   ├── monitor_agent.py         # Observes performance, uptime, and alerts
│
├── llm/
│   ├── detection_prompt.py      # Prompt templates for reasoning-based detection
│   ├── planner_prompt.py
│
├── utils/
│   ├── graylog_api.py           # Pulls logs from Graylog REST API
│   ├── config.py                # API keys, model paths
│   ├── db_logger.py             # Writes agent reasoning to MongoDB or Elasticsearch
│
├── frontend/
│   ├── streamlit_app.py         # Interactive SOC dashboard
│
└── main.py                      # Entry point (initializes graph + starts agents)
