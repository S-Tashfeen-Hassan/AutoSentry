import React from "react";

export default function Navbar({ page, setPage }) {
  const items = [
    { id: "overview", label: "Overview" },
    { id: "live", label: "Live Feed" },
    { id: "timeline", label: "Timeline" },
    { id: "graph", label: "Correlation Graph" },
    { id: "health", label: "Agent Health" }
  ];

  return (
    <header 
      style={{
        background: "#1a1a1a",
        borderBottom: "1px solid #2a2a2a",
        padding: "10px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        position: "sticky",
        top: 0,
        zIndex: 100
      }}
    >
      {/* Branding */}
      <div style={{ display: "flex", flexDirection: "column" }}>
        <span style={{ fontSize: 20, fontWeight: 600, color: "#00bfff" }}>Autosentry</span>
        <span style={{ fontSize: 12, color: "#9aa0a6" }}>Agentic Detection & Response</span>
      </div>

      {/* Navigation Items */}
      <nav style={{ display: "flex", gap: 26 }}>
        {items.map(it => (
          <div
            key={it.id}
            onClick={() => setPage(it.id)}
            style={{
              cursor: "pointer",
              padding: "8px 12px",
              borderRadius: 6,
              color: page === it.id ? "#00bfff" : "#e0e0e0",
              background: page === it.id ? "#0f0f0f" : "transparent",
              transition: "all 0.2s",
              fontWeight: page === it.id ? 600 : 400,
              fontSize: 14
            }}
            onMouseEnter={e => {
              if (page !== it.id) e.target.style.color = "#6cd6ff";
            }}
            onMouseLeave={e => {
              if (page !== it.id) e.target.style.color = "#e0e0e0";
            }}
          >
            {it.label}
          </div>
        ))}
      </nav>

      {/* Backend Info */}
      <div style={{ color: "#7f8c8d", fontSize: 13 }}>
        Backend: http://localhost:5000
      </div>
    </header>
  );
}
