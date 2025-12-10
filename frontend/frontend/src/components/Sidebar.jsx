import React from "react";

export default function Sidebar({ page, setPage }) {
  const items = [
    { id: "overview", label: "Overview" },
    { id: "live", label: "Live Feed" },
    { id: "timeline", label: "Timeline" },
    { id: "graph", label: "Correlation Graph" },
    { id: "health", label: "Agent Health" }
  ];

  return (
    <aside className="sidebar">
      <div style={{textAlign:"center", marginBottom:12}}>
        <h2 style={{color:"#00bfff", margin:"6px 0"}}>Autosentry</h2>
        <div style={{color:"#9aa0a6", fontSize:13}}>Agentic Detection & Response</div>
      </div>

      <nav style={{marginTop:18}}>
        {items.map(it => (
          <div key={it.id}
               className={`nav-item ${page === it.id ? "active" : ""}`}
               onClick={() => setPage(it.id)}>
            <div>{it.label}</div>
          </div>
        ))}
      </nav>
    </aside>
  );
}
