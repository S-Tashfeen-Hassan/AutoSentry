import React, { useEffect, useState } from "react";
import axios from "axios";

export default function AgentHealth() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await axios.get("http://localhost:5000/api/health");
        setHealth(res.data);
      } catch (e) {
        console.error(e);
      }
    };
    fetch();
    const id = setInterval(fetch, 3000);
    return () => clearInterval(id);
  }, []);

  if (!health) return <div className="panel">Loading health...</div>;

  return (
    <div>
      <div className="header">
        <h3 className="title">Agent Health</h3>
        <div className="subtitle">Status of Planner, Detection, and Response agents</div>
      </div>

      <div className="panel">
        {["planner","detection","response"].map(k => (
          <div key={k} style={{display:"flex", justifyContent:"space-between", padding:"8px 0", borderBottom:"1px solid rgba(255,255,255,0.02)"}}>
            <div style={{textTransform:"capitalize"}}>{k}</div>
            <div>
              <span style={{marginRight:12}}>{health[k].status}</span>
              <span style={{color:"#9aa0a6"}}>{health[k].last_seen_seconds_ago}s ago</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
