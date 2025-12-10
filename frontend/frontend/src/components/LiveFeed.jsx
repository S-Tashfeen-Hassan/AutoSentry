import React, { useEffect, useState } from "react";
import axios from "axios";

function colorFor(p, d) {
  if (p === "suspicious" && d === "malicious") return "#ff4b4b";
  if (p === "suspicious" && d === "benign") return "#FFD700";
  if (p === "benign" || d === "benign") return "#00cc66";
  if (p === "malicious" || d === "malicious") return "#ff4b4b";
  return "#999999";
}
function iconFor(p, d) {
  if (p === "suspicious" && d === "malicious") return "🔴";
  if (p === "suspicious" && d === "benign") return "🟡";
  if (p === "benign" || d === "benign") return "🟢";
  if (p === "malicious" || d === "malicious") return "🔴";
  return "⚪";
}

export default function LiveFeed() {
  const [results, setResults] = useState([]);
  useEffect(() => {
    // initial load of last 50
    axios.get("http://localhost:5000/api/logs/recent?n=50").then(r => {
      setResults(r.data);
    }).catch(()=>{});

    const id = setInterval(async () => {
      try {
        const res = await axios.get("http://localhost:5000/api/logs/new");
        if (Array.isArray(res.data) && res.data.length > 0) {
          setResults(prev => {
            const combined = prev.concat(res.data);
            return combined.slice(-500); // keep last 500 in memory
          });
        }
      } catch (e) {
        console.error("poll error", e);
      }
    }, 1000);

    return () => clearInterval(id);
  }, []);

  const last50 = [...results].slice(-50).reverse();
  return (
    <div>
      <div className="header">
        <h3 className="title">Live Feed</h3>
      </div>

      <div style={{marginTop:12}} className="count">Showing last {last50.length} entries</div>

      {last50.map((r,i) => {
        const planner = r.planner || {};
        const detection = r.detection || {};
        const pVerdict = (planner.verdict || "unknown").toLowerCase();
        const dVerdict = (detection.verdict || "unknown").toLowerCase();
        const color = colorFor(pVerdict, dVerdict);
        const icon = iconFor(pVerdict, dVerdict);

        return (
          <div key={r.log_id + "-" + i} className="log-card" style={{borderLeft:`6px solid ${color}`}}>
            <h4 className="log-title" style={{color}}>{icon} Log <code>{r.log_id}</code></h4>
            <div className="log-meta">
              <b>Planner Verdict:</b> {pVerdict} &nbsp; | &nbsp;
              <b>Detection Verdict:</b> {dVerdict} &nbsp; | &nbsp;
              <b>Logged At:</b> {r.logged_at}
            </div>

            <details>
              <summary style={{cursor:"pointer", color:"#00bfff"}}>Detailed Analysis</summary>
              <div className="json-block">
                <b>Planner:</b>
                <pre>{JSON.stringify(planner, null, 2)}</pre>
              </div>
              <div className="json-block">
                <b>Detection:</b>
                <pre>{JSON.stringify(detection, null, 2)}</pre>
              </div>
              <div className="json-block">
                <b>Response:</b>
                <pre>{JSON.stringify(r.response || {status:"No action triggered"}, null, 2)}</pre>
              </div>
            </details>
          </div>
        );
      })}
    </div>
  );
}
