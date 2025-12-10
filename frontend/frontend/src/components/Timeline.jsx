import React from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function Timeline({ stats, recentLogs }) {
  if (!stats) return <div className="panel">Loading timeline...</div>;

  const data = (stats.trend || []).map(b => ({
    time: new Date(b.ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}),
    malicious: b.malicious || 0,
    suspicious: b.suspicious || 0,
    benign: b.benign || 0
  }));

  return (
    <div>
      <div className="header">
        <h3 className="title">Timeline</h3>
        <div className="subtitle">Events over the last 60 minutes</div>
      </div>

      <div className="panel" style={{height:360}}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Area type="monotone" dataKey="benign" stackId="1" stroke="#00cc66" fill="#003b1a" />
            <Area type="monotone" dataKey="suspicious" stackId="1" stroke="#FFD700" fill="#3a3000" />
            <Area type="monotone" dataKey="malicious" stackId="1" stroke="#ff4b4b" fill="#3a0000" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
