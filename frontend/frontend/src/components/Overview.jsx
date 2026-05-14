import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip } from "recharts";

const COLORS = ["#ff4b4b", "#FFD700", "#00cc66", "#999999"];

export default function Overview({ stats }) {
  if (!stats) return <div className="panel">Loading overview...</div>;

  const pieData = [
    { name: "Malicious", value: stats.malicious },
    { name: "Suspicious", value: stats.suspicious },
    { name: "Benign", value: stats.benign },
    { name: "Unknown", value: Math.max(0, stats.total - (stats.malicious + stats.suspicious + stats.benign)) }
  ];

  const lineData = (stats.trend || []).map(bucket => ({
    time: new Date(bucket.ts).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
    malicious: bucket.malicious || 0,
    suspicious: bucket.suspicious || 0,
    benign: bucket.benign || 0
  }));

  return (
    <div>
      <div className="header">
        <h3 className="title">Overview</h3>
        <div className="subtitle">Summary of recent activity</div>
      </div>

      <div style={{display:"flex", gap:12, marginTop:16}}>
        <div style={{flex:1}} className="panel">
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center"}}>
            <div>
              <div style={{fontSize:12, color:"#9aa0a6"}}>Total Logs</div>
              <div style={{fontSize:22, marginTop:6}}>{stats.total}</div>
            </div>
            <div>
              <div style={{fontSize:12, color:"#9aa0a6"}}>Malicious</div>
              <div style={{fontSize:20, color:"#ff4b4b"}}>{stats.malicious}</div>
            </div>
            <div>
              <div style={{fontSize:12, color:"#9aa0a6"}}>Suspicious</div>
              <div style={{fontSize:20, color:"#FFD700"}}>{stats.suspicious}</div>
            </div>
            <div>
              <div style={{fontSize:12, color:"#9aa0a6"}}>Benign</div>
              <div style={{fontSize:20, color:"#00cc66"}}>{stats.benign}</div>
            </div>
          </div>

          <div style={{height:240, marginTop:12}}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={lineData}>
                <XAxis dataKey="time" tick={{fontSize:11}} />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="malicious" stroke="#ff4b4b" dot={false} />
                <Line type="monotone" dataKey="suspicious" stroke="#FFD700" dot={false} />
                <Line type="monotone" dataKey="benign" stroke="#00cc66" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div style={{width:320}} className="panel">
          <h4 style={{marginTop:0}}>Severity Distribution</h4>
          <div style={{height:220}}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} dataKey="value" innerRadius={40} outerRadius={80} label>
                  {pieData.map((entry, idx) => <Cell key={`c-${idx}`} fill={COLORS[idx % COLORS.length]} />)}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="footer-note">Distribution of last {stats.total} logs</div>
        </div>
      </div>
    </div>
  );
}
