import React, { useEffect, useState } from "react";
import axios from "axios";
import Sidebar from "./components/Sidebar";
import Overview from "./components/Overview";
import LiveFeed from "./components/LiveFeed";
import Timeline from "./components/Timeline";
import CorrelationGraph from "./components/CorrelationGraph";
import AgentHealth from "./components/AgentHealth";

export default function App() {
  const [page, setPage] = useState("overview");
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);

  // Poll stats and recent logs every 3s (charts/overview)
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [statsRes, logsRes] = await Promise.all([
          axios.get("http://localhost:5000/api/stats"),
          axios.get("http://localhost:5000/api/logs/recent?n=200")
        ]);
        setStats(statsRes.data);
        setRecentLogs(logsRes.data);
      } catch (e) {
        console.error("fetchAll error", e);
      }
    };

    fetchAll();
    const id = setInterval(fetchAll, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="app">
      <Sidebar page={page} setPage={setPage} />
      <main className="main">
        {page === "overview" && <Overview stats={stats} recentLogs={recentLogs} />}
        {page === "live" && <LiveFeed />}
        {page === "timeline" && <Timeline stats={stats} recentLogs={recentLogs} />}
        {page === "graph" && <CorrelationGraph />}
        {page === "health" && <AgentHealth />}
      </main>
    </div>
  );
}
