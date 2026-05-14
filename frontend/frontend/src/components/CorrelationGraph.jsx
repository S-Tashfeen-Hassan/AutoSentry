import React, { useEffect, useState, useCallback } from "react";
import axios from "axios";
import { ReactFlow, Background, Controls } from "@xyflow/react";
import "@xyflow/react/dist/style.css";


function transform(nodes, edges) {
  // convert our simple nodes/edges format to react-flow format
  const rfNodes = nodes.map((n) => ({
    id: n.id,
    data: { label: n.label },
    position: { x: Math.random() * 600, y: Math.random() * 400 },
    style: {
      padding: 8,
      borderRadius: 6,
      background: n.group === "ip" ? "#0b3" : (n.group === "planner" ? "#033" : (n.group === "detection" ? "#330" : "#222")),
      color: "#fff",
      border: "1px solid rgba(255,255,255,0.06)"
    }
  }));

  const rfEdges = edges.map((e, i) => ({
    id: `e${i}`,
    source: e.from,
    target: e.to,
    animated: true,
    style: { stroke: "rgba(255,255,255,0.08)" }
  }));

  return { rfNodes, rfEdges };
}

export default function CorrelationGraph() {
  const [elements, setElements] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);

  const fetchGraph = useCallback(async () => {
    try {
      const res = await axios.get("http://localhost:5000/api/graph");
      const { nodes, edges } = res.data;
      const { rfNodes, rfEdges } = transform(nodes, edges);
      setElements({ nodes: rfNodes, edges: rfEdges });
      setLoading(false);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    const timeoutId = setTimeout(fetchGraph, 0);
    const id = setInterval(fetchGraph, 5000);
    return () => {
      clearTimeout(timeoutId);
      clearInterval(id);
    };
  }, [fetchGraph]);

  return (
    <div>
      <div className="header">
        <h3 className="title">Correlation Graph</h3>
        <div className="subtitle">Planner → Detection → Response chains</div>
      </div>

      <div className="panel" style={{height:600}}>
        {loading ? <div>Loading graph...</div> :
          <ReactFlow nodes={elements.nodes} edges={elements.edges} fitView>
            <Background />
            <Controls />
          </ReactFlow>
        }
      </div>
    </div>
  );
}
