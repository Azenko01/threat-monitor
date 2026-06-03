import { useState, useEffect, useRef, useCallback } from "react";
import "./App.css";

interface Port {
  port: number;
  protocol: string;
  service: string;
  version: string;
  risk: "high" | "medium" | "low";
}

interface ScanResult {
  id: number;
  target: string;
  ports: Port[];
  os_info: string;
  risk_level: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  port_count: number;
  timestamp: string;
}

interface LogEntry {
  type: string;
  message: string;
  timestamp: string;
  data?: Port;
}

interface HistoryScan {
  id: number;
  target: string;
  timestamp: string;
  status: string;
  ports: Port[];
  os_info: string;
  risk_level: string;
}

type ScanType = "basic" | "full" | "stealth";

function App() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState<ScanType>("basic");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryScan[]>([]);
  const [activeTab, setActiveTab] = useState<"scan" | "history">("scan");
  const [livePorts, setLivePorts] = useState<Port[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const fetchHistory = useCallback(async () => {
    const res = await fetch("http://localhost:8000/api/history");
    const data = await res.json();
    setHistory(data);
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const startScan = () => {
    if (!target.trim()) return;
    setIsScanning(true);
    setLogs([]);
    setResult(null);
    setLivePorts([]);
    const ws = new WebSocket("ws://localhost:8000/ws/scan");
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ target: target.trim(), scan_type: scanType }));
    };
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      setLogs((prev) => [...prev, msg]);
      if (msg.type === "port_found" && msg.data) {
        setLivePorts((prev) => [...prev, msg.data]);
      }
      if (msg.type === "scan_complete") {
        setResult(msg.data);
        setIsScanning(false);
        fetchHistory();
      }
      if (msg.type === "error") setIsScanning(false);
    };
    ws.onclose = () => setIsScanning(false);
  };

  const stopScan = () => {
    wsRef.current?.close();
    setIsScanning(false);
  };

  const deleteHistory = async (id: number) => {
    await fetch(`http://localhost:8000/api/history/${id}`, { method: "DELETE" });
    fetchHistory();
  };

  const getRiskColor = (risk: string) => {
    switch (risk?.toUpperCase()) {
      case "HIGH": return "#ff3b3b";
      case "MEDIUM": return "#ffaa00";
      case "LOW": return "#00ff9d";
      default: return "#555";
    }
  };

  const getRiskBg = (risk: string) => {
    switch (risk?.toUpperCase()) {
      case "HIGH": return "rgba(255,59,59,0.1)";
      case "MEDIUM": return "rgba(255,170,0,0.1)";
      case "LOW": return "rgba(0,255,157,0.1)";
      default: return "rgba(85,85,85,0.1)";
    }
  };

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">⬡</span>
            <span className="logo-text">THREAT<span className="logo-accent">MONITOR</span></span>
          </div>
          <div className="header-status">
            <span className={`status-dot ${isScanning ? "pulsing" : ""}`}></span>
            <span>{isScanning ? "SCANNING..." : "READY"}</span>
          </div>
        </div>
        <nav className="nav">
          <button className={`nav-btn ${activeTab === "scan" ? "active" : ""}`} onClick={() => setActiveTab("scan")}>SCANNER</button>
          <button className={`nav-btn ${activeTab === "history" ? "active" : ""}`} onClick={() => setActiveTab("history")}>HISTORY ({history.length})</button>
        </nav>
      </header>
      <main className="main">
        {activeTab === "scan" && (
          <div className="scan-layout">
            <div className="panel control-panel">
              <div className="panel-header">TARGET CONFIGURATION</div>
              <div className="form-group">
                <label>TARGET IP / HOSTNAME</label>
                <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g. 192.168.1.1" onKeyDown={(e) => e.key === "Enter" && !isScanning && startScan()} disabled={isScanning} />
              </div>
              <div className="form-group">
                <label>SCAN TYPE</label>
                <div className="scan-types">
                  {(["basic", "full", "stealth"] as ScanType[]).map((t) => (
                    <button key={t} className={`scan-type-btn ${scanType === t ? "active" : ""}`} onClick={() => setScanType(t)} disabled={isScanning}>
                      <span>{t === "basic" ? "⚡" : t === "full" ? "🔬" : "👤"}</span>
                      <span>{t.toUpperCase()}</span>
                    </button>
                  ))}
                </div>
                <p className="scan-desc">
                  {scanType === "basic" && "Fast scan of common ports"}
                  {scanType === "full" && "All 65535 ports"}
                  {scanType === "stealth" && "SYN stealth scan"}
                </p>
              </div>
              <button className={`btn-scan ${isScanning ? "scanning" : ""}`} onClick={isScanning ? stopScan : startScan} disabled={!target.trim() && !isScanning}>
                {isScanning ? <><span className="spinner"></span> STOP SCAN</> : <>⬡ INITIATE SCAN</>}
              </button>
              {(isScanning || livePorts.length > 0) && (
                <div className="live-stats">
                  <div className="stat"><span className="stat-num">{livePorts.length}</span><span className="stat-label">PORTS</span></div>
                  <div className="stat"><span className="stat-num" style={{ color: "#ff3b3b" }}>{livePorts.filter((p) => p.risk === "high").length}</span><span className="stat-label">HIGH</span></div>
                  <div className="stat"><span className="stat-num" style={{ color: "#ffaa00" }}>{livePorts.filter((p) => p.risk === "medium").length}</span><span className="stat-label">MEDIUM</span></div>
                </div>
              )}
            </div>
            <div className="panel log-panel">
              <div className="panel-header">LIVE OUTPUT {isScanning && <span className="blink">●</span>}</div>
              <div className="log-container">
                {logs.length === 0 && <div className="empty-log">Awaiting scan target...</div>}
                {logs.map((log, i) => (
                  <div key={i} className={`log-entry log-${log.type}`}>
                    <span className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className="log-msg">{log.message}</span>
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
            <div className="panel results-panel">
              <div className="panel-header">SCAN RESULTS</div>
              {!result && livePorts.length === 0 && (
                <div className="empty-results">
                  <div className="radar"><div className="radar-ring"></div><div className="radar-ring"></div><div className="radar-sweep"></div></div>
                  <p>No results yet</p>
                </div>
              )}
              {livePorts.length > 0 && !result && (
                <div className="ports-list">
                  {livePorts.map((p, i) => (
                    <div key={i} className="port-card" style={{ borderColor: getRiskColor(p.risk), background: getRiskBg(p.risk) }}>
                      <div className="port-num">{p.port}</div>
                      <div className="port-info"><div className="port-service">{p.service}</div><div className="port-version">{p.version || p.protocol}</div></div>
                      <div className="port-risk" style={{ color: getRiskColor(p.risk) }}>{p.risk.toUpperCase()}</div>
                    </div>
                  ))}
                </div>
              )}
              {result && (
                <div className="result-container">
                  <div className="result-header" style={{ borderColor: getRiskColor(result.risk_level) }}>
                    <div><div className="result-target">{result.target}</div><div className="result-time">{new Date(result.timestamp).toLocaleString()}</div></div>
                    <div className="result-risk" style={{ color: getRiskColor(result.risk_level), background: getRiskBg(result.risk_level) }}>{result.risk_level}</div>
                  </div>
                  <div className="ports-list">
                    {result.ports.map((p, i) => (
                      <div key={i} className="port-card" style={{ borderColor: getRiskColor(p.risk), background: getRiskBg(p.risk) }}>
                        <div className="port-num">{p.port}</div>
                        <div className="port-info"><div className="port-service">{p.service}</div><div className="port-version">{p.version}</div></div>
                        <div className="port-risk" style={{ color: getRiskColor(p.risk) }}>{p.risk.toUpperCase()}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        {activeTab === "history" && (
          <div className="history-panel panel">
            <div className="panel-header">SCAN HISTORY</div>
            {history.length === 0 && <div className="empty-log">No scans yet</div>}
            <div className="history-list">
              {history.map((scan) => (
                <div key={scan.id} className="history-card">
                  <div className="history-main">
                    <div><div className="history-target">{scan.target}</div><div className="history-time">{new Date(scan.timestamp).toLocaleString()}</div></div>
                    <div className="history-stats">
                      <span className="history-ports">{scan.ports.length} ports</span>
                      <span className="history-risk" style={{ color: getRiskColor(scan.risk_level), background: getRiskBg(scan.risk_level) }}>{scan.risk_level}</span>
                      <button className="btn-delete" onClick={() => deleteHistory(scan.id)}>✕</button>
                    </div>
                  </div>
                  {scan.ports.length > 0 && (
                    <div className="history-ports-preview">
                      {scan.ports.slice(0, 5).map((p, i) => (
                        <span key={i} className="port-badge" style={{ background: getRiskBg(p.risk), color: getRiskColor(p.risk) }}>{p.port}/{p.service}</span>
                      ))}
                      {scan.ports.length > 5 && <span className="port-badge">+{scan.ports.length - 5} more</span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;