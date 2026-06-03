import asyncio
import json
import sqlite3
import subprocess
import re
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Real-time Threat Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        timestamp TEXT,
        status TEXT,
        ports TEXT,
        os_info TEXT,
        risk_level TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"

def assess_risk(ports):
    dangerous = {21, 23, 445, 3389, 5900}
    medium = {22, 80, 8080, 3306}
    if any(p.get("port") in dangerous for p in ports):
        return "HIGH"
    elif any(p.get("port") in medium for p in ports):
        return "MEDIUM"
    elif ports:
        return "LOW"
    return "NONE"

async def run_nmap_scan(target, scan_type, websocket):
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if scan_type == "full":
        cmd = [nmap_path, "-p-", "--open", "-T4", target]
    else:
        cmd = [nmap_path, "--open", "-T4", target]

    await websocket.send_json({
        "type": "status",
        "message": f"Starting {scan_type} scan on {target}...",
        "timestamp": datetime.now().isoformat()
    })

    ports = []
    os_info = "Unknown"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for line in result.stdout.split("\n"):
            line = line.strip()
            port_match = re.match(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
            if port_match:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                service = port_match.group(3)
                version = port_match.group(4).strip()
                port_info = {
                    "port": port_num,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "risk": "high" if port_num in [21, 23, 445, 3389, 5900] else "medium" if port_num in [22, 80, 8080] else "low"
                }
                ports.append(port_info)
                await websocket.send_json({
                    "type": "port_found",
                    "data": port_info,
                    "message": f"Found open port: {port_num}/{protocol} ({service})",
                    "timestamp": datetime.now().isoformat()
                })
    except Exception as e:
        await websocket.send_json({
            "type": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        })

    risk_level = assess_risk(ports)
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (target, timestamp, status, ports, os_info, risk_level) VALUES (?, ?, ?, ?, ?, ?)",
        (target, datetime.now().isoformat(), "completed", json.dumps(ports), os_info, risk_level)
    )
    scan_id = c.lastrowid
    conn.commit()
    conn.close()

    await websocket.send_json({
        "type": "scan_complete",
        "data": {
            "id": scan_id,
            "target": target,
            "ports": ports,
            "os_info": os_info,
            "risk_level": risk_level,
            "port_count": len(ports),
            "timestamp": datetime.now().isoformat()
        },
        "message": f"Scan complete! Found {len(ports)} open ports. Risk: {risk_level}",
        "timestamp": datetime.now().isoformat()
    })

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        target = data.get("target", "").strip()
        scan_type = data.get("scan_type", "basic")
        if not target:
            await websocket.send_json({"type": "error", "message": "No target specified", "timestamp": datetime.now().isoformat()})
            return
        await run_nmap_scan(target, scan_type, websocket)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e), "timestamp": datetime.now().isoformat()})
        except:
            pass

@app.get("/api/history")
def get_history():
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "timestamp": r[2], "status": r[3], "ports": json.loads(r[4]) if r[4] else [], "os_info": r[5], "risk_level": r[6]} for r in rows]

@app.delete("/api/history/{scan_id}")
def delete_scan(scan_id: int):
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.get("/")
def root():
    return {"status": "OK"}