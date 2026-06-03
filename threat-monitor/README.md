# 🔍 Real-time Threat Monitor

A cybersecurity tool for scanning network targets and detecting open ports in real-time.

## Tech Stack
- **Backend**: Python + FastAPI + WebSocket + SQLite
- **Frontend**: React + TypeScript
- **Scanner**: Nmap (optional, has demo mode)

## Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:py --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173

## Features
- Real-time port scanning via WebSocket
- Risk assessment (HIGH/MEDIUM/LOW)
- Scan history with SQLite storage
- 3 scan modes: Basic, Full, Stealth
- Demo mode if Nmap not installed

## Portfolio Note
Built as a cybersecurity demonstration tool combining:
- Network scanning (Nmap integration)
- Real-time communication (WebSocket)
- Modern React + TypeScript frontend
- RESTful API with FastAPI
