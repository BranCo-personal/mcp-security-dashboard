# MCP Security Dashboard

A web-based security scanner for Model Context Protocol (MCP) servers. Detects vulnerabilities like tool poisoning, prompt injection, and cross-origin escalation attacks.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![React](https://img.shields.io/badge/React-18+-61dafb)
![License](https://img.shields.io/badge/License-MIT-green)

## 🎯 What This Does

MCP (Model Context Protocol) is the new standard for connecting AI agents to external tools. But with great power comes great attack surface. This dashboard helps you:

- **Scan MCP servers** for security vulnerabilities
- **Detect tool poisoning** — malicious instructions hidden in tool descriptions
- **Find prompt injection vectors** — hidden commands that hijack AI behavior
- **Identify data exfiltration risks** — tools that could leak sensitive data
- **Generate reports** — shareable findings for your team

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- mcp-scan installed (`pip install mcp-scan`)

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Backend runs at `http://localhost:8000`

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`

## 📊 Features

### Dashboard View
- Real-time scan status
- Risk level indicators (Critical/High/Medium/Low)
- Scan history with timestamps

### Vulnerability Details
- Tool name and description
- Attack vector explanation
- OWASP LLM Top 10 mapping
- Remediation suggestions

### Scanning Capabilities
- HTTP/SSE MCP servers
- Local stdio servers
- Claude Desktop configs
- Cursor/Windsurf configs

## 🔒 Vulnerabilities Detected

| Vulnerability | Description | Risk |
|--------------|-------------|------|
| Tool Poisoning | Malicious instructions in tool metadata | Critical |
| Prompt Injection | Hidden commands to hijack AI behavior | High |
| Cross-Origin Escalation | Tool shadowing across servers | High |
| Data Exfiltration | Unauthorized data transmission | Critical |
| Rug Pull Detection | Tool definitions that change post-install | Medium |

## 🛠️ Tech Stack

- **Backend**: FastAPI, SQLite, Python
- **Frontend**: React, Tailwind CSS, Vite
- **Scanner**: mcp-scan (Invariant Labs)

## 📁 Project Structure

```
mcp-security-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app
│   │   ├── scanner.py       # MCP scanning logic
│   │   ├── database.py      # SQLite operations
│   │   └── models.py        # Pydantic models
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   │       ├── ScanForm.jsx
│   │       ├── ResultsTable.jsx
│   │       └── VulnerabilityModal.jsx
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## 🎓 Learning Resources

- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/concepts/security)
- [Invariant Labs MCP Research](https://invariantlabs.ai/)

## License

MIT

## 👤 Author

Built by Michael Branigan

---

**Note**: This is a security research tool. Only scan MCP servers you have permission to test.
