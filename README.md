# SecureReview AI — Enterprise Code Security Platform

> An elite, AI-powered SAST + Bug Bounty platform combining the capabilities of CodeQL, Semgrep, Checkmarx, Snyk, Bearer, and Nuclei — with Gemini AI reasoning.

---

## 🛡️ Features

| Engine | Capability |
|---|---|
| **AST Engine** | 14-language parser (Tree-sitter + regex fallback) |
| **Taint Engine** | Interprocedural source → sink tracking |
| **Secret Engine** | 200+ patterns + Shannon entropy analysis |
| **AI Engine** | Gemini/Ollama: PoC gen, FP reduction, CVSS scoring |
| **Business Logic** | IDOR, race conditions, ATO, payment bypass, GraphQL |
| **Dependency** | OSV.dev CVE lookup, typosquatting, dependency confusion |
| **Rules** | 100+ SAST rules: Python, JS/TS, Java, PHP, Go, IaC |
| **Reports** | HackerOne, Executive, Developer, SARIF/JSON |

---

## 🚀 Quick Start

### Prerequisites
- Docker + Docker Compose
- Gemini API key (or local Ollama)

### 1. Configure
```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY
```

### 2. Start Platform
```bash
docker compose up --build
```

### 3. Access
- **Frontend**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Flower** (Celery monitor): http://localhost:5555

### 4. Register & Scan
1. Open http://localhost:3000
2. Register an account
3. Click **Scanner** → upload code or paste a GitHub URL
4. Choose a scan profile and launch

---

## 🔬 Scan Profiles

| Profile | Time | Description |
|---|---|---|
| **Quick** ⚡ | ~30s | Secrets + pattern rules |
| **Standard** 🛡️ | ~2min | Full SAST + taint + business logic |
| **Deep** 🧠 | ~5min | Standard + AI analysis for HIGH+ findings |
| **Bug Bounty** 🐛 | ~8min | Deep + PoC generation + H1 reports + bounty estimates |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Vite)                     │
│  Dashboard │ Scanner │ Findings │ Bug Bounty │ Reports       │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP + WebSocket
┌─────────────────────▼───────────────────────────────────────┐
│                 FastAPI Backend                               │
│  /auth │ /scans │ /findings │ /dashboard                    │
└──────────┬──────────────────────────┬───────────────────────┘
           │ Celery Task Queue        │ DB (async SQLAlchemy)
┌──────────▼────────────┐    ┌────────▼───────────────────────┐
│  Celery Workers        │    │     PostgreSQL                  │
│  ┌─────────────────┐  │    │  Users, Projects, Scans,        │
│  │  SAST Engine     │  │    │  Findings                       │
│  │  ├─ AST Engine   │  │    └────────────────────────────────┘
│  │  ├─ Taint Engine │  │
│  │  ├─ Secret Engine│  │    ┌────────────────────────────────┐
│  │  ├─ Dep Engine   │  │    │     Redis (Celery Broker)       │
│  │  ├─ Rules Engine │  │    └────────────────────────────────┘
│  │  ├─ BizLogic Eng │  │
│  │  └─ AI Engine    │  │    ┌────────────────────────────────┐
│  └─────────────────┘  │    │  Gemini AI / Ollama (local)     │
└───────────────────────┘    └────────────────────────────────┘
```

---

## 📁 Project Structure

```
secure-code-review/
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py          ← FastAPI entry
│       ├── config.py        ← Settings
│       ├── database.py      ← Async SQLAlchemy
│       ├── models/          ← SQLAlchemy models
│       ├── core/            ← Auth, RBAC
│       ├── engines/         ← 7 analysis engines
│       ├── rules/           ← 100+ SAST rules
│       ├── workers/         ← Celery tasks
│       └── routers/         ← FastAPI routers
└── frontend/
    ├── Dockerfile
    ├── src/
    │   ├── pages/           ← Dashboard, Scanner, Findings, BugBounty, Reports
    │   ├── components/      ← Sidebar, Toast
    │   └── api/             ← Axios client
    └── package.json
```

---

## 🔒 Security Notes

- JWT with RS256 (or HS256 configurable)
- bcrypt password hashing
- RBAC: Admin / Security Analyst / Developer
- API key support for CI/CD integration
- No `alg: none` JWT attack surface

---

## 📝 License

Enterprise Internal Use — All Rights Reserved
