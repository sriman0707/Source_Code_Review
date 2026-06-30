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

## 🚀 Local Run Guide (Windows Manual Setup)

Follow these steps to run the platform locally on Windows:

### 1. Prerequisites: Start Database & Redis (Docker)
Keep only the PostgreSQL database and Redis services running in Docker:
```bash
docker compose up -d postgres redis
```

### 2. Run the Frontend UI (Port 5173 / 3000)
Open a terminal, navigate to the `frontend` directory, and start Vite:
```bash
cd frontend
npm install
npm run dev
```

### 3. Run the Backend API (Port 8000)
Open a second terminal, navigate to the `backend` directory, activate the virtual environment, and start Uvicorn:
```bash
cd backend
.\venv\Scripts\Activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Run the Celery Worker (Scan Queue)
Open a third terminal, navigate to the `backend` directory, activate the virtual environment, and start the Celery worker (required to process code scans):
```bash
cd backend
.\venv\Scripts\Activate
celery -A app.workers.celery_app worker --loglevel=info -Q scans --pool=solo
```

### 5. Access Endpoints
- **Frontend UI**: [http://localhost:5173](http://localhost:5173) (or [http://localhost:3000](http://localhost:3000))
- **Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

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
