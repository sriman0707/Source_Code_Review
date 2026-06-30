# 🚀 Running SecureReview AI Platform

Follow these steps to run the platform locally on Windows.

---

## 🛠️ Prerequisites: Start Database & Redis (Docker)

Keep only the PostgreSQL database and Redis services running in Docker:

```bash
docker compose up -d postgres redis
```

---

## 💻 Step 1: Run the Frontend UI (Port 5173 / 3000)

Open a terminal, navigate to the `frontend` directory, and start Vite:

```bash
cd frontend
npm install
npm run dev
```

---

## ⚙️ Step 2: Run the Backend API (Port 8000)

Open a second terminal, navigate to the `backend` directory, activate the virtual environment, and start Uvicorn:

```bash
cd backend
.\venv\Scripts\Activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🧠 Step 3: Run the Celery Worker (Scan Queue)

Open a third terminal, navigate to the `backend` directory, activate the virtual environment, and start the Celery worker (required to process code scans):

```bash
cd backend
.\venv\Scripts\Activate
celery -A app.workers.celery_app worker --loglevel=info -Q scans --pool=solo
```

---

## 🔗 Access Endpoints

- **Frontend UI**: [http://localhost:5173](http://localhost:5173) (or [http://localhost:3000](http://localhost:3000))
- **Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
