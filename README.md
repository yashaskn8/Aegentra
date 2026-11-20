# Aegentra

Aegentra is an evidence-first software supply-chain security project based on the **SentinelAI SA-1.1** architectural specification.

**Current state: S1 foundation in shadow mode.** This is not a production security product. No live scans, deployment approvals, release activation, or AWS infrastructure are enabled.

## Stack

- Python 3.12+, FastAPI, Pydantic, SQLAlchemy, Alembic
- React, TypeScript, Vite
- PostgreSQL (AWS RDS for a future qualified deployment)
- Native Linux / EC2 / systemd; **no Docker or Kubernetes**

## Backend — local development

```bash
cd backend
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m pytest -q
uvicorn aegentra.api:app --reload
```

`GET http://127.0.0.1:8000/v1/health/live` provides minimal liveness. There are intentionally no public scan or deployment endpoints. A local-only manifest-validation route is exposed **only** when the application factory is explicitly called with `enable_local_shadow_preview=True` in tests.

To apply PostgreSQL schema migrations in a dedicated development database, set `AEGENTRA_DATABASE_URL` to a valid `postgresql+asyncpg://...` URL and run `cd backend && alembic upgrade head`. Do not use a privileged application database role in production.

## Frontend — local development

```bash
cd frontend
npm install
npm run dev
```

Vite's development proxy forwards `/v1` to the local FastAPI service. Review and commit an audited `package-lock.json` before enabling release builds or production CI; none is provided by this initial scaffold.

## Engineering rules

Read [AGENTS.md](AGENTS.md). Keep changes small, testable, and honest about gaps. The architecture's release authority, witness, protected origin, and offline EC2 workers are **future milestones**, not implemented controls.

See [implementation status](docs/implementation-status.md).
