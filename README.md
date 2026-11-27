# Aegentra

Aegentra is an evidence-first software supply-chain security project based on the **SentinelAI SA-1.1** architectural specification.

**Current state: S1 foundation and nonproduction S2/S3 reference contracts in shadow mode.** This is not a production security product. No live scans, deployment approvals, release activation, or AWS infrastructure are enabled.

## Stack

- Python 3.12+, FastAPI, Pydantic, SQLAlchemy, Alembic
- React, TypeScript, Vite
- PostgreSQL (AWS RDS for a future qualified deployment)
- Native Linux / EC2 / systemd; **no Docker or Kubernetes**

## Adversarial security CI (nonproduction)

Every push to `main`, pull request and scheduled weekly security run checks
pinned GitHub Actions, least-privilege workflow tokens, high-confidence
tracked-text credentials, explicit fail-closed adversarial tests with no silent
skips, Python/npm dependency advisories and Python/JS/TS CodeQL. Both npm
projects now use committed, audited lockfiles and `npm ci`. See
[adversarial CI operations](docs/adversarial-ci.md).

The Python 3.12 backend now has a SHA-256-hashed dependency lock
(`backend/requirements.lock`), and CI publishes a deterministic, unsigned
CycloneDX inventory of Python, frontend and infrastructure packages. See
[Python supply-chain operations](docs/python-supply-chain.md).

CI does **not** prove that live AWS isolation, image provenance, physical
deletion, credential custody or production release gates are qualified.
Protected production is **NO-GO**.

## Backend — local development

```bash
cd backend
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e '.[dev]'
python -m pip check
python -m pytest -q
uvicorn aegentra.api:app --reload
```

`GET http://127.0.0.1:8000/v1/health/live` provides minimal liveness. There are intentionally no public scan or deployment endpoints. A local-only manifest-validation route is exposed **only** when the application factory is explicitly called with `enable_local_shadow_preview=True` in tests.

To apply PostgreSQL schema migrations in a dedicated development database, set `AEGENTRA_DATABASE_URL` to a valid `postgresql+asyncpg://...` URL and run `cd backend && alembic upgrade head`. Do not use a privileged application database role in production.

## Frontend — local development

```bash
cd frontend
npm ci
npm run dev
```

Vite's development proxy forwards `/v1` to the local FastAPI service. Frontend and infrastructure installs use committed audited npm lockfiles; these do not qualify protected production releases.

## Engineering rules

Read [AGENTS.md](AGENTS.md). Keep changes small, testable, and honest about gaps. The architecture's release authority, witness, protected origin, and offline EC2 workers are **future milestones**, not implemented controls.

See [implementation status](docs/implementation-status.md),
[SA-1.1 traceability](docs/sa11-traceability.md), and the
[engineering toolchain](docs/engineering-toolchain.md).

## Native S2 preflight (nonproduction)

The read-only `python -m aegentra.native_launch_preflight` entrypoint checks
an active fenced DB attempt, independently pinned AMI/root snapshot and AWS
isolation inventory, then produces a constrained **unexecuted** request-plan
digest. It never creates, attaches or launches an AWS resource. See
[the native launch preflight runbook](docs/native-launch-preflight.md) and
[physical detach verification](docs/native-detach-operations.md).

A separate **nonproduction, default-disabled** Python creation adapter
(`aegentra.native_creation_controller`) now journals physical
`PREPARED`/ `RECORDED`/ `UNKNOWN` requests before any AWS IO,
quarantines uncertain results, and records immutable physical IDs.
It is **not** a deployed EC2 worker or an authorization for live creation.
See [native creation operations](docs/native-creation-controller.md).

The new **default-disabled** physical-operation adapter
(`aegentra.native_physical_controller`) uses a separate immutable
PostgreSQL journal for exact raw EBS attachments and termination requests.
A termination ACK is not proof of detachment; the independent two-pass
inventory remains required. See
[physical-operation supervision](docs/native-physical-supervision.md).
No native guest is automatically launched or terminated.

A separate **default-disabled** native scan watchdog
(`aegentra.native_deadline_supervisor`) runs transaction-scoped 30-second
lease checks, never extends the 8-minute attempt deadline, and requests
termination through the previously journaled adapter when it must stop.
It is not a deployed/supervised daemon and cannot prove physical shutdown.
See [native deadline supervision](docs/native-deadline-supervisor.md).

## Authenticated shadow projections

When the OIDC and restricted PostgreSQL API are configured, the console can
browse linked, case-scoped evidence metadata and read-only scan-job status.
These routes return no executable submitted content and grant no release authority:

- `GET /v1/cases/{case_id}/evidence?page_size=50&cursor=...`: case-membership
  checked on every page; only linked same-asset SHA-256/kind/time metadata.
- `GET /v1/operations/scans`: ADMIN/ANALYST-only, organization-scoped view of
  up to 100 recent DB scan jobs, with explicit QUEUED, LEASED,
  PENDING_TRUSTED_VALIDATION and UNKNOWN states.

Native Chromium tests exercise session revocation on focus, browser Back
revalidation, and escaped rendering of hostile-looking case/evidence strings.
These tests use synthetic API fixtures; they do not demonstrate a deployed
independent origin, EC2 isolation or protected production readiness.

## OIDC browser sessions (opt-in)

The default `aegentra.api:app` exposes only liveness and no authentication or asset mutations.
To run the authenticated app, provide all of these externally managed settings:

```text
AEGENTRA_DATABASE_URL
AEGENTRA_OIDC_ISSUER
AEGENTRA_OIDC_AUTHORIZATION_URL
AEGENTRA_OIDC_TOKEN_URL
AEGENTRA_OIDC_JWKS_URL
AEGENTRA_OIDC_CLIENT_ID
AEGENTRA_OIDC_CLIENT_SECRET
AEGENTRA_OIDC_REDIRECT_URI
AEGENTRA_CSRF_KEY_HEX
```

All OIDC URLs and the callback must use HTTPS. The CSRF key must be at least 32 bytes,
hex encoded. The callback path is `/v1/auth/callback`. The provider identity must be
**pre-enrolled** by a trusted database administrator in `identities`; authenticating
does not create a user or assign an authorization role. Run the native migration before
enabling the app.

```bash
cd backend
alembic upgrade head
uvicorn aegentra.server:create_configured_app --factory
```

The backend sets host-only Secure/HttpOnly cookies; deploy behind a correctly configured
HTTPS reverse proxy. A plain HTTP Vite development proxy cannot complete the secure
cookie and strict-Origin flow. Do not weaken cookie security to make it work.

**Limitations:** This is an implementation foundation, not qualified production IAM.
Identity enrollment administration, ingress rate limits, hardened DB roles, and
independent security review remain outstanding. Frontend development currently uses
`npm install` because a reviewed lockfile has not been committed; do not treat the
frontend build as release-supply-chain qualified.
