# Implementation status — Aegentra / SA-1.1

**Verdict: conditional GO for local/native development and shadow trials; NO-GO
for protected production traffic or certification.** Passing GitHub CI is not
an independent security qualification. No customer origin, AWS account, KMS
root, native EC2 workload, or public gateway has been deployed by this repo
workflow. This document describes code at the current `main` branch.

The supported phase-1 release profile is **one enrolled controlled static
origin, one exact HTML entry document and one same-origin classic JavaScript
resource**. Arbitrary React builds, third-party CDNs, dynamic dependency
loaders and generic web ecosystems remain investigation/shadow only.

## Additional completed contracts in this implementation pass

- **S0 independently signed origin scope:** customer-origin owner and
  security-custodian signatures, distinct AWS account IDs, pinned generated
  HTML template and digest-addressed classic JavaScript, exact CSP/header
  profile and enforced SHADOW_PENDING_INDEPENDENT_QUALIFICATION result.
  No browser approval, automatic enrollment or ENFORCED activation.
- **S2 native cleanup controls:** immutable EBS/EC2 IDs, advisory receipt
  dependency, durable DELETE_REQUESTED intent, narrowly scoped janitor
  DeleteVolume requests, strict read-only AWS NotFound inventory and two
  time-separated confirmations before DISPOSED. All AWS responses in CI
  are synthetic; no EBS resource was deleted in an AWS account.
- **S4 incident/recovery cases:** triage and containment-request transitions
  under case membership, CSRF and optimistic revision fencing; case statuses
  cannot be promoted to CONTAINED by browser requests. Recovery preflight
  reports missing external STOP, writer fencing, tombstones, consent, audit,
  witness and custodians but never clears STOP.
- **Security CDK:** distinct retained P-256 KMS witness and veto signing
  keys with no workload/API grants. AWS key policies and independent custody
  are not deployed or qualified.

## Built and exercised with native CI fixtures

- **Identity/API/console (S1):** FastAPI BFF with OIDC code/PKCE/nonce/session
  protection, authenticated assets and assigned case routes, tenant/asset
  scope and a bounded React/TypeScript/Vite console.
- **PostgreSQL (S1):** Alembic migrations, FORCE RLS, composite scoped foreign
  keys, independently restricted API/bridge/validator/release/observer/outbox
  CI roles, and transactionally coupled hash-chain audit plus outbox.
- **Content intake (S1/S2):** Canonical content manifests, bounded staging
  tickets and checksum-constrained S3 presigned PUT contracts. Finalized
  uploads remain AWAITING_VERIFICATION until a distinct verifier checks the
  exact S3 versions and bytes.
- **Static analysis (S2):** Inert JS Tree-sitter and npm lockfile inspection,
  explicit unknown coverage, fenced PostgreSQL scan jobs, bounded raw guest
  protocol, readback validation, EC2/EBS custody journal, and unsigned
  advisory scan receipts. No customer code is imported or executed by API.
- **Private review/release contracts (S2/S3):** Canonical review subject,
  independently enrolled two-reviewer signature verification, shadow-only
  signed grants and consumed nonce/selection sequence, distinct witness
  certificate, conditional immutable S3 archive, guarded private publish,
  publication receipt sealing, and nonce-bound KMS head generation.
  Synthetic ENFORCED state used **only in native database tests**; normal API
  does not expose ENFORCED enrollment or privileged signing.
- **Reference serving (S3):** Standalone fail-closed ASGI gateway prebuffers
  exact immutable bytes, checks signed headers/witness/current head twice,
  queries a fresh signed independent veto last, and refuses range/conditional
  variants. It is not connected to a real customer origin or CDN.
- **Observability/incident (S3/S4):** Signed independent client-facing
  observation contract; historical mismatch vs current STOP distinction,
  overdue/missing coverage HOLD; separate security-account STOP CAS code,
  signed authority/gateway acknowledgment and drain-deadline verification.
- **Native events (S4):** Bounded, per-stream ordered PostgreSQL outbox
  delivery leases, retry/replay fencing, separate dispatcher role, one-shot
  SQS FIFO adapter, and systemd service/timer examples. Remote consumer
  idempotency and real queue receipt semantics remain unqualified.

## Not yet operating or independently qualified

- Actual 3-account separation, independent IAM/KMS administrators and
  human hardware-backed credential enrollment/revocation.
- Native disposable EC2 guest lifecycle, AMI build provenance, no-route/no-
  IMDS/no-IAM runtime drills, volume attach/detach, trusted byte acquisition,
  deployed automated janitor, SQS controller and secure guest execution qualification.
- Signed source-builder provenance and independent two-channel final-byte
  provenance; an offline parser can never certify semantic safety.
- External root/veto monotonic floor, retained append-only history, physical
  AWS S3 Object Lock retention/versioning and recovery/rotation custodians.
- Actual enrolled origin, bypass-closure, no-other-script/resource controls,
  live head and signed security services with mTLS, browser/CDN fidelity,
  bounded admission/writes and independent cohort readback.
- Live emergency-STOP endpoint and enrolled gateway registry, signed
  acknowledgments persisted externally, independent containment/resume drill.
- End-to-end retained audit/checkpoint archive, external consumer retries and
  DLQ, quotas, retention/tombstones, exports, consent, full incident workflows.
- Load/cost/availability capacity and restoration drills, sealed Matrix C
  oracles and independent verification of applicable F01–F15 tests.
- Optional AI broker, consent-controlled egress and blind evaluation (S5).

Never interpret a static scan, successful artifact hash, signed fixture or a
passing test as production release authorization. This repo intentionally
does not deploy protected resources without customer-owned infrastructure
enrollment and independent P0 qualification.

Native stack remains Python/FastAPI/SQLAlchemy/Alembic/PostgreSQL,
React/TypeScript/Vite, AWS CDK/EC2/systemd. **No Docker, Compose, containers
or Kubernetes.**

## Identity session revocation hardening

Browser sessions now pin the issuing identity's `membership_version`.
PostgreSQL automatically advances that version when identity active state,
role, issuer, subject, or organization changes, preventing old cookies from
becoming valid after reactivation or role changes. The 0018 migration leaves
preexisting browser sessions with a NULL version and invalidates them until
users authenticate again. Native PostgreSQL integration tests exercise both
re-enrollment and role-change rejection. This is not proof of hardened
production identity enrollment or independent revocation custody.
