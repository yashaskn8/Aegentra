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

## November 21 code-level hardening (not a production gate)

- Untrusted manifest and package-lock JSON rejects nesting deeper than 128 before
  Python JSON object allocation. Brackets inside quoted strings are not nesting.
- Non-finite numeric JSON values and unbounded integer-decoder failures produce
  controlled invalid-evidence outcomes, not uncaught parser errors.
- The OIDC exchange rejects token responses that are JSON values other than an
  object, without issuing a browser session.
- The console removes asset/case views before session revalidation on focus,
  page return or access-denial responses. It also invalidates actionable stale
  cases on 409/412 and fences an in-flight asset mutation by session epoch.
- Native backend unit/PostgreSQL integration, frontend TypeScript/Vite build and
  CDK synthesis workflows passed on commit `2aff947d2ea61a73dde09cf85a83a0783e1d596b`.
  These checks do **not** exercise live browser role changes, browser Back,
  actual AWS isolation, or protected serving. DOM/browser adversarial tests
  remain a D9 qualification gap.

**Dead-code qualification is still open.** Tested protocol modules are not
necessarily reachable from a deployed service. In particular, infrastructure
prototypes and example systemd services are not permission to report a running
worker, witness, gateway, or qualified offline guest. An entry-point/reachability
review and actual native deployment evidence are required; do not label test-only
code as operational coverage.

## Native fixed-deadline scan watchdog — 21 November 2026

- `aegentra.guest_physical_operations.heartbeat_physical_attempt`
  now performs a transaction-scoped, nonce- and generation-bound lease check
  every 30 seconds, with an 8-minute attempt cap and 90-second lease window.
  Terminal or ambiguous operations cannot be renewed into trust.
- `aegentra.native_deadline_supervisor.supervise_native_attempt` adds
  a **default-disabled** bounded native loop. It stops renewals for expired,
  completed, revoked or quarantined attempts, delegates a single journaled
  termination request, and refuses to retry unknown AWS operations.
- Unit and restricted-role PostgreSQL integration tests cover heartbeat
  renewal, forged nonces, changed states, timeout escalation, clock drift,
  cancellation and missing/uncertain termination receipts. The loop does
  not hold PostgreSQL transactions while sleeping or making AWS calls.
- [Watchdog runbook](native-deadline-supervisor.md) documents the operating
  boundaries and independent qualification still required.

**Still missing:** independently deployed and supervised native service,
physical host/clock assurance, crash and DB-outage stop recovery, live AWS
isolation/AMI provenance, guest-visible volume/device and raw output
qualification. Production remains NO-GO.

## Native EBS attachment and termination supervision contracts — 21 November 2026

- Migration `0022_guest_physical_operations` introduces a bridge-only,
  RLS-scoped journal for ATTACH_INPUT, ATTACH_OUTPUT and TERMINATE, with
  immutable physical identities and terminal VERIFIED/REQUESTED/UNKNOWN
  outcomes.
- `aegentra.native_attachment_inventory` validates fresh STS/EC2
  readbacks of the exact guest, encrypted pinned volumes and device order,
  and denies foreign or untracked volume attachments.
- `aegentra.native_physical_controller` implements **default-disabled**
  attach and termination-request adapters. Every AWS operation requires a
  committed intent, occurs outside PostgreSQL locks and cannot be blindly
  retried after uncertainty. Only verified attachments advance; accepted
  termination is REQUESTED, not detached/terminated proof.
- PostgreSQL integration CI now actually runs the creation-intent tests
  together with the new physical-operation journal scenarios, including
  ordering, terminal outcomes, quarantined cleanup, tenant RLS and API-role
  rejection. Simulated AWS tests cover failed readback, timeouts and
  deadline/operator-stop admission.
- See the [physical supervision runbook](native-physical-supervision.md).

**Still unqualified:** independent AMI build and credentials, live guest
network/IMDS/volume-device drills, native automatically scheduled deadline
renewal and termination, raw input/output handling and incident janitor
reconciliation. No production AWS lifecycle has been exercised; NO-GO.

## Durable native AWS resource creation intents — 21 November 2026

- Migration `0021_guest_create_intents` adds a tenant-scoped, bridge-only
  creation-intent ledger with immutable plan/token identity and irreversible
  PREPARED → RECORDED/UNKNOWN transitions. Only recorded and non-reused
  physical IDs can advance the staged attempt.
- `aegentra.guest_creation` durably commits creation intent before AWS IO,
  enforces INPUT_EBS → OUTPUT_EBS → INSTANCE ordering, current lease
  generation, stable plan hash, and journaled result/unknown quarantine.
  Late results remain recorded for cleanup but cannot authorize guest use.
- `aegentra.native_creation_controller` implements the staged EC2 client
  adapter behind **default-disabled** live-mutation enablement, with no
  public API, CLI, daemon or deployed AWS changes.
- Tests use mock EC2 and native PostgreSQL roles to reject out-of-order,
  duplicated, altered and ambiguous requests, post-API database failures,
  stale-generation results and unauthorized cross-tenant reads.
  See the [native creation runbook](native-creation-controller.md).

**Not yet complete:** Independent permissioned AWS execution, physical
post-create inventory and approved attach, bounded running/termination,
device handling, external janitor reconciliation, qualified AMI build and
actual network/IMDS/egress drills. A synthetic success is not an
authorization predicate. Production remains NO-GO.

## Read-only EC2 launch preflight — 21 November 2026

- `python -m aegentra.native_launch_preflight` now checks a fenced
  resource-free RESERVED attempt before and after read-only AWS calls.
- A pinned private AMI and root EBS snapshot must have exact owner,
  state, encryption, KMS and size properties; the separate native isolation
  collector must verify its conservative VPC/route/DNS snapshot.
- The preflight constructs one fixed guest instance and two encrypted raw
  EBS requests with distinct idempotency tokens, then prints only a
  request hash and `SHADOW_ONLY_EXTERNAL_QUALIFICATION_REQUIRED`.
  It **never** invokes RunInstances, CreateVolume, AttachVolume or any
  other AWS mutation, and it does not authorize live guest execution.
- New adversarial tests cover public/wrong-owner/unpinned AMIs, root/snapshot
  changes, network/pin drift and stale DB leases. All three CI workflows
  passed on commit `81ff2c42023901b7f65ec610a584c257cd283b1a`.
- [Native preflight runbook](native-launch-preflight.md) documents its
  complete operating and qualification boundary.

**Still missing:** Independently approved, actually deployed EC2 create,
attach, terminate and timeout supervisor; guaranteed journal-before-use,
native physical/AMI trust, quotas, and independently witnessed hostile-input
and disposal drills. This remains a production NO-GO.

## Native guest custody hardening — 21 November 2026

- The bridge now rejects two identical or unspaced detached inventories.
  Two independent, timestamped EC2/EBS snapshots must be 30 seconds to
  5 minutes apart; the second must be fresh, neither can predate the recorded
  physical attempt, and both must match the pinned account and resource IDs.
- A strictly read-only native EC2/ST​S collector checks the exact terminated
  instance, two detached encrypted EBS volumes, metadata endpoint disabled,
  no IAM profile, account, tags and KMS identity. Missing or partial AWS
  results fail closed. No cloud mutation was made.
- Migration 0019 pins an immutable AMI ID per newly reserved attempt.
  Older NULL AMI records cannot be validated as trusted advisory results;
  no legacy AMI is silently inferred. Migration 0020 adds database-level
  physical-identity immutability, a forward-only guest state machine, and
  monotonic custody timestamps.
- `python -m aegentra.native_detach_worker` is a native one-shot entrypoint
  that reads the journal, performs two read-only inventories **outside**
  database transactions, then commits DETACHED_VERIFIED only after checks.
  See [native detach operation requirements](native-detach-operations.md).
- Unit and native PostgreSQL integration checks passed on commit
  `1e71eabb474d5197419e56f5bff574d143853bde`.
  They are fixture tests, not a deployed AWS/AMI qualification.

Outstanding S2 work: qualified native EC2 launch, termination and cleanup
supervision; physical image signing and build provenance; independent IAM,
no-route/no-IMDS/no-DNS/no-egress drills; raw volume identity binding and
hostile-input testing; durable external janitor operation. Production remains
NO-GO.

## Additional verified code and browser work — 21 November 2026

- New membership-scoped case evidence list with bounded keyset pagination,
  same-asset joins and explicit no-store response. Native PostgreSQL tests
  cover authorized paging, malformed tokens and denied unrelated identities.
- An ADMIN/ANALYST-only operations view reports real PostgreSQL scan-job
  statuses. It cannot claim clean analysis, completed validation or live
  queue/EC2 health; the API exposes no raw guest input or lease nonce.
- The frontend consumes both endpoints. In-memory evidence views disappear
  on unmount/access revocation, and untrusted strings stay escaped text.
- Added Vitest DOM regressions and native Chromium Playwright tests for
  focus and browser-Back reauthorization and inert content. All passed on
  `main` commit `9bd1966e42e9e23dcbe2bba2b4fadceb2eaa008b`.
- CI now enforces Python Ruff unused-import/local-variable/undefined-name
  checks and TypeScript unused-symbol checks. Earlier unused bindings were
  removed without skipping signed-veto and origin validation calls.

**Still not qualified:** Independent AWS accounts/roles and custodians,
hardware-backed reviewers, native EC2 creation/isolation and janitor,
live mTLS/witness/veto/origin, production browser/CDN bypass closure, full
evidence retention/consent/export and independent F01–F15 oracles. A green
local CI pipeline is not production certification. Code entry-point
reachability and deployment configuration still need independent assessment.

## Identity session revocation hardening

Browser sessions now pin the issuing identity's `membership_version`.
PostgreSQL automatically advances that version when identity active state,
role, issuer, subject, or organization changes, preventing old cookies from
becoming valid after reactivation or role changes. The 0018 migration leaves
preexisting browser sessions with a NULL version and invalidates them until
users authenticate again. Native PostgreSQL integration tests exercise both
re-enrollment and role-change rejection. This is not proof of hardened
production identity enrollment or independent revocation custody.
