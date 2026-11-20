# Implementation status — S1 foundation

Status: **shadow-only, not production-qualified**.

Implemented:
- Read-only liveness endpoint.
- Strict, side-effect-free metadata validator behind an explicitly test-only app factory option.
- Explicit scan coverage assessment; parser/required-check failure cannot produce a security approval.
- PostgreSQL organization, asset and evidence models; Alembic RLS migration.
- Internal transaction-scoped database session and explicitly tenant-filtered asset operations.
- Real native PostgreSQL integration testing for tenant separation, foreign key scope, and reused connections.
- Backend unit tests and GitHub Actions checks with no Docker or service containers.
- React/TypeScript dashboard shell without live scanning or enforcement.

Not implemented:
- OIDC/BFF sessions; the asset store is internal only and is not an HTTP endpoint.
- Signed/sealed evidence ingestion, independently witnessed immutable audit archive, outbox dispatcher, isolated analyzer, release governance, signing, protected serving, or AWS deployment.
- Production PostgreSQL role provisioning/permissions review and independent security testing.
- Frontend dependency lockfile and release-ready pinned supply-chain review.
- No production security decision may be made using these components.

Important RLS limitation: PostgreSQL custom transaction settings can be changed by a role capable of executing arbitrary SQL. RLS is defense in depth, not a substitute for authentication, least-privilege DB roles, parameterized queries, and server-owned organization scope.

Next: implement OIDC/BFF identity and authenticated asset APIs; exercise database permission boundaries and migrations under separate production-style roles.

The current database-local audit hash chain is not sufficient against database-administrator compromise; an independently governed archive is a later stage. Outbox records are durable but are not yet dispatched.

## S2 prototype (inert fixtures only)

- Added a bounded JavaScript Tree-sitter syntax analyzer (no execution, no automatic release approval), with explicit failure states and byte spans.
- Added a deterministic streaming SHA-256 verifier of server-authorized versioned blobs, with an injectable S3 adapter.
- These functions **must not process untrusted customer bytes in the API process**. The native offline EC2 guest and independent verifier are still unbuilt/unqualified.
- See [security release gates](security-release-gates.md) before making protected deployment claims.

## Investigation cases (S1)

- Cases are tenant- and asset-scoped and visible only to explicitly assigned case members.
- Case creation requires an enrolled ANALYST or ADMIN; it is idempotent and records a transactionally consistent audit/outbox event.
- A case member can link only existing evidence belonging to the same asset; cross-case and cross-org reads return no metadata.
- Case membership administration, retention policy, signed source provenance and a real evidence intake pipeline remain outstanding. Tests use synthetic metadata, not submitted hostile files.

## Console and query bounds

- React now displays assigned cases and supports authenticated case creation for ANALYST/ADMIN identities.
- Asset list queries cap the result set at 101, returning at most 100 and an explicit truncation flag.
- Case evidence bytes are still unavailable: the prior metadata-only evidence table is a fixture foundation, not a production ingest path.
