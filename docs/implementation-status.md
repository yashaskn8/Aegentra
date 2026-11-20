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
- Signed/sealed evidence ingestion, outbox, immutable audit chain, isolated analyzer, release governance, signing, protected serving, or AWS deployment.
- Production PostgreSQL role provisioning/permissions review and independent security testing.
- Frontend build verification and pinned npm lockfile.
- No production security decision may be made using these components.

Important RLS limitation: PostgreSQL custom transaction settings can be changed by a role capable of executing arbitrary SQL. RLS is defense in depth, not a substitute for authentication, least-privilege DB roles, parameterized queries, and server-owned organization scope.

Next: implement OIDC/BFF identity and authenticated asset APIs; exercise database permission boundaries and migrations under separate production-style roles.
