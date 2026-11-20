# Implementation status — S1 foundation

Status: **shadow-only, not production-qualified**.

Implemented in this PR:
- Read-only liveness endpoint.
- Strict, side-effect-free metadata manifest validator, behind an explicit test-only app factory option.
- Explicit scan-coverage assessment; parser/required-check failure cannot produce an approval.
- Initial PostgreSQL organization, asset and evidence models with composite scoped references and a migration declaring FORCE RLS.
- Unit tests and a native Python GitHub Actions workflow.
- React/TypeScript dashboard shell; no browser evidence ingestion or active security claims.

Not implemented:
- OIDC/BFF sessions, scoped PostgreSQL connections, verified runtime RLS, sealed evidence ingestion, outbox, immutable audit chain, offline guest isolation, release governance, signing, serving gateway, or AWS deployment.
- Protected endpoints remain absent rather than accepting requests without authentication.
- Shadow fingerprint is only a deterministic preview, never a canonical signed release manifest.
- No production security decision may be made using these components.

Next: test the PostgreSQL migration and role/RLS separation on a real PostgreSQL instance; then implement authenticated, scoped asset operations.
