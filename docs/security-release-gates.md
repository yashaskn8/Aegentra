# SA-1.1 release qualification gates

**Current verdict: NO-GO for protected production deployments.**

This checklist is deliberately a gap ledger, not an assertion of completed controls.

## Confirmed in CI
- Native Python tests and PostgreSQL RLS integration exercise organization-scoped asset operations.
- OIDC signature, issuer, audience and nonce negative tests use a test RSA key.
- Idempotent asset registration and transactional local audit/outbox are database-tested.
- Inert JavaScript fixtures exercise static parser syntax, bounded AST traversal and explicit gaps.
- Exact-blob verifier checks original bytes against a pinned object version and expected digest with fake storage.

## Unverified / release-blocking
- Native AWS EC2 offline guest isolation, no metadata or egress, runtime resource limits, disposal and independent negative tests.
- Independently administered byte verifier and two-human authorization service.
- Release grant, one-time redemption, separate security-account witness, guarded publish and origin serve.
- Controlled customer origin closure, gateway readback, cache behavior, emergency veto, crash and race drills.
- Production IAM, TLS, KMS, RDS backup/restore, S3 Object Lock, CloudTrail and real S3 VersionId verification.
- Strict dependency lockfiles and signed native build artifacts with independent custody.
- Ingest authorization, quotas, data classification, retention and consent/revocation.
- Full scan job state machine, SQS leases/fencing, bounded raw guest frame and trusted result validation.
- Outbox dispatcher, independently archived audit, incident handling and recovery.
- Browser integration at real HTTPS origin and public-exposure review; unqualified staging is not production.
- Independent assessor review with SA-1.1 F01–F15 test oracles and written sign-off.

Security principle: a passing parser, local unit test or successful HTTP endpoint never authorizes production publication. Do not enable untrusted customer analysis until native guest isolation is qualified.

## Scoped database write boundary (CI)

The ordinary API role has SELECT-only access to final evidence and SELECT/INSERT-only access to audit entries. A native PostgreSQL negative test confirms that the API role cannot insert even a same-organization evidence record. This is **role-level restriction**, not independent verifier or immutable archive qualification; the production role grants and migrations must be tested in a separate environment.
