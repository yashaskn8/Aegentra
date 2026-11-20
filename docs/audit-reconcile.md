# Bounded audit-chain reconciliation

`reconcile_audit_window` verifies a contiguous, tenant- and stream-scoped
batch (at most 1,000 entries), including sequence, previous hash, body
digest, event digest and optionally the expected primary head. It accepts
a previously verified external checkpoint as the start of a new window,
not an arbitrary claimed offset. Missing, duplicated or forged entries
fail closed. It cannot verify that a privileged database operator did
not delete both local entries and the local head unless previous
checkpoints and a complete source are independently retained.

The separate security-account audit checkpoint contract binds
sequence/head, predecessor digest, incarnation and root generation;
the signed checkpoint is kept in an exact immutable S3 object version.

**Required before production:** a native independently credentialed
export/reconciliation worker, source completeness proof, durable
outside-database chain and checkpoint sequence, key custody,
Object Lock retention, tamper/cost/retention drills, and alerting.
Tests use synthetic local entries and do not certify external witnessing.
