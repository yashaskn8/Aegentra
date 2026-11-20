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

Before an independent signer issues a checkpoint, pass the head returned by
`reconcile_audit_window` to `require_reconciled_checkpoint_head` alongside
the proposed `AuditCheckpoint`. The check rejects mismatched tenant, stream,
sequence, digest, and malformed head lengths. This binding does not establish
source completeness, independence, or authorization to sign.

Callers with an independently established terminal sequence should pass
`expected_sequence` to `reconcile_audit_window`. The verifier then rejects
a valid-but-truncated tail, malformed bounds, and any terminal sequence
mismatch. The caller must derive that bound independently: copying the last
sequence in the received batch would defeat the truncation check. Neither
this option nor the primary database head proves independently complete
capture, and protected serving remains disabled.

### Canonical audit-payload retention (new records only)

New audit events retain their **exact canonical payload bytes** (bounded to
64 KiB) alongside the event hash, including actor, event type, UTC timestamp,
and body. Reconciliation rehashes the bytes and rejects any change to those
fields, malformed/noncanonical payloads, missing bytes or excessive payloads.
The database migration deliberately leaves `payload_bytes` nullable for
legacy rows: the lost pre-migration payload cannot be reconstructed from the
hash. Those rows now **fail** payload-complete reconciliation and must not be
treated as independently qualified. No retrospective backfill or silent trust
upgrade is permitted. External source retention, complete export,
authorization to create audit checkpoints, and deployed immutability remain
separate mandatory P0 gates.

The writer also rejects NaN and positive/negative infinity before an audit
record can be committed: those are not JSON numbers and would otherwise
create records that fail strict independent reconciliation.
