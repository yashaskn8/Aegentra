# Independent audit checkpoint archive — SA-1.1 D12

A local PostgreSQL `audit_streams` hash chain is **not** resilient
against a privileged database administrator rewriting its history.
The separate `AuditCheckpoint` contract binds a canonical organization,
installation incarnation, stream, sequence, exact head SHA-256, predecessor
checkpoint digest and independent security-root generation.

A P-256 signature with the audit-checkpoint signing purpose can be
verified using an externally pinned public key. An independently
credentialed security-account S3 archive conditionally stores the
signed bytes under a sequence-specific key with `IfNoneMatch="*"`,
requires a non-null VersionId and verifies the original bytes and
hash on a version-specific readback. ETags are not integrity hashes.

**Not sufficient for production by itself:** a separate security-account
service must actually recompute every audit event hash from the
workload's independently acquired immutable audit data, reconcile every
stream sequence and any outbox gap, enforce monotonic predecessor links
and independent key custody, then sign and write checkpoints under
Object Lock retention. The present code supplies cryptographic and
exact-version storage **primitives**, not independent archive witnessing
or proof of administrator-tamper resilience in deployed AWS.
All CI fixtures use artificial test keys and fake S3.

`verify_archived_checkpoint` additionally rejects noncanonical, altered or
malformed signed envelopes and verifies their P-256 signature against a pinned
public key and expected checkpoint context. Consumers should validate the exact
S3 version with `read_exact` before calling it. Passing both checks is not
proof of complete independent source acquisition or deployed Object Lock.
