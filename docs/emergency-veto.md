# Independent emergency STOP — SA-1.1 §5 and D11/D13

A separate native process with pre-enrolled incident authority in the **security
AWS account** can record an emergency STOP even when PostgreSQL or the workload
control plane is unavailable. No "emergency allow", remote reset or CLEAR
action exists in this module.

Each STOP writes a unique, conditionally created immutable
`security-root/v1/<org>/stops/<generation>/<incident>` record and uses S3
`IfMatch` to atomically advance the live versioned current-root pointer.
ETag is only a compare-and-swap token, **not** an integrity digest. The
object's bytes use canonical RFC 8785 JSON and SHA-256, with a predecessor
link. A pinned minimum generation may be supplied from an **external**
monotonic-floor source; the floor source itself is not yet implemented.
A conditional failure is `StopUnknown`: the immutable intent may be
present but active STOP and containment have **not** been confirmed.

Fresh per-request P-256/KMS signed veto snapshots include the root
incarnation and veto generation. Gateways must contact the security service
on every protected admission and deny on STOP or any failure to obtain it.
There is no caching of live state.

**This is a testable protocol component, not a qualified incident service.**
Before production: separate AWS account/administration and IAM, Object Lock
retention, one-way signer access, trusted enrolled root bootstrap, independent
monotonic floor, real S3 concurrency/retry/failover exercises, separate
incident principal, audit/log visibility, root incarnation recovery, and
every enrolled gateway's acknowledgment plus maximum already-admitted
response drain. The current return type states
`VETO_RECORDED_PENDING_ACK`, never "contained".

AWS S3 supports conditional `PutObject` with `IfMatch`; configure
versioning and Object Lock retention independently and verify live account
policy before using this implementation. See AWS S3 PutObject and Object Lock
documentation.
