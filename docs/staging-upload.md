# Staging upload implementation status

This implements the SA-1.1 §3 two-stage intake boundary, *not* a completed
evidence vault. A verified ADMIN/EDITOR can declare a bounded content manifest
for an existing tenant-owned asset. The declaration, one-time idempotency key,
audit entry and outbox event commit in one PostgreSQL transaction.

When AEGENTRA_STAGING_BUCKET and AEGENTRA_STAGING_REGION are configured,
the server may issue short-lived checksum-bound S3 PUT URLs scoped to keys
created by the server. The signer must have only staging-prefix write IAM.
The API does not inspect or execute the submitted bytes.

The finalize route records **claimed** exact S3 VersionIds for *all* declared
parts. It returns AWAITING_VERIFICATION. This neither produces an evidence
record nor makes the content eligible for release. A separate independently
administered verifier must fetch those exact versions, recompute hashes and
lengths, check provenance, and issue a sealed storage manifest. No mutable
latest-object fallback is permitted.

Runtime qualification gaps:
- IAM boundary tests, S3 CORS, max upload size enforcement, checksum handling,
  S3 versioning and presigned-header compatibility with real HTTPS browsers.
- An independent verifier and version-locked storage manifest signatures.
- Quota admission, ticket cleanup, retention, rate limiting and bounded
  per-principal concurrent uploads.
- The full job/outbox dispatcher and EC2 isolation required for hostile input.

Never enable this endpoint on a publicly reachable environment without the
staging account/IAM, transport, quota and custody controls being reviewed.

Finalization refuses the literal S3 `null` VersionId at both the HTTP
schema and internal ticket-transition boundaries. This prevents an
unversioned reference from irreversibly consuming a valid upload ticket;
only a non-null pinned version may enter the AWAITING_VERIFICATION state.
It remains an unverified client claim until a separate reader validates the
actual S3 object, version, length and digest.
