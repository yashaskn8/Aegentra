# SA-1.1 protected static-origin reference gateway

This is an **opt-in standalone ASGI gateway contract** for one enrolled
exact HTML or classic JavaScript resource, not the React console. It has no
fallback routes, directory listing, mutable latest-object reads, conditional
or partial responses, alternative content encodings or success streaming
before validation.

Each admission performs the following in a bounded two-second decision
envelope:

1. Require exact HTTPS host/path and plain GET; reject Range and
   If-Modified/ETag variants without contacting downstream dependencies.
2. Fetch a request-specific, P-256 signed published head from the primary
   release authority. Require ENFORCED, ACTIVE or HOLD_PROMOTION, a nonzero
   public revision and an enrolled resource identity.
3. Read the specified immutable witness S3 VersionId and recompute its exact
   object hash. Verify the independent P-256 signature and bind its
   incarnation, target, selection attempt, content hash, profile hash and
   predecessor/published revision.
4. Fetch only the signed exact origin S3 VersionId from the pre-enrolled
   bucket/key prefix, buffer all bytes (≤1 MiB), recompute SHA-256 and
   compare the fixed no-store/CSP/identity-header profile hash.
5. Fetch a SECOND nonce-specific signed published head. Deny if it has
   changed during prebuffering.
6. Fetch the independent security-account root/veto snapshot LAST with a
   fresh nonce. Require CLEAR and a current incarnation/root generation.
   Only then return the fully validated representation for immediate
   ASGI delivery; otherwise send maintenance without candidate bytes.

The reference implementation deliberately has **no publicly configured
deployment entrypoint**. The origin operator must supply independent
authenticated primary-head, root/veto, witness-read and origin-read clients
with short timeouts, pinned TLS and exact-storage credentials.

Unqualified P0 gates: physical origin route closure and writer control,
independently administered keys and roots, production KMS witness signing,
real live veto and STOP-ACK handling, observer readback/cohort semantics,
accurate network/TLS/CloudFront header behavior, 2 s p95/p99 drills,
active response cutoff and error behavior, restore and bypass tests.

The reference does not prove that a response already sent can be revoked,
nor that an external CDN will preserve exact signed headers.
