# SA-1.1 publication receipt and fresh primary-head service

A witnessed selection does not become a published release until a serialized
publication transaction writes a distinct monotonically incrementing public
revision, audit/outbox and a **PENDING_SEAL** publication record.

The authority creates a separate typed, signed publication receipt containing
the published revision, selection attempt, independent witness digest and
exact versioned origin bytes/profile. The receipt writer conditionally appends
to a versioned S3 key; later the release controller checks its exact returned
VersionId, raw bytes, signature, digest and current committed publication
before marking that single revision SEALED.

Only a SEALED **current** revision can produce a new nonce-bound P-256 signed
head. The native AWS KMS wrapper signs a bounded RAW message with the fixed
ECDSA_SHA_256 key ID and verifies it against a separately pinned public key.
No other principal's key is accepted. HOLD_PROMOTION can retain the last
sealed release, while STOP_SERVING denies new fresh heads.

These commands are private to the release authority. The ordinary API has no
permission to write their tables or sign heads.

**Limitations and unfinished P0 qualification:** The test uses ephemeral
signers, a fake KMS and fake S3. The production signing key, TLS/mTLS gateway
ingress, separate security-account root/veto, exact S3 IAM, independent
custodians, release recovery and physical origin-bypass tests remain required.
The CI fixture simulates ENFORCED by a database-owner change; it is not a
valid production enrollment or activation procedure.
