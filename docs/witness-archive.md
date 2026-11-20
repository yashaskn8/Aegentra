# SA-1.1 independently signed witness — verification and archive contract

The security witness is a **different signing purpose** from reviewer
endorsement, staging verifier, authority grant, published head and emergency
veto. An externally pinned P-256 public key authenticates its immutable
certificate. It binds incarnation, org, target, never-reused attempt sequence,
prior published revision, predecessor witness hash, independently reviewed
subject/approval-set/staging digests, final content and delivery-profile
digests, security-account root generation and selection deadline.

A separately credentialed security-account writer may persist a conditional
S3 object with `IfNoneMatch=*` and a required non-null S3 VersionId. The
exact-version reader recomputes SHA-256; it never silently reads the current
latest key or trusts ETag as an object digest.

**Crucial limitation:** this is a cryptographic *contract*, not an operational
witness service. The normal API and release controller never obtain the KMS
signing key. No real separate account identity, signed source attestation,
two-reviewer credential custody, root/veto state, bucket compliance-retention
duration, S3 event rollback drill, publication operation or protected gateway
has been qualified. A real signer must independently fetch the committed
selection and verify its evidence before signing. The test suite uses
in-memory synthetic keys and fake S3; such tests do not establish AWS
custody or production readiness.
