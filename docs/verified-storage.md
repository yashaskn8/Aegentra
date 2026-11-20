# Independent storage verification — proof contract

SA-1.1 requires an independently administered verifier to identify the exact
pinned S3 object versions and independently recompute all original-byte SHA-256
and lengths. The `verified_storage.py` contract accepts trusted readers and
conservatively aborts if any declared part is missing, extra, mismatched,
versionless or altered.

It constructs a separate RFC 8785 storage-manifest digest. The returned
status `VERIFIED_BYTES_UNSIGNED` explicitly **does not** claim a signed
storage manifest, approval, malware verdict, or publication right.

Remaining before qualified use:
- Separate native host, IAM role, KMS key and production pipeline.
- Signed source/builder provenance and human two-custodian process.
- Independent AWS S3 VersionId verification and network/permissions tests.
- Guest isolation and analysis, signed receipts, protected origin witness.
- No per-tenant final-evidence writes from the ordinary API.

The native S3 reader and the byte verifier both reject absent, literal
`null`, non-string and oversized version identifiers before any object read.
Literal `null` identifies a potentially mutable unversioned S3 object and
must never satisfy the immutable-version requirement. Byte lengths must be
positive integers, never booleans. These checks do not substitute for
independent AWS IAM and bucket-versioning qualification.
