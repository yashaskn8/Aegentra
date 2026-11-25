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

## Evidence stream ownership and cleanup

The version-pinned adapter closes any returned response body even if the
version or length metadata is rejected before reading. A boolean length is
invalid. The byte verifier explicitly closes closeable iterators on exit,
including early size or type rejection, rather than relying on garbage
collection. Ordinary non-closeable iterable readers remain compatible.
A cleanup failure propagates instead of yielding a verified result.
The tests use actual botocore StreamingBody objects over local in-memory
streams; they establish neither deployed S3 behavior nor AWS identity
independence. See the [botocore response reference](https://docs.aws.amazon.com/botocore/latest/reference/response.html)
and [Python resource cleanup guidance](https://docs.python.org/3.12/library/contextlib.html).
