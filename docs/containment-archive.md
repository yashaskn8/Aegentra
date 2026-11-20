# Independent incident proof archive

`ContainmentProofArchive` is a separate security-account S3 writer/reader
for the bounded canonical STOP/authority-fence/gateway-ACK receipt bundle.
The writer creates exactly one `incidents/v1/<org>/<case>/<generation>`
object with `IfNoneMatch="*"` and requires a non-null immutable S3
VersionId. The reader takes the **exact version**, confirms the expected
security account, bucket, exact key and byte length, and recomputes SHA-256.
Neither an ETag nor an S3 "latest" key is an integrity proof.

`record_independent_containment` still requires the independently
authenticated security root, all signed ACKs and drained write deadline
before it can set CONTAINED. The archive adapter cannot grant status itself.

**Not deployed or qualified:** Security-account S3 IAM, versioning, Object
Lock compliance retention, immutable audit, independent signer enrollment,
network/VPC endpoint policy and live customer gateway evidence must be
verified separately. Tests use fake S3/STS and do not prove physical custody.
