# Witness registration and guarded publication prototype

The authority can now register a witness only when its certificate, signature,
predecessor link, exact S3 VersionId, digest, two-reviewer subject and
committed one-time selection agree with fresh signed root/veto evidence. The
selection remains private until a separate guarded publication transaction.

A publication requires an ENFORCED and ACTIVE target, current organization
and target epochs, unexpired independent review/staging evidence, the witnessed
selection and a separately signed exact-origin object/version binding.
It advances a unique public revision and leaves an explicit **PENDING_SEAL**
receipt; a fresh public head is not available until a separate receipt-seal
step and independent readback. No network call occurs under serialized locks.

The normal API role has no privileges to write witness or publication tables.
The CI test temporarily changes a fixture target to ENFORCED using the
test-database owner, which **does not model a qualified production
activation**. A real controlled-origin enrollment cannot be permitted without
two-custodian governance and live origin-bypass/route/credential tests.

Remaining: receipt sealing, signed head service, independent live veto adapter,
observer response readback, recovery and physical AWS custody qualification.
