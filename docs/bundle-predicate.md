# Fixed bundle digest through protected release stages — D1/D2/D4/D5

The fixed HTML+one-JS manifest digest (`fixed_bundle_sha256`) is a
**required typed field** in the review subject, independent staging proof,
signed origin binding, security witness and its selected-snapshot
verification, publication receipt and fresh signed primary head.

A new nullable PostgreSQL column holds the bundle digest for each
publication. New publication transactions write the exact reviewed
digest. **Existing or restored historical rows with no independently
established bundle digest fail closed:** primary head generation refuses
a missing digest; no migration invents new evidence.

The protected gateway requires the current nonce-bound signed head's
bundle digest to equal its independently enrolled
`FixedStaticProfile.manifest_sha256()`. It also requires the
separately signed witness certificate to carry that same digest.
It then independently verifies the exact immutable origin bytes,
generated HTML or script, response headers and fresh veto.

A helper `verify_review_subject_bundle` checks a separately signed
two-object attestation against the review subject, exact stage bytes,
storage versions, fixed template hash, original HTML and response
profile. It fails on mismatched reviewed bytes, script manifest,
source attestation, storage identity or target.

**This narrows a critical ambiguity; it does not complete atomic
two-resource publication.** The current database still has one
`resource_path` and one origin object VersionId per target
revision, not a complete two-object serving-slot map. Further work
must persist both origin VersionIds, independently check both
resources in the same guarded publication transaction and ensure
the entry and JS head resolve to the same sealed bundle revision.
The shadow grant path does not yet require the signed bundle helper
as a hard predicate; production ENFORCED is therefore still NO-GO.

Additional P0 requirements remain: externally enrolled verifier
hosts, human hardware-backed reviewer custody, independently
controlled customer origin, live browser CSP/SRI checks,
protected CDN bypass closure, trusted head/veto network callers,
physical AWS fault schedules and signed Matrix C qualifications.
No deployment or AWS resource mutation is performed by this change.
