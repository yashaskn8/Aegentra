# Independent fixed two-object bundle proof — SA-1.1 D1/D4/D5

A separately credentialed verifier must independently read **both**
the generated HTML and the one digest-addressed classic script from
two explicitly pinned, versioned storage objects in the enrolled
bucket/prefix. The bounded verifier re-hashes the exact original
bytes, checks the HTML against the fixed template, checks the JS
length/digest and fails closed on missing, changed or redirected
object versions. It never imports or evaluates submitted JavaScript.

The two-object bundle manifest covers template version, exact paths,
HTML hash/length, script digest/length, SRI, CSP and host.
A separate canonical storage manifest binds the manifest to both
bucket/key/VersionId tuples. An independently enrolled P-256 signer
may attest the bundle in its own `aegentra.independent.fixed-bundle.v1`
domain. Verification requires the exact signed storage/content
identities, target, incarnation, verifier key ID and validity window.

**Important boundary:** the verifier adapter must itself be
independently authenticated and pinned to trusted original storage;
these functions use injected versioned readers. Test fixtures cannot
establish actual AWS account independence. The combined bundle
attestation is not yet a mandatory approval/publication predicate:
the current release subject, witness and primary head still describe
one resource. Until all of those contracts and the two-object
publication model bind this bundle digest, protected production
ENFORCED remains NO-GO. The existing gateway's per-resource checks
reduce exposure but do not independently prove atomic bundle
publication.

Remaining: an independent server with native IAM credentials,
durable signed bundle ledger, separate original-byte readback
channels, two-object version-linked publication, live browser and
CSP/SRI validation, origin bypass checks, operator sign-off and
SA-1.1 Matrix C negative controls.
