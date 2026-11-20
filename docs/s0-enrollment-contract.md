# SA-1.1 S0 — independent enrollment contract freeze

The new `ProtectedOriginContract` freezes the deliberately narrow
protected-origin scope: one exact HTML entry path, one same-origin
classic-JS path, maximum 1 MiB JavaScript, pinned response profile,
immutable origin bucket/prefix, distinct workload/analysis/security
12-digit AWS account IDs, AWS region, data-residency and incident
policies, frozen fixture oracle, fail-closed outage behavior, and a
2-second maximum proposed admission deadline.

Exactly two **separately enrolled** P-256 owner keys must sign the
canonical contract digest with independent customer-origin owner and
security-custodian purposes. Duplicate people/groups/keys, expired
custody, wrong public key, changed profile, wrong account or another
signing purpose are rejected. No browser supplies enrollment keys.

Verification produces **SHADOW_ONLY_INDEPENDENT_QUALIFICATION_REQUIRED**.
It is not permission to set `ENFORCED`, deploy an AWS stack, rotate
the security-account root, or grant a release. Real owner signatures,
origin closure, IAM identities, customer policy, immutable contract
retention, and independently signed F01–F15 qualification are still
required before any protected-production claim.

The fixture-oracle digest must be grounded in the separately supplied
**Matrix C** referenced by the SA-1.1 architecture. The 15-page PDF
does not include its full fixture/oracle content; do not invent that
artifact or treat placeholder hashes as independent approval.
