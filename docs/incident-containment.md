# SA-1.1 independently verified CONTAINED incident transition

The normal FastAPI/browser role can create, TRIAGE and
CONTAINMENT_REQUEST an authorized incident case. It cannot set
`CONTAINED`, `RECOVERING` or `CLOSED`: PostgreSQL migration 0016
checks privileged case-status writes under the separate named
`aegentra_incident` native database role. A direct same-organization
API SQL write is denied, including if it bypasses the FastAPI route.

A separate incident-custodian transaction now validates the
independent security-account STOP, a signed authority fence, every
enrolled gateway's signed ACK, and the maximum response-write drain
using `assess_stop_containment`. It requires the target to already
have local STOP_SERVING, matches case asset and installation
incarnation, and checks a bounded canonical proof bundle against a
pinned immutable archive key, exact non-null S3 VersionId and SHA-256.
Only then can `CONTAINMENT_REQUESTED` become `CONTAINED` with a
revision increment, immutable proof-reference row and audit/outbox
entry in one serializable transaction. Retries are idempotent when
the proof/version are identical and reject forks otherwise.

**Hard limitation:** The caller must use an independently administered
security-account S3 read and trusted gateway enrollment registry.
A caller-constructed `ContainmentArchiveRef` is not independent proof
that Object Lock retention or a live customer TLS cutoff actually
occurred. CI uses synthetic P-256 signatures, fake archive bytes and a
native PostgreSQL role, not real AWS governance.

`RECOVERING` and `CLOSED` intentionally remain unavailable through
the normal case API. An independently signed dual-custody recovery
workflow, evidence reconciliation, consent revocation, fresh
incarnation and new reviewed publication remain release-blocking.
The browser cannot clear STOP.
