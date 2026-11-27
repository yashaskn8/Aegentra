# SA-1.1 D11 — conservative recovery preflight

The `recovery_preflight.py` module reports explicit gaps before two
independent custodians can begin a new-incarnation restoration review.
It NEVER issues a release grant, changes PostgreSQL states, invokes AWS,
clears security-account STOP, or authorizes origin serving.

Required preconditions are separately demonstrated old-region writer
fencing, customer origin route closure, externally active STOP,
network-isolated restore with disabled egress/AI, serving and notifications, quarantined credentials,
independent minimum incarnation/generation, full archive/audit/outbox/
attempt/publication/readback reconciliation, tombstones, consent revocations,
old-grant/session invalidation and fresh human review.

A complete inventory returns only `READY_FOR_INDEPENDENT_REVIEW`.
An explicit boolean `True` is required for every attested control. Inventory
identifiers must be non-nil UUIDs and the external generation must advance a
positive, signed-64-bit floor. The serving and notification fields default to
unverified so omission blocks review.
Its boolean fields are **not cryptographic evidence**: callers must ground
each from retained, independently signed records and custody controls.
Reviewers cannot convert this assessment into a root/veto-clear command.

A separate future recovery client must collect and validate the actual
cross-account witness/version/root and TLS-enrolled origin proofs, persist
recovery receipts, complete new credential and origin enrollment, perform
live old-region cutoff drills, and require signed authorization before
the separate security custodian removes a STOP. If any proof is unknown,
protected traffic remains in maintenance.

Tests are synthetic only; no AWS resource was restored.
