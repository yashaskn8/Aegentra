# SA-1.1 incident cases — triage is not containment

The database migration 0014 supports the complete incident case-state
vocabulary: `OPEN → TRIAGED → CONTAINMENT_REQUESTED → CONTAINED →
RECOVERING → CLOSED`. The ordinary authenticated case API can only make
the first two transitions. They are CSRF-protected, membership-scoped,
revision-fenced, and write a matching audit/outbox event.

Both transitions return `enforcement_effect=NONE`. A triaged case or
containment request does **not** imply a freeze, STOP, independent
observation, physical origin revocation, or customer acknowledgment.
Operator-supplied `CONTAINED`, `RECOVERING`, or `CLOSED` values are
rejected. An independently authorized evidence-bearing process must
record the signed security-root STOP, primary authority fence, enrolled
gateway acknowledgments, and response-write drain before advancing
an incident to containment.

The downgrade refuses to discard an active incident state. Recovery
requires separate custody, original/restore-side isolation, predecessor
reconciliation and a fresh incarnation; it must not clear STOP by changing
a browser case status.

**Still required:** separate privileged containment and recovery transitions,
immutable incident archive, customer consent/revocation coordination,
incident response runbooks, alert delivery, and live cross-account drills.
