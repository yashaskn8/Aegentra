# Native guest physical-disposal verification — S2/S4

A trusted validator receipt is required before retiring a `DETACHED_VERIFIED`
physical attempt. The bridge retains its original instance and two EBS IDs
in the immutable resource ledger and records `DISPOSED` with an audit/outbox
event only after two **time-separated**, bounded AWS inventories agree.

Both inventories must match the pinned analysis account and instance ID,
and prove the exact two encrypted raw EBS volume IDs are **not found**.
The old instance must be terminated or absent. A missing, stale, wrong-account,
wrong-generation, ambiguous or mismatched inventory is a denial. Replaying a
confirmed disposal is idempotent and does not erase the original attempt.

**Important:** The `DeletedInventory` contract represents trusted external
AWS inventory; it is not an authenticated inventory service itself. A
separately credentialed read-only collector must distinguish explicit AWS
NotFound from AccessDenied/timeouts, retain both observations, and enforce
that they are separately collected. A janitor must actually terminate the
instance and delete both volumes under narrow IAM after ensuring validator
custody is complete. Without those external operations, this code cannot
certify true AWS disposal or prevent cost leaks. CI uses inert inventories.
