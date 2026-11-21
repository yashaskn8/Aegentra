# Native S2 deadline supervisor — shadow / not deployed

The Python library `aegentra.native_deadline_supervisor` provides a
**default-disabled** bounded watchdog loop for an already journaled offline
guest. It is not a daemon, public API, systemd unit or production scheduler.
It never executes customer code, does not prove isolation, and does not
automatically run on any AWS account.

## Inputs and security boundary

`supervise_native_attempt` accepts a pre-enrolled native management identity:
restricted bridge database sessions, the exact organization/job/generation,
the original scan-lease nonce, an audited actor, and separately provisioned
read-only STS/EC2 plus restricted EC2 lifecycle clients.

`explicitly_enabled` defaults to `False`. Enabling this local library flag
does not constitute authorization to run it against AWS. Independent
signed AMI trust, accounts/roles, network and device isolation, operation
provenance, external operator custody, incident stop and recovery must be
established before live execution. There is no CLI or automatic deployment.

## Fenced heartbeat protocol

On each tick, `heartbeat_physical_attempt`:

1. Locks the organization-scoped scan job and physical attempt in one
   PostgreSQL transaction; reads the immutable EC2/EBS creation and physical
   operation journals.
2. Requires the original attempt nonce, exact generation and an eligible
   physical state. The watchdog cannot renew a stale, completed, quarantined
   or revoked generation, or extend an attempt past its original 8-minute
   deadline. Missing timestamps and implausible clocks are rejected.
3. Produces one of three durable decisions:
   `RENEWED`, `STOP_REQUIRED`, or `RECONCILE`. A valid renewal is capped
   at 90 seconds and never exceeds the job's attempt deadline.
4. Commits and releases every DB transaction before waiting 30 seconds;
   no AWS network request is made while holding a database lock.

When stopping is required, the library uses the existing default-disabled,
journal-first `request_native_termination` path with exact pinned IDs.
The termination operation must commit PREPARED before its one AWS call.
An accepted response records only `REQUESTED`, **never** TERMINATED or
DETACHED_VERIFIED. Two subsequent independent read-only, time-separated
EC2/EBS inventories are still needed before raw output may be read.

If a stop was already requested or an AWS callback is still PREPARED,
the watchdog returns `RECONCILE`; no blind replay or second termination
request is permitted. Database failure, cancellation, unexpected state,
clock rollback or exceeding the 20-tick safety budget produces a failure
requiring independent reconciliation. No false stopped receipt is issued.

## Operational qualification still outstanding

The function only runs while an externally governed native process invokes
it. An independent host supervisor is still needed for restart/crash
detection, hardware/monotonic clock trust, guaranteed coverage when the DB
or management network is down, physical cleanup after missing or ambiguous
AWS outcomes, actual guest shutdown and KMS/AMI/network drills, host quotas,
raw input/output and device mapping. This code does not guarantee a
deadline when its host is stopped or compromised.

The tests cover synthetic clock, failed heartbeat, nonce mismatch,
bounded tick counts, termination fencing and native PostgreSQL authorization.
They are **not** evidence that any real AWS resource was stopped.

**Protected production: NO-GO.**
