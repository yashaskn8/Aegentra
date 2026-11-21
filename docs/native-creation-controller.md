# Native S2 EC2 resource creation — journal-first shadow controller

This is a **nonproduction native Python library**, not a deployed worker.
It adds the write-side **creation sequence only** to the previously
implemented read-only AMI, network, lease and launch-plan preflight.
No AWS resources are created in CI or by this repository change.

## Interfaces and operating boundary

`aegentra.native_creation_controller.create_guest_resources` accepts a
previously generated and unchanged `LaunchPlan`, the persisted
`LaunchReservation` identity, an enrolled bridge actor, a restricted
PostgreSQL session factory and an independently supplied EC2 client.
It **refuses to run by default**: `explicitly_enabled` is false and
there is no exposed CLI, FastAPI route, deployment worker or scheduler.
A local Boolean is **not** a substitute for independent IAM, signed AMI
provenance, actual network isolation drills or external human approval.
Do not enable live AWS mutation until those controls are separately
implemented, provisioned, verified and authorized.

The pure launch plan still requires signed independent qualification.
The adapter regenerates the fixed request plan and rejects any mutation
of its fixed EC2/volume parameters. It uses the plan's deterministic,
distinct per-operation ClientToken values; AWS client automatic retries
must be disabled by the future native operating owner. The adapter does
not include an automatic retry or blind recovery after an ambiguous call.

## Transaction and physical resource order

Migration `0021_guest_create_intents` creates the RLS-protected
`guest_create_intents` ledger. A bridge-only database role can manage
its immutable, one-way physical intents; the ordinary browser API role
cannot read them.

For each planned `INPUT_EBS`, `OUTPUT_EBS`, and `INSTANCE`
operation, the library:

1. Locks the fenced job and guest attempt in PostgreSQL; requires a
   live lease and valid generation; checks the previous resource ID and
   prior committed plan digest.
2. Atomically inserts `PREPARED` (request digest, token hash, kind,
   exact attempt generation, audit), then commits **before** AWS IO.
3. Makes one native AWS create call **outside** all DB transactions.
   It checks the response's exact physical ID, AMI or EBS properties.
4. On a definite, complete response, commits the globally unique
   physical ID into `guest_resources`, marks the intent `RECORDED`,
   and advances the attempt only after the required previous resource
   IDs were durably recorded.
5. On an exception, timeout, truncated or mismatched AWS response,
   commits `UNKNOWN` and `QUARANTINED` with an audit event. It does
   not continue, replay the client token, or request another resource.
   If quarantine cannot be committed or AWS succeeds but the DB
   acknowledgment fails, the caller receives `CreationUnknown` and
   must independently reconcile the exact AWS request and journal.

If a result returns after a lease change, its physical ID is still
recorded for safe cleanup, but the attempt becomes `QUARANTINED`.
A terminal UNKNOWN cannot be reclassified by an ordinary bridge update.
Database trigger constraints prevent request-digest rewrites and
recorded-state rollback, while resource IDs cannot be reused globally.

## Explicitly not implemented in this stage

This library **does not attach** EBS volumes, install source code, execute
the guest, terminate instances, attest guest/network isolation, read raw
output, delete volumes or approve releases. The next governed stage must
verify independently collected post-create AWS inventories and permanent
physical journal identity **before attachment**, supervise timeouts,
execute an independent termination/reconciliation sequence and prove
the two-pass disposal evidence. Production remains NO-GO.

The added native PostgreSQL and mock-EC2 tests exercise ordering,
tenant/role isolation, failed writes, delayed AWS responses, and
ambiguous outcomes. They are synthetic tests, not cloud operation
or security certification.
