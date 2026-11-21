# Native EBS attachment and EC2 termination — S2 shadow

These are **default-disabled native Python libraries**, not deployed
background services. They do not activate guest execution, prove isolation,
mount guest-produced filesystems, or approve customer releases. CI uses
synthetic AWS responses and native PostgreSQL test roles only. No Docker.

## Contracts

- `aegentra.native_attachment_inventory.collect_live_inventory` reads
  precisely the journaled instance and two raw EBS volumes, verifying the
  AWS account, AMI, subnet, AZ, disabled IMDS, missing IAM instance profile,
  no public addresses, single network interface, resource ownership tags,
  KMS and encryption, volume role, size and non-multi-attach state.
- `verify_attachment_count` requires an exact, running guest with input
  volume at `/dev/sdf` and output at `/dev/sdg`, attached strictly in
  order to the one pinned instance. This checks AWS control-plane device
  names, **not** the guest-visible block-device mapping or isolation.
- `verify_termination_inventory` allows the same exact guest's two
  tracked volumes to be attached, partly attached or detached while refusing
  an attachment to any other instance.
- Migration `0022_guest_physical_operations` adds FORCE RLS, bridge-only
  physical operation intents and a PostgreSQL trigger with immutable
  account/job/generation/resource identity and one-way transitions.
  Attachment outcomes are PREPARED → VERIFIED/UNKNOWN; termination is
  PREPARED → REQUESTED/UNKNOWN. Terminal outcomes cannot be overwritten.
- `aegentra.guest_physical_operations` requires all three creation intents
  RECORDED with exact globally unique IDs. It prevents duplicate or
  out-of-order AWS actions, verifies a live lease for attachments, and
  permits later cleanup requests for quarantined or retired attempts.

## Default-disabled native adapters

`aegentra.native_physical_controller.attach_raw_volumes` and
`request_native_termination` both require `explicitly_enabled=True`
and an already-qualified independent native operator, a tightly scoped
restricted PostgreSQL role and read-only STS/EC2 inventory credentials.
Neither function is connected to FastAPI, the browser, a scheduler or
an automatically running systemd service.

The attachment adapter, for each raw volume:

1. Reads current pinned database custody and lease, then obtains a fresh
   AWS inventory outside PostgreSQL.
2. Checks the previous attachment count, commits a PREPARED operation,
   and performs **one** exact `AttachVolume` request outside a transaction.
3. Checks the AWS response and independently queries exact inventory
   again, requiring the expected instance, raw volume and device state.
4. Commits VERIFIED only if the lease and original custody remain valid.
   On timeout, malformed/ambiguous response, cancellation, stale lease or
   readback failure it does not continue and attempts UNKNOWN/quarantine.
   If the database acknowledgment fails after AWS success, manual
   reconciliation is mandatory and no automatic retry is allowed.

The termination adapter checks whether the lease has expired, the attempt
has been retired/quarantined, or an explicit operator-stop was requested.
It rechecks the exact instance and raw attachments before committing
PREPARED, makes a single `TerminateInstances` request, and records only
REQUESTED after the exact AWS response. **REQUESTED is not TERMINATED.**
The separate native detach worker must later observe two fresh,
time-separated terminated/detached inventories before DETACHED_VERIFIED.

## Native 30-second watchdog library

The [default-disabled deadline supervisor](native-deadline-supervisor.md)
now performs bounded 30-second PostgreSQL lease renewals, detects the
8-minute attempt deadline or result handoff, and delegates exactly one
journal-first termination request. It is **not deployed** as a service,
does not grant raw output readback and does not guarantee a stop if its
host fails.

## Critical qualification gates

The independent custodian must still certify a signed AMI/toolchain,
separate AWS accounts and IAM principals, real physical network/link-local
and no-IMDS reachability, input framing, guest source independence,
correct guest-visible block devices, external enforcement of the
8-minute attempt timeout and 30-second lease renewal under host failure,
host resource quotas, cancellation/crash recovery,
authoritative termination, raw output readback, deletion and two-pass
disposal. The adapter does **not** implement a 24/7 deadline scheduler,
device initialization, a terminated-state waiter, or janitor recovery.
If a previous AWS call remains PREPARED/UNKNOWN, reconcile it using
independent AWS evidence; never blindly replay it. Client-side retries
must also be disabled in an eventual authorized AWS integration.

No live AWS actions or production deployments were performed. Security
release status stays NO-GO.
