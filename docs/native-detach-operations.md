# Native EC2 detach-verification bridge — shadow S2 procedure

This describes a **code-level, non-production custody step**, not certified
guest isolation or live deployment. The bridge is a separate native Python
process. No Docker, Kubernetes, container guest, or HTTP endpoint is used.

## Required external prerequisites

Before using this command in any AWS environment, independent security
custodians must enroll and qualify the guest AMI, image provenance, account
and IAM roles, instance launch and termination, EBS attachment and encryption,
network/no-route/no-IMDS/no-IAM properties, quotas, deadlines and janitor.
None of that qualification is performed by this repository or its CI.

The analysis bridge's PostgreSQL role must access only its RLS-scoped
`guest_attempts`, `guest_resources` and audit chain. The AWS credentials
must have read-only STS/EC2 inventory permission in the exact separately
enrolled analysis account. Do not share API, guest or release credentials.

A separately supervised lifecycle component must already have persisted
the lease and exact instance + two encrypted EBS IDs and pinned AMI as
`INSTANCE_RECORDED`. This command does **not** launch or terminate EC2,
attach or detach disks, read arbitrary guest content or delete volumes.

## One-shot entrypoint

The native command is `python -m aegentra.native_detach_worker` from the
installed backend package. Its required environment keys are:

- `AEGENTRA_BRIDGE_DATABASE_URL` — native restricted bridge database role
- `AEGENTRA_BRIDGE_ORG_ID` — enrolled tenant UUID
- `AEGENTRA_BRIDGE_JOB_ID` — durable scan job UUID
- `AEGENTRA_BRIDGE_GENERATION` — current fenced attempt generation
- `AEGENTRA_BRIDGE_ACTOR_ID` — enrolled audit actor UUID
- `AEGENTRA_BRIDGE_AWS_REGION` — pinned region for the exact attempted EC2 guest

Supply AWS credentials only through the independently administered native
host identity, never in committed code or shell history.

The worker reads the journal, releases the DB transaction, obtains one exact
`DescribeInstances` + `DescribeVolumes` + STS account snapshot, waits
31 seconds without a DB lock, and obtains a second independent snapshot.
Both must identify exactly the terminated EC2 instance and the two detached,
available, encrypted, tagged and KMS-pinned volumes. The instance's `ImageId`
must match the journaled AMI. Malformed/partial pagination, alternate
accounts, IAM profiles, public addresses or enabled IMDS cause refusal.

The final database transaction rechecks the current physical pins and
requires the snapshots to be at least 30 seconds apart, no more than
5 minutes apart, and the second no more than 60 seconds old. The DB trigger
prevents physical identity changes, illegal state jumps and timestamp rollback.
Only then may the attempt move to `DETACHED_VERIFIED`.

On any error, **no detachment acknowledgment is committed**. Quarantine,
investigate and reconcile independently; never treat API unavailability as
proof of termination. The raw output, advisory scan receipt, janitor deletion,
retained disposal receipt and external security qualification are separate
steps and remain subject to the original safety gates.

The native CI tests use fake AWS APIs and PostgreSQL fixtures; they do not
prove real account separation, AMI build provenance, guest isolation, EBS
cleanup or any production release predicate.
