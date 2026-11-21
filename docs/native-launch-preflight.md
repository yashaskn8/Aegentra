# Native disposable EC2 launch preflight — S2 shadow

This is a **read-only verification and request-planning entrypoint**, not a
production launch controller, image signature, isolation certification, or
customer scan runner. It performs **zero AWS mutations**. No Docker, images
built by a container, guest execution, or public API endpoint are involved.

## Independent prerequisites (not supplied by this repository)

An independently administered analysis account and constrained native bridge
identity, a separate read-only AWS inventory identity, qualified AMI build
and signer provenance, pinned root snapshot and KMS key, VPC/subnet/SG and
region enrollment, live network/link-local/IAM isolation drills, deadlines,
quotas, destruction and second-person approval are required *before any real
lifecycle can operate*. A shell environment variable is not security
enrollment or a signed authorization.

The database must already contain a fenced `LEASED` scan job and a
`RESERVED` physical attempt bound to the correct generation, nonce digest,
tenant, AMI, account, AZ, subnet, security group, and KMS key.
Physical volume and instance IDs must not yet be recorded.

## Native command and inputs

The one-shot read-only command is:

```bash
python -m aegentra.native_launch_preflight
```

Configure the restricted native bridge DB URL, org and attempt identity:

- `AEGENTRA_BRIDGE_DATABASE_URL`
- `AEGENTRA_BRIDGE_ORG_ID`
- `AEGENTRA_BRIDGE_JOB_ID`
- `AEGENTRA_BRIDGE_GENERATION`
- `AEGENTRA_BRIDGE_AWS_REGION`

Provide **independently verified and enrolled**, immutable configuration:

- `AEGENTRA_ENROLLED_ANALYSIS_ACCOUNT_ID`
- `AEGENTRA_ENROLLED_AMI_ID`
- `AEGENTRA_ENROLLED_IMAGE_OWNER_ID`
- `AEGENTRA_ENROLLED_ROOT_SNAPSHOT_ID`
- `AEGENTRA_ENROLLED_SNAPSHOT_OWNER_ID`
- `AEGENTRA_ENROLLED_EBS_KMS_KEY_ARN`
- `AEGENTRA_ENROLLED_GUEST_VPC_ID`
- `AEGENTRA_ENROLLED_GUEST_SUBNET_ID`
- `AEGENTRA_ENROLLED_GUEST_SG_ID`
- `AEGENTRA_ENROLLED_GUEST_AZ`

The bridge authenticates to AWS via its **already enrolled native IAM
identity**; do not put AWS access keys in source, arguments or output.
The command requires only STS identity and EC2/Route53Resolver read APIs.

## Verification boundaries

The preflight reads the currently authorized organization-scoped DB attempt;
the lease must retain at least 15 seconds. It checks:

1. The supplied enrolled account, AMI, KMS, subnet, security group and AZ
   match the DB-pinned physical reservation.
2. Read-only STS/EC2 image and snapshot inventory: exactly one private,
   available HVM x86_64 EBS-backed AMI with one encrypted, pinned,
   delete-on-termination root snapshot; exact owner, state, size and KMS key.
   Unknown pages, response fields or errors fail closed.
3. Read-only VPC/subnet/SG/route/DNS/endpoint inventory through the native
   isolation collector. This returns `LIVE_ISOLATION_DRILLS_REQUIRED`;
   it **does not certify link-local or guest-network isolation**.
4. A second DB transaction rechecks the active fenced lease and identical
   RESERVED pins. All AWS calls occur **outside** DB transactions.

It constructs but **never submits** a fixed single `t3.small` instance
request (no IAM instance profile, IMDS, public IP, IPv6, user data or
SSH key) and two independently encrypted 1 GiB `gp3` raw EBS requests.
Each planned request has a distinct deterministic idempotency token and
journal ownership tags. These requests cannot be interpreted as a release
authorization or executed by this module.

Only a summary is printed, with the status
`SHADOW_ONLY_EXTERNAL_QUALIFICATION_REQUIRED` and SHA-256 of the planned
request set. No instance, disk or customer input is created or executed.

## Remaining blocking work

A separately governed controller must securely acquire and persist exact
native AWS resource IDs **before attachment or use**, handle ambiguous AWS
timeouts by durable UNKNOWN/quarantine, attach only the intended raw volumes,
enforce an eight-minute attempt deadline and 90-second leases, terminate
the instance, and invoke the independent two-pass native detach validator.
Readback, advisory result verification, disposal and recovery remain distinct.
Actual AMI provenance and live cross-account network and IMDS testing must be
independently signed off before an ENFORCED cohort can exist.

The synthetic unit and PostgreSQL CI tests check contract failures and
query ordering; they do **not** prove live AWS correctness or production safety.
