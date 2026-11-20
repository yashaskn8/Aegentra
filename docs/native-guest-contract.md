# Native EC2 analysis guest — implementation boundary

SA-1.1 §4 requires one disposable native EC2 guest per attempt in a **separate
analysis AWS account**, with no IAM profile, IMDS, DNS, internet, NAT, VPC
endpoints, usable link-local routes, IPv6, public IP, secrets or shared runtime.
The management bridge must be in a different network and independent trust
domain. A passing CloudFormation template is not proof of live isolation.

Implemented in this increment:

- Domain-separated, canonical raw input and result frames.
- Exact SHA-256 binding to original bytes and a job generation + nonce.
- Bounded 1 MiB JS input, 1 MiB result and 2,000 advisory findings.
- A single-operation native raw device reader/writer that never mounts a
  guest-produced filesystem or executes submitted JavaScript.
- Trusted structural validator for identity, toolchain digest, length, byte
  bounds, duplicates and coverage gaps. It cannot attest honest detection.
- Independent bridge-side EC2 custody assertions over recorded resource IDs,
  detached encrypted EBS volumes and terminated instances.
- No persistent prototype EC2 guest in the CDK template; the VPC and blocked
  security group remain an inert infrastructure definition.

**Not completed or production-qualified:**

1. Independently administered bridge and verified native AMI/systemd image.
2. Trusted management AWS identities and persistent per-attempt physical
   resource records; dynamic EC2/EBS lifecycle, attach/detach/cleanup, SQS
   dispatcher and two-pass janitor.
3. Real negative routing, link-local, IMDS, IAM and block-device mapping tests.
4. Reviewer credentials, signed immutable evidence, witness, protected
   gateway, emergency stop and recovery sign-off.

Do not enable processing of adversarial customer files on a shared host or
the API process. All CI tests here use inert local fixtures. Guest output
returns **advisory only** and must never authorize publication.

## Additional native bridge custody implementation

Migration 0007 adds an organization-scoped guest attempt ledger plus a globally
unique physical resource-ID ledger, preventing accidental reuse of an EBS or
instance ID in another attempt. A distinct, non-owner PostgreSQL bridge role
can record attempts, physical resources and audit/outbox events. The ordinary
application role receives **no access** to either ledger.

The bridge records a generation/nonce checked against the live scan lease,
then records both EBS IDs and EC2 ID in distinct committed stages. It will not
accept a detached record until both inventory snapshots match the original
job/account/AZ/instance/volume identity and show a terminated guest and fully
detached encrypted volumes. The state machine supports quarantine.

The actual EC2 launch, two-pass independently timed observations, IAM
constraints, janitor deletion and live reachability tests remain separate
release-blocking integration tasks. The CI inventory is synthetic.
