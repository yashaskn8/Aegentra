# Aegentra native AWS CDK draft

This folder defines three separate **prototype** CloudFormation stacks:
Workload (isolated PostgreSQL, versioned encrypted evidence bucket, scan SQS,
and an encrypted outbox FIFO queue with dead-letter queue/private SQS endpoint),
Analysis (isolated VPC skeleton with NO deployed guest or IAM profile), and
Security (encrypted, versioned object-lock archive).

The CI workflow only runs TypeScript checks, tests, and `cdk synth`. There
are **no AWS credentials, deployment actions, Docker images or containers**.

Production gates remain closed: this scaffold does not deploy the FastAPI
service, case-aware evidence verifier, bridge/guest workflow, witness, release
authority, emergency stop system, customer origin or observer. It does not
prove independent AWS administration, IAM organization boundaries, guest
network reachability, two-human approval or disaster recovery.

The analysis stack deploys NO instances. A future independent native bridge
must require a separately signed/qualified AMI and isolated disposable guest.
Neither an arbitrary AMI nor a successful CloudFormation synthesis establishes
safe execution of untrusted inputs.

The workload outbox resources are also inert until a separately installed
systemd worker is enrolled. Outbox IAM grants only SQS SendMessage on its
own FIFO queue; the worker security group has no general internet egress.
The private interface endpoint and managed SQS encryption have operating
costs and require an independent VPC/IAM/network review before deployment.
PostgreSQL dispatcher credentials and a consumer-side durable deduplication
ledger must be provisioned separately. No local test guarantees exactly-once
consumer processing.

Future production profiles need separate account bootstraps, guardrails, CDK
context, IAM trust reviews, code artifact signing, cost reviews, and actual
infrastructure tests. Keep the project in shadow mode.

Native commands:

```bash
cd infra
npm install
npm run build
npm test
npm run synth
```

No deployment commands are run by CI. Do not run `cdk deploy` until its
security and cost implications are reviewed. A reviewed lockfile must be
committed before a release pipeline is allowed.
