# Aegentra native AWS CDK draft

This folder defines three separate **prototype** CloudFormation stacks:
Workload (isolated PostgreSQL, versioned encrypted evidence bucket and SQS),
Analysis (offline EC2 prototype with no IAM profile/IMDS/public route), and
Security (encrypted, versioned object-lock archive).

The CI workflow only runs TypeScript checks, tests, and `cdk synth`. There
are **no AWS credentials, deployment actions, Docker images or containers**.

Production gates remain closed: this scaffold does not deploy the FastAPI
service, case-aware evidence verifier, bridge/guest workflow, witness, release
authority, emergency stop system, customer origin or observer. It does not
prove independent AWS administration, IAM organization boundaries, guest
network reachability, two-human approval or disaster recovery.

The analysis stack requires an explicitly supplied prebuilt qualified AMI
ID before any proposed deployment. Neither an arbitrary AMI nor a successful
CloudFormation synthesis establishes safe execution of untrusted inputs.

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
