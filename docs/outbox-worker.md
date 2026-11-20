# Native SQS FIFO worker — implementation and controls

`python -m aegentra.outbox_worker` is a one-shot native process that claims
bounded events under the independently credentialed PostgreSQL dispatcher role,
commits the leases, and only **then** sends canonical metadata to the pinned
SQS FIFO queue. Successful SQS `MessageId` is acknowledged in a *new*
transaction. A missing response schedules a bounded retry; a crash can cause
a redelivery when the lease expires.

FIFO message group is `<org_hex>:<stream>`; deduplication ID is the
immutable outbox event UUID, never the per-attempt lease nonce. Source bytes,
prompts, user content, credentials and signed URLs are never sent.

AWS FIFO deduplication is bounded (five minutes). This does **not** provide
unbounded exactly-once semantics: the downstream consumer must persist
event UUID idempotency independently. A queue ACK is only a handoff,
not a confirmed customer action, case delivery or incident containment.

**Native configuration**: `AEGENTRA_OUTBOX_DATABASE_URL` points to the
narrow DB role; `AEGENTRA_OUTBOX_ORG_ID` is fixed for this installation;
`AEGENTRA_OUTBOX_FIFO_QUEUE_URL` and `AEGENTRA_OUTBOX_AWS_REGION`
are operator-controlled. AWS credentials must come from the authorized
EC2 instance profile, not a browser or uploaded file. Sample systemd unit
and timer are in `ops/`. No Docker or scheduled deployment is performed.

Before production: independently qualified network and service roles, TLS,
SQS queue policy/KMS, actual SQS acceptance and downstream idempotency
integration, replay/timeout tests, dead-letter alarm, separate consumer
authorizations, outage drills, and operational metrics. Unit tests use an
inert fake transport, not real AWS.
