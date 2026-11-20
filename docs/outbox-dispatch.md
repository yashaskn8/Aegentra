# Native transactional outbox delivery — SA-1.1 D12

Every audit event already commits an audit-stream hash, an immutable audit row
and an outbox row in the **same PostgreSQL transaction**. Migration 0012 adds
durable, bounded dispatcher claims, lease generations and retry state.

The separate native dispatcher role sees only scoped outbox metadata and
read-only audit hashes. The ordinary API role may INSERT an outbox row with a
business transaction but cannot UPDATE its delivery/lease columns.

A worker claims at most 10 eligible events with PostgreSQL
`FOR UPDATE SKIP LOCKED` and commits its short lease before attempting any
network delivery. Claims are fenced by a random nonce digest, incrementing
lease generation, expiry and a maximum of 10 attempts. An unsent predecessor
blocks later events in the **same stream**, including after exhaustion; this
avoids incorrectly claiming ordered checkpoint completeness. Transient failure
schedules bounded exponential backoff. Exhausted rows remain visible for
operator action rather than being erased.

After the independently authenticated destination confirms delivery, the
worker may persist a bounded delivery-reference and mark the row delivered.
A lost acknowledgment can lead to redelivery. **At-least-once, not
exactly-once**: every sink must deduplicate by the immutable outbox event UUID,
and the outbox worker must verify its sink's acknowledgment. The claim never
contains raw customer source or prompts.

**Remaining before production:** a native, scoped and mTLS-authenticated
dispatcher process and systemd unit, actual target adapters, independently
verifiable sink receipts, dead-letter escalation, a retention/archive service,
cross-account disaster-recovery tests, lag/lease metrics and load budgeting.
Inert native PostgreSQL CI proves transaction/role/retry mechanics, not
remote delivery correctness.
