# Cross-domain emergency containment — SA-1.1 D13

STOP is **not** a distributed atomic transaction. The security-account S3
veto can block fresh gateway admissions while an in-flight workload
publication remains committed-but-unservable.

Containment uses four **distinct** claims, never a single "stopped" flag:

1. A fresh independently administered security-root read confirms an active
   STOP for the expected installation and veto generation.
2. The separately enrolled authority signs a fence that binds that STOP
   generation, target, incarnation and target epoch to `STOP_SERVING`.
3. **Every** enrolled gateway signs an acknowledgment showing that the
   generation was observed and further protected admissions were closed.
4. The maximum previously admitted response-write deadline has elapsed,
   including a bounded safety margin. Only then is `CONTAINED` eligible.

`stop_containment.py` verifies distinct P-256 signing purposes for authority
and gateway receipts, rejects unknown/duplicate/revoked gateways, requires
the exact enrolled gateway set, checks installation/target/generation and
bounds the response drain. A missing authority fence is only
`VETO_RECORDED`, missing gateway ACKs remain `AUTHORITY_FENCED`, and
early completion remains `GATEWAYS_ACKNOWLEDGED_DRAINING`. Invalid proofs
are rejected, not interpreted as success.

**Not qualified for production:** This module is a pure validation contract
over **trusted inputs**, not a deployed distributed incident coordinator.
Its caller must independently fetch current root/veto records and the complete
gateway enrollment list, persist signed ACKs/receipts as immutable records,
fence the local DB under serializable rules, and measure real TLS admission
and response-write cutoffs. Offline/crashed gateways require independent
verifiable cutoff; simply missing an ACK cannot be called contained.
No recovery/reopen or emergency allow is implemented.

Negative tests use only synthetic keys and inert fixtures. Live outage,
concurrency, time-skew, restoration and cross-account drills remain required
before production.
