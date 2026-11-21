# SA-1.1 security-release gates — production NO-GO

Code-level protocols, signed S0 enrollment and synthetic native CI tests have advanced, but
**none of the F01–F15 protected-production qualifications have been
independently signed off.** A component existing in Python is not proof that
independent AWS identities, human custody, enrolled origin routing, live veto
or customer TLS behavior are configured correctly.

| SA-1.1 decision | Repository implementation | Remaining gate |
|---|---|---|
| D1 exact origin closure | Bounded single-resource ASGI reference gateway | Independent controlled-origin writer and bypass/CSP/CDN negative tests |
| D2 witness/publish | Grant, selection, witness, pending-seal publication, receipt and head contracts | Production independent witness key, real S3 VersionId proof, concurrency/crash tests |
| D3 serialization | SERIALIZABLE primary release sessions, guard/nonce/sequence uniqueness | Production writer role ownership, lock/race/ack schedule and latency tests |
| D4 independent reviewers | Canonical subject, distinct Ed25519 signers and challenges | Hardware credential and custody enrollment, independent review clients, revocation |
| D5 scope/profile | Exact source/header/profile and fail-closed prebuffering | Live HTML/JS origin restriction and customer response fidelity |
| D6 cloud separation | CDK isolated VPC, read-only exact EC2/EBS inventory, AMI-pinned immutable journal, time-separated native detach bridge and independent key contracts | Real multi-account EC2/AMI/IAM isolation drills, verified launch/teardown and cleanup |
| D7 parser coverage | Tree-sitter and bounded raw guest frame/proof validation | Independent live isolation and hostile-input qualification |
| D8 capacity/cost | Native unit/integration CI | Real target request and cost envelope |
| D9 case/API/console | OIDC, bounded API, scoped case evidence paging, read-only scan status, React shell, native Chromium revocation/Back/inert-rendering tests | Independent browser/accessibility review, complete safe projections and exports |
| D10 inference | Not enabled | Consent/data broker, blind accuracy and egress assessment |
| D11 external root | Separate security-account STOP CAS/veto contract | Monotonic floor, physical protected keys and restoration |
| D12 database/audit | Composite FKs, FORCE RLS, role tests, outbox | External immutable archive, quotas, backup/tombstone |
| D13 freeze/containment | STOP/HOLD, observations, signed gateway ACK/drain oracle | Real incident identities, all gateway ACKs and drained live responses |
| D14 jobs/events | Fenced leases and guest frames, native two-pass detach checks, immutable journal, outbox/SQS handoff and bounded janitor intents | Deployed live EC2/EBS lifecycle, independent disposal inventory, retries and workload quotas |
| D15 evidence efficacy | Static facts only, explicit unknown/incomplete states | Independent accuracy datasets and proof provenance |

**Non-negotiable gating:** production ENFORCED requires all relevant P0
witness/origin/custody/STOP and Matrix C oracles, independently checked. No
"emergency allow." A historical mismatched observation does not disable a
healthy new release. Unavailable primary head or security veto denies
new protected responses. Already-sent bytes cannot be revoked.

Separate private incident/key/custody recovery and actual AWS deployment
are **not performed by this repository CI**. The SA-1.1 PDF references a
detailed Matrix C oracle but does not contain its full fixture descriptions;
those must be finalized before claiming certification.

Read component-specific documentation in `docs/` for exact gaps and
synthetic test contracts.
