# Defensive red-team review — 2026-11-20

**Scope:** Aegentra repository code and native CI fixtures. Review and
adversarial unit tests targeted immutable evidence version selection, signed
protected-origin authorization, and audit reconstruction. No requests were
sent to customer origins or AWS accounts; no EC2 guests or production gateway
were exercised. This is **not** an independent penetration-test certificate.

## Findings and code-level remediation

| Finding | Risk | Remediation | Evidence |
|---|---|---|---|
| RT-01: Version reader allowed a null/unpinned version parameter into the S3 get path | High — immutable storage assertions could accidentally reference an unversioned object | Reject absent, literal `null`, non-string, or oversized VersionIds in both S3 reader and byte verifier before I/O (`72db114`) | New negative tests in `test_evidence_verifier.py` |
| RT-02: origin key membership used raw `startswith`, so malformed enrolled prefixes could include sibling object namespaces | High — storage scope confusion if signed origin binding/enrollment is misconfigured | Require canonical directory-delimited prefixes and validate key segments in both origin binding and gateway (`93e2a23`) | New signed-sibling-key and malformed-enrollment tests |
| RT-03: audit hash chain stored a body hash but not canonical event bytes; actors, event types, or timestamps could be changed in database rows without updating the chain hash | High — a reconciling reader could accept inconsistent audit metadata | New bounded canonical payload retention, migration 0017, and strict payload/metadata/hash recheck (`68841c6`) | New actor/type/time/byte tampering tests; native PostgreSQL migration CI |
| RT-04: Python JSON hashing could serialize nonstandard NaN/infinity values that a strict independent verifier refuses | Medium — non-reconcilable audit records | Fail at serialization with `allow_nan=False` (`ed1b6cd`) | Regression tests for non-finite numeric values |

Commit references are repository code changes, not assertions about deployed
behavior. The release remains **NO-GO** until required independently witnessed
P0 qualification is completed.

## Explicit residual risks — not solved by this review

1. **Historical audit records:** Existing pre-0017 rows have no retained
   canonical payload. The migration does not reconstruct or fabricate it.
   Reconciliation now rejects these records as payload-incomplete; an
   independent archival/rebaseline decision and complete source acquisition
   remain necessary before any production checkpointing.
2. **Database administrator compromise:** Canonical payloads in the same
   database alone cannot prevent wholesale rewrite of the hash chain. An
   outside-database append-only source, independent terminal sequence and
   immutable checkpoint chain are required.
3. **AWS custody and isolation:** Separate real accounts, role/key grants,
   versioning, Object Lock, native disposable EC2 guests, no-route/no-IMDS
   drills and cleanup evidence were not tested.
4. **Serving and incident response:** Customer-origin bypass closure,
   browser/CDN fidelity, independent live veto, signed gateway STOP
   acknowledgments and recovery drills are not qualified.
5. **Certification:** Matrix C's missing fixtures and independent F01–F15
   sign-off cannot be inferred from passing code tests.

## Verification rules

Every remediation must be tested on `main` with backend unit and native
PostgreSQL integration workflows plus frontend build and CDK synthesis.
GitHub Actions success verifies only the synthetic contracts in that commit,
not resistance to real-world bypass or production deployment. No Docker,
branches, pull requests, AWS mutations or protected serving occurred.

## Follow-up: identity lifecycle and upload finalization

| Finding | Risk | Code-level remediation | Test |
|---|---|---|---|
| RT-05: browser session did not pin the identity's membership version | Old cookie could become valid again after deactivation/reactivation, or remain valid after a role change | Session-version check, automatic monotonically advancing identity version on sensitive changes, and nullable legacy-session invalidation via migration 0018 (`7702f29`) | Native PostgreSQL reactivation/role-change regression in `test_auth_integration.py` |
| RT-06: upload finalization could accept literal S3 `null` version | Invalid immutable-version claim could irreversibly consume an otherwise valid upload ticket | Reject `null` both at API schema and transactional finalization boundary (`b2a3784`) | Native PostgreSQL finalization rejection then valid retry in `test_upload_integration.py` |

**Limits:** Synthetic network/OIDC and S3 fixtures remain in use. The
membership trigger only guards updates that go through the ordinary PostgreSQL
write path and does not defend against a privileged database administrator.
There is no independent IAM/credential revocation drill, production OIDC
provider validation, or real versioned S3 upload qualification in this pass.
The protected-production release verdict remains **NO-GO**.
