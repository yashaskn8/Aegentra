# SA-1.1 architecture traceability

The source is `SentinelAI_SA11_Master_Architecture.pdf`, Phase 1, 20 November 2026,
15 pages, SHA-256 `883ab90fb9197c9965cb546885b3da8b292962754334f58b09033da963dd5db1`.
The page numbers and D/F/T identifiers below come from that file. The
[incremental requirements ledger](requirements-ledger.json) retains its
existing identifiers and records file and CI evidence for individual changes.

## Sections and implementation

| Section | Repository evidence | Open implementation or verification |
| --- | --- | --- |
| 1, p. 1 · Authorized first release | [Application assembly](../backend/aegentra/api.py), [fixed profile](fixed-delivery-profile.md), [release gates](security-release-gates.md) | Protected serving requires independent enrollment and qualification. |
| 2, pp. 2–3 · Modules and trust domains | [Server assembly](../backend/aegentra/server.py), [bridge roles](native-guest-contract.md), [observer interface](observer-http.md), [synthesis](../infra/README.md) | Physical and administrative separation still needs independent evidence. Several reviewed protocol modules have no active runtime consumer. |
| 3, pp. 3–4 · Intake and enrollment | [Content manifest](content-manifest.md), [staging](staging-upload.md), [versioned storage proof](verified-storage.md), [enrollment](s0-enrollment-contract.md) | The verifier is an unsigned reference contract. It lacks an independently operated consumer and signed source-builder provenance. |
| 4, pp. 4–5 · Analysis and evidence | [Scan leases](scan-leases.md), [guest protocol](native-guest-contract.md), [advisory receipts](scan-receipts.md), [static analysis](../backend/aegentra/static_analysis.py), [disposal](guest-disposal.md) | Evidence production remains disconnected from case reads. Typed issuer-event ingestion, correction history, provenance, retention and independent analysis fixtures remain open. |
| 5, pp. 5–8 · Protected release | [Release contracts](release-shadow.md), [witness archive](witness-archive.md), [publication](publication-protocol.md), [gateway](protected-gateway.md), [observer](independent-observer.md), [emergency veto](emergency-veto.md) | Deployment, physical immutability, custody, origin closure, live service availability and drills require independent verification. |
| 6, pp. 8–9 · Backend contracts | [Auth and scoped routes](../backend/aegentra/auth_routes.py) include authenticated asset reads by ID. See [case storage](../backend/aegentra/case_store.py) and the [operations projection](../backend/aegentra/operations_projection.py). | Findings, exports, typed events, readiness, metrics and private release/work interfaces remain partial or absent. |
| 7, pp. 9–11 · PostgreSQL and audit | [Migrations](../backend/migrations/versions), [audit](../backend/aegentra/audit.py), [checkpoint](audit-checkpoints.md), [outbox](outbox-dispatch.md), [pagination index](../backend/migrations/versions/0023_case_evidence_page.py) | Typed evidence provenance, retention holds, consent, tombstones and restored-read handling remain open. Archive and consumer durability require external evidence. |
| 8, p. 11 · Console and AI | [Console source](../frontend/src), [browser regressions](../frontend/e2e/console.pw.ts), [case evidence summary](../frontend/src/CaseEvidencePanel.tsx) | A model-free summary covers loaded evidence metadata. Full case timelines, scoped diffs, approval/observation views and optional external processing remain open. |
| 9, pp. 12–13 · AWS, operations and recovery | [Native CDK](../infra), [supply-chain checks](python-supply-chain.md), [incident containment](incident-containment.md), [recovery](recovery-preflight.md) | Physical identity and infrastructure controls, deployment, restore drills, capacity and independent responder evidence remain open. |
| 10, pp. 13–15 · Implementation and qualification | [Implementation status](implementation-status.md), [release gates](security-release-gates.md), [incremental ledger](requirements-ledger.json) | The PDF provides the qualification index. Detailed Matrix C oracles and independent signed results were unavailable. |

## Qualification index

| Decision | Finding / test | Gate | Repository evidence and qualification work |
| --- | --- | --- | --- |
| D1 | F01 / T01 | P0 | [Fixed delivery](fixed-delivery-profile.md), [enrollment](s0-enrollment-contract.md). Enrolled origin and browser/CDN closure evidence required. |
| D2 | F02 / T02 | P0 | [Authority and witness protocol](publication-protocol.md). Independent cross-service receipt and failure drills required. |
| D3 | F03 / T03 | P0 | [Fenced state and sequence](release-shadow.md), [native DB tests](../backend/tests/test_release_state_integration.py). Qualified writer and recovery fencing evidence required. |
| D4 | F04 / T04 | P0 | [Review verification](../backend/aegentra/review_crypto.py), [review regressions](../backend/tests/test_review_crypto.py). Independent hardware enrollment and reviewer client required. |
| D5 | F05 / T05 | P0 | [Content identity](content-manifest.md), [verified storage](verified-storage.md), [bundle predicate](bundle-predicate.md). Trusted source-builder and final-byte provenance required. |
| D6 | F06 / T06 | P0 | [Native isolation inventory](native-isolation-inventory.md), [launch preflight](native-launch-preflight.md). Independent live native isolation and custody evidence required. |
| D7 | F07 / T07 | P0 | [Static analysis](../backend/aegentra/static_analysis.py), [integrity regression](../backend/tests/test_lockfile_integrity.py). Measured analysis corpus and pinned native artifact evidence required. |
| D8 | F08 / T08 | P1 | [Native tests and implementation status](implementation-status.md). Measure qualified capacity, time and cost on the actual target workload. |
| D9 | F09 / T09 | P0 | [Scoped case tests](../backend/tests/test_case_integration.py), [console tests](../frontend/e2e/console.pw.ts). Full case/evidence projection, external-origin and retention gates remain open. |
| D10 | F10 / T10 | P1 | [Local evidence summary](../frontend/src/CaseEvidencePanel.tsx). Consent/dispatch controls and blinded evaluation are required if external inference is enabled. |
| D11 | F11 / T11 | P0 | [Recovery preflight](recovery-preflight.md), [witness archive](witness-archive.md). Independently retained floor, tombstones, restore and old-writer denial evidence required. |
| D12 | F12 / T12 | P0 | [Audit reconciliation](audit-reconcile.md), [checkpoint](audit-checkpoints.md), [native outbox tests](../backend/tests/test_outbox_dispatch_integration.py). Independent archive reconciliation and physical recovery evidence required. |
| D13 | F13 / T13 | P0 | [Signed veto](emergency-veto.md), [STOP containment](stop-containment.md). Enrolled gateway acknowledgment, bounded drain and independent resume drills required. |
| D14 | F14 / T14 | P1 | [Scan leases](scan-leases.md), [outbox dispatch](outbox-dispatch.md). Real worker and consumer replay, outage and capacity evidence required. |
| D15 | F15 / T15 | P1 | [Versioned evidence verifier](../backend/aegentra/evidence_verifier.py), [observation contract](independent-observer.md). Typed issuer-event intake, retained corrections, evidence lifecycle and independent verification remain open. |

The ten sections and fifteen indexed decisions are fixed coverage anchors.
Several anchors contain multiple requirements. This map gives no percentage
of local implementation or production qualification. Protected operation
remains gated by the independent evidence listed above.

| Evidence status | Examples |
| --- | --- |
| Complete in the local application | Section 6 scoped asset lookup with tenant and revocation checks. Section 7 indexed evidence pagination with per-page membership and stable cursor order. |
| Partial | Section 8 deterministic summary covers the metadata pages loaded by the case member. Full case timelines, scoped source diffs and release projections are open. |
| Disconnected | Section 3 storage verification and section 4 receipt recording are callable contracts. The browser API has no production evidence writer and no independent service connects these contracts to routine operation. |
| Unverified | D8 end-to-end capacity and cost bounds under an enrolled workload. The synthetic case-paging measurement covers one PostgreSQL query. |
| Externally blocked | The detailed Matrix C oracles and independently witnessed custody, origin, isolation, veto, restoration and approval evidence. |
