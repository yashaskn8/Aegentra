# D9 authorized case timeline

SA-1.1 sections 4 and 6–8 require case-scoped evidence projections, renewed
authorization on each page, bounded pagination, and an investigation timeline
in the case workspace. Case membership grants a read of the case’s projection.
The case belongs to one organization and asset. An evidence reference is
visible only through its current link to that case and asset.

## Where the records come from

The case store and incident services already append case creation, evidence
linking, operator triage, containment requests, and independent containment
records to the `cases` audit stream in their business transactions. The timeline
projects that ledger. It presents containment requests and custody-verified
records as distinct events. The database enforces the existing independent
incident role on new verified containment records.

Before this change, the workspace could read case state and evidence metadata but
could not reconstruct earlier incident transitions. Reading case rows alone
would lose those transitions. A second timeline table would introduce another
event write path. Parsing all audit rows on every request would make page cost
grow with unrelated history. Migration `0024_case_timeline` adds generated
scope columns to the existing ledger and indexes organization, case, timestamp,
and event hash. The timestamp and hash form a stable display order. Equal
timestamps use hash order. The private audit sequence remains authoritative for
ledger reconciliation.

The migration computes coordinates from retained payloads, including events
written by older application versions. Records without retained bytes or usable
scope cannot be attributed to a case. New and historical payloads selected by
the index are validated again before serialization. The migration rewrites the
audit table to populate generated columns and takes a table lock. Plan a
maintenance window on a shared database. Downgrade removes the projection
columns, index and guard. The audit bodies, hashes and outbox records survive.

## API and workspace

- `GET /v1/cases/{case_id}/timeline` reads the case timeline.
- `GET /v1/cases/{case_id}/evidence/{evidence_id}/timeline` narrows the read to a current evidence link.
- Both routes use the existing BFF session and transaction-scoped organization
  context. The page query checks current membership and evidence linkage before
  the lookahead limit. Cursors bind the organization, case, optional evidence
  reference and display boundary. The response contains only the event identifier,
  timestamp, event kind, optional scoped evidence identifier and optional case
  revision.
- The workspace opens one evidence or timeline panel at a time. Scope and
  revision changes discard the previous timeline and cancel its requests. A case
  404 removes that case from the workspace. Session denial runs the existing
  reauthorization path. Loading, empty, retry and event-count messages are
  available to assistive technology.

FastAPI validates case and evidence responses against Pydantic models while
keeping existing wire keys. Native HTTP tests check the typed schema in-process
and verify that the deployed app configuration keeps `/openapi.json` closed.
Schemathesis could validate generated requests against an in-process schema,
but it would need fixture-aware case IDs, cookie handling, and a way to obtain
valid next-page cursors to exercise successful authenticated paths. The native
fixtures and bounded Hypothesis tests already cover those paths for this slice.
The project dependency set remains sufficient.

## Verification and plugin evidence

| Tool or skill | Operation and result |
| --- | --- |
| Addy Osmani Agent Skills | Applied the installed `using-agent-skills`, `doubt-driven-development`, `api-and-interface-design`, `test-driven-development`, `incremental-implementation`, `debugging-and-error-recovery`, `frontend-ui-engineering`, `accessibility-engineering`, `browser-testing-with-devtools`, `code-review-and-quality`, `security-and-hardening` and `ci-cd-and-automation` files. The first native acceptance request returned 404 and the first DOM run could not find the timeline control. Native and Chromium regressions now exercise both. A synthetic browser fixture initially counted an extra development-mode fetch. Its error state now persists until the test explicitly permits retry. |
| Ponytail | Applied full mode and the review, audit and debt skills. Kept the ledger, membership helper, case workspace and current workflows. The review also identified a pagination focus change that should occur only if focus is still on the disappearing button. |
| Matt Pocock architecture skills | Applied `domain-modeling`, `codebase-design` and `improve-codebase-architecture` to scope the projection to case and asset, keep one ledger and retain transaction ownership. The independent review checked same-organization denial, revocation, legacy scope and the generated-column rewrite. |
| CodeGraph 1.6.4 | Ran `codegraph context accessible_case`, `codegraph context list_case_evidence`, `codegraph callers accessible_case`, `codegraph callees list_case_evidence`, `codegraph impact list_case_evidence`, and `codegraph_explore`. The new routes flow through `list_case_timeline` to the existing membership helper and audit ledger. `codegraph sync`, `codegraph status` and `codegraph cycles` verify the resulting graph. |
| Context7 4.9.0 | Used `resolve-library-id` and `query-docs` for FastAPI, Pydantic, SQLAlchemy, PostgreSQL, React, Hypothesis, Alembic and Schemathesis. Where the locked release was absent from the documentation index, checked official documentation and verified behavior against installed versions. |
| Hypothesis 6.170.17 | Ran `python -m pytest -q --hypothesis-show-statistics` with native PostgreSQL variables and repeated the focused tests with `--hypothesis-seed=23817`. The new cursor, ordering and wire-format properties passed 40 generated examples each in the full run. |
| Playwright MCP 0.0.86 | `browser_navigate`, `browser_snapshot`, `browser_click` and `browser_press_key` exercised the built console with synthetic loopback data at 390 px. The final page retained the evidence ID and moved focus to its count. A fixture 503 produced a retry control, and retry showed the second case’s empty state. `rtk npm run test:e2e -- --workers=1 --reporter=list --global-timeout=90000` passed four Chromium scenarios. |
| Import Linter, Pyright and Dependency Cruiser | `lint-imports --no-logo` kept both Python contracts. `pyright --pythonpath` checked the locked Python 3.12 environment with zero diagnostics. `rtk npm run check:architecture` passed, with the case-view rules covering the timeline panel. |
| RTK 1.2.1 | Used explicit `rtk git`, `rtk npm`, `rtk bypass` and `rtk gain` commands for source review, builds, complete test output and verification. |

## Technical references

- FastAPI response validation and Pydantic strict typing inform the closed projection. [FastAPI response models](https://fastapi.tiangolo.com/tutorial/response-model/) · [Pydantic strict mode](https://docs.pydantic.dev/latest/concepts/strict_mode/)
- Transactions retain the existing async session context. The keyset comparison and index use PostgreSQL 17 behavior. [SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/21/orm/extensions/asyncio.html) · [PostgreSQL multicolumn indexes](https://www.postgresql.org/docs/17/indexes-multicolumn.html) · [PostgreSQL row comparisons](https://www.postgresql.org/docs/17/functions-comparisons.html)
- Effects abort stale reads and panel identity resets on revision changes. [React effect cleanup](https://react.dev/reference/react/useEffect)
- Property tests use bounded strategies. Migration tests use the same additive upgrade and downgrade operations as CI. [Hypothesis settings](https://hypothesis.readthedocs.io/en/latest/settings.html) · [Alembic operations](https://alembic.sqlalchemy.org/en/latest/ops.html)
- The schema tool can work with authenticated fixtures and selected operations. [Schemathesis authentication](https://schemathesis.readthedocs.io/en/stable/guides/auth/)
