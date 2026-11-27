# Case evidence pagination

SA-1.1 section 7, page 10 calls for an ordered index for authorized case
pagination. The existing primary key could resolve an evidence link by ID.
For a late page it had to scan and sort rows to return the cursor order.

Migration `0023_case_evidence_page` adds a B-tree on organization, asset,
case, link timestamp and evidence UUID. The first three columns match the
tenant and case equality predicates. A PostgreSQL row comparison seeks past
the timestamp and UUID together. The UUID resolves ties, including cursors
created before the migration. Every request still checks membership first
and joins evidence by organization, asset and evidence ID under RLS.

PostgreSQL 17.11 on native Windows ran the same 100,000-link fixture under
the restricted CI application role. The page returns 25 items and checks one
additional row. Values are the median of five runs after one warm-up, using
`EXPLAIN (ANALYZE, BUFFERS, TIMING OFF)`. This measures the evidence lookup
after the separate membership query.

| Query and schema | Execution time | Shared buffer accesses |
| --- | ---: | ---: |
| Original cursor, prior schema | 86.440 ms | 1,577 |
| Original cursor, ordered index | 43.978 ms | 2,417 |
| Row cursor, ordered index | 0.183 ms | 117 |

The index-only plan still discarded 90,002 preceding links. The row cursor
turns both ordered fields into a seek condition. The index adds maintenance
work when evidence links change. The migration builds it transactionally and
can block writes during the build. Plan a database maintenance window for
shared environments with case writes. The downgrade removes only this index.

To reproduce in a disposable database with the backend CI app role and
grants, run from the repository root with `psql` configured for that database.
The synthetic inserts and `ANALYZE` run in a transaction that rolls back.

```text
# Schema at 0022_guest_physical_operations
psql -X -v row_cursor=false -f scripts/benchmark_case_evidence.sql
# After applying 0023_case_evidence_page
psql -X -v row_cursor=false -f scripts/benchmark_case_evidence.sql
psql -X -v row_cursor=true -f scripts/benchmark_case_evidence.sql
```
## Streaming metadata export

`GET /v1/cases/{case_id}/exports?projection=evidence_metadata` uses the indexed
case reader and the current browser session. The exact media type is
`application/x-ndjson`. The body consists of `evidence` records containing
the same fields as the paginated view and an `end` record with `next_cursor`.
Pass a non-null cursor back through the same authenticated route to continue.
An empty case returns only the end record. Clients must treat a response
without an end record as incomplete, even if the HTTP status is 200.

Each response reads up to 100 rows in batches of at most 25. The stream
reauthenticates the browser session and rechecks current case membership on
each subsequent batch. The metadata query itself filters by membership,
including when grants change after the initial case lookup. Transactions
close before yielding rows. A revocation or failed required dependency
interrupts subsequent batches. Already sent rows and rows admitted by the
current query may remain in transit. The export uses live keyset pagination
and is subject to concurrent changes to the case.

The API exports linked metadata only. The response is an attachment with
`no-store` and `nosniff`. Native PostgreSQL tests exercise projection
selection, cursor continuation, unauthorized access and revocation during
streaming. This contract is part of SA11-P08-036 in the atomic register.
