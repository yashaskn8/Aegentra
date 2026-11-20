# SA-1.1 Independent observer and scoped mismatch response

A separate independently enrolled observer signs a typed readback that binds
the target/incarnation/revision, exact client-facing path, cohort, expected
and observed original representation SHA-256, header-profile SHA-256, HTTP
status, completeness and observation time. A P-256 verification key must be
pinned from the observer custody domain, not from a browser-supplied URL or
the release authority.

A serializable primary PostgreSQL transaction reads the installation guard
before locking the target. It checks the signed body against a **SEALED**
published revision and consumes the observation ID once. It writes the
observation with the corresponding audit/outbox event.

- A fresh, complete HTTP 200 representation matching exact bytes and profile
  is **MATCH**; it does not authorize publishing or automatically clear HOLD.
- A fresh, complete HTTP 200 byte/profile mismatch for the **current**
  published revision is **CURRENT_MISMATCH** and transitions the target to
  **STOP_SERVING**, invalidating outstanding grants.
- An inaccessible, non-200 or incomplete readback is a **COVERAGE_GAP** and
  transitions ACTIVE to **HOLD_PROMOTION**.
- A delayed or historically scoped observation becomes **HISTORICAL**,
  never stopping a newer healthy revision by itself.
- If a current sealed revision has no matching independent observation
  within the bounded configured five-minute default window, admission of
  new promotion is **HOLD_PROMOTION**. Existing releases still require a
  fresh authority head and independent live veto on each request.

The CI native PostgreSQL role has only SELECT on governance/publication,
column-limited target guard/epoch writes, status-only grant cancellation and
INSERT-only observation receipts plus audit/outbox rights. The ordinary
FastAPI role cannot read the observer table or control release guards.

**Remaining:** independently credentialed deployed observer and TLS client,
measured exact HTTPS request and response headers, CDN bypass/alternate
representation testing, signed readback retention, customer responder
confirmation and emergency STOP gateway acknowledgments. Unit and synthetic
native PostgreSQL CI are not production qualification.
