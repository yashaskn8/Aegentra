# Independent HTTPS readback — native observer reference

`NativeReadbackObserver` fetches a fresh nonce-bound, pinned P-256 signed
**current head** from the primary authority before it samples the exact
customer-facing HTTPS host and path. It requests identity encoding and
no-store, never follows redirects, and uses a bounded raw-byte stream.
It hashes the received content and the actual protected response headers,
not desired values from a config file. It records revision, cohort, time,
HTTP status and completeness, then signs the typed observation with a
separately pinned P-256/KMS observer key.

For fresh HTTP 200 complete observations, the separate observer-state
controller compares observed digests against the sealed current
publication and can issue STOP. Non-200 or incomplete coverage triggers
HOLD. Delayed or historical mismatches cannot stop a newer healthy
revision. A network/TLS failure raises `ReadbackUnavailable`; it is NOT a
clean observation and must be handled by the overdue-observation HOLD path.

**Not production qualified:** The tests use httpx.MockTransport, ephemeral
signers and a synthetic published head. Real TLS/DNS/SNI/certificate
validation, exclusive customer route, independent observer host/account,
access to all enrolled client cohorts, HTTP/2 and CDN header behavior,
latency/timing, loss-of-signer and outage alarm drills remain required.
The production caller must set `trust_env=False`, use independent CA
trust and never accept browser-configured arbitrary URLs.
