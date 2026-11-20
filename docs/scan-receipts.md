# Independent trusted validation receipt — prototype

A separate native PostgreSQL validator principal receives only the rights
necessary to lock/read a pending scan job, read guest attempt custody records,
append one advisory receipt, and append audit/outbox rows. The ordinary web
role and separate bridge role have **no read or write permission** to the
receipt table in the CI contract.

The validator checks fenced job generation, the exact result SHA-256 accepted
by the controller, matching original source SHA-256, toolchain digest, guest
nonce, and an independently journaled `DETACHED_VERIFIED` custody state.
The result frame must be canonical, bounded and internally consistent.

The receipt is typed `COMPLETE` or `INCOMPLETE`; **COMPLETE is only parser
coverage**. It cannot grant release authority. It does not sign a protected
approval, certify semantic safety, or prove cloud reachability.

Before production: real independent hosts, trusted original-byte acquisition,
a verifier signing key, actual EC2/EBS lifecycle, negative IAM/network drills,
SQS dispatch and disposal. Inert fixtures in native PostgreSQL CI cannot
satisfy these qualification gates.
