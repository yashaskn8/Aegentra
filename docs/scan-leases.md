# Scan job fencing — SA-1.1 §4

PostgreSQL owns an opaque job ID, attempt generation, random nonce, lease
expiry and eight-minute attempt deadline. A controller can claim a 90-second
lease and renew it, but duplicate deliveries cannot claim the same live job.
After expiry, a replacement receives a *new* generation and nonce. Old worker
results are discarded. Only three attempts are permitted.

Submitting a result stores only its SHA-256 and changes status to
`PENDING_TRUSTED_VALIDATION`. **This is NOT a completed scan, a clean verdict,
or an approval.** The trusted validator, fresh EC2 guest lifecycle, encrypted
EBS frame transfer, separate analysis account, cleanup and SQS controller
remain unimplemented and must not be represented as active controls.

No hostile input may execute in the FastAPI process, the database host or
a privileged verifier. Native PostgreSQL integration tests cover duplicates,
fencing, expired leases and cross-tenant lookup denial.
