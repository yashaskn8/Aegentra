# SA-1.1 shadow-only release authority foundation

This increment introduces separate serializable organization and target guards,
a one-time grant ledger with 60-second maximum TTL, individually retained
cryptographically verified reviewer endorsements and challenge nonces, an
independent staging-proof signature purpose, and never-reused selection attempt
sequences. Published revision stays distinct and remains **zero** during this
shadow workflow.

A HOLD blocks promotions; STOP blocks serving and refuses an ordinary resume.
Target epoch advances on every new restriction, invalidating outstanding grants.

**Security boundary:** The commands are intentionally private, and the
application database role has no grants on these tables. A dedicated
release-authority role has only enough rights for shadow enrollment, signed
review recording and selection. It has *no privilege to write published
revisions*. We do not accept browser-supplied signer enrollment or an
AI/parser "clean" status as authorization.

**Not yet release-capable:** independently administered hardware-backed reviewer
enrollment, privileged identity recovery, real independent final-byte
verification, signed witness certificate, conditional-create independent
archive, publication commit, fresh gateway read, veto and observer are P0
gates. The code has no API for enabling ENFORCED.

Native CI uses ephemeral RSA/Ed25519 test keys and synthetic source hashes.
These tests exercise *protocol correctness*, not physical custody or
production readiness.
