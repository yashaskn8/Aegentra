# SA-1.1 D1 — fixed two-resource browser delivery profile

**Inert reference implementation; NO-GO for a production protected origin.**

`FixedStaticProfile` generates the entry HTML *only from the audited,
constant template* `aegentra-fixed-entry-v1`. It allows exactly one
external classic JS file at `/app-<sha256>.js` with SHA-256 SRI and
`crossorigin="anonymous"`. The JavaScript is a previously authorized
artifact, not executed in the backend. The script is capped at 1 MiB.
The supplied HTML cannot contain arbitrary markup, injected inline
scripts, dynamic imports, plugins, service-worker registration or
extra resources. The template produces no source maps or network links.

The CSP uses only an exact matching **hash source** for `script-src`
and `script-src-elem`. It has no `'self'`, wildcard, inline,
`blob:` or `data:` script allowance; it also forbids workers,
connect, objects, base URI, forms and frames. No-store and nosniff
headers are fixed and their bytes contribute to the exact delivery
profile digest. **These browser restrictions do not prove that the
reviewed JavaScript is semantically safe.**

The protected gateway now requires an enrolled `FixedStaticProfile`
for **every** successful HTML or JS response. Even if a forged
published head and an independent witness claim an unexpected HTML
hash, the final bytes cannot pass the fixed-template check. A JS
response must match both its exact digest-derived path and pinned
script size/digest. Unsupported path, user-supplied HTML or a
same-origin but different script is denied without a successful
protected response.

**Unfinished:** one cryptographically signed *combined* bundle
manifest bound to the release review and both resource-head records,
an independent generated-template and origin writer, browser matrix
and CSP/SRI cross-browser testing, DNS/TLS alias closure, real
customer-owned origin path enforcement, CDN/encoding bypass drills,
independent deployment custody and fully versioned origin snapshots.
Existing per-resource signed head/profile digests alone do not
prove the two resources were atomically enrolled in the same release.
Keep ENFORCED disabled outside synthetic CI.
