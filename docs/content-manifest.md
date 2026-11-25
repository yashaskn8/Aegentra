# Canonical artifact identity — implementation note

SA-1.1 §3 requires exact pre-upload content identity and an independent
post-upload storage manifest. This increment implements only the *content*
identity: strictly declared ASCII file paths, lengths, SHA-256, media types,
bounded dependency graph and RFC 8785 canonical bytes.

These are metadata claims until **independently rehashed from a specific
versioned storage object**. Neither a content hash nor a lockfile inspection is
a signature, approval, safety verdict or publication credential.

## Current limitations

- No authenticated upload tickets or S3 staging/finalization endpoints yet.
- No signed storage manifest or independent byte-verification service.
- npm package-lock v3 parser is conservative; missing integrity/unknown entries
  are gaps. It never invokes package scripts, npm, Node or network fetches.
- RFC 8785 applies to the closed schema here; signed contexts must introduce
  distinct domain-separated message types and independent key custody.

The API remains unchanged. Do not expose untrusted customer analysis in the
FastAPI process. See security-release-gates.md.

## Strict UTF-8 input boundary

The shared `aegentra.bounded_json` decoder enforces strict UTF-8 before JSON
schema validation. UTF-16/32, a leading BOM, malformed UTF-8 and raw surrogate
encodings are rejected. Byte and nesting limits, duplicate-key rejection and
finite numeric parsing remain in effect. `content_manifest` re-exports the
existing parser and exception names; the lockfile inspector directly uses the
same bounded decoder and returns INCOMPLETE on invalid encoding. The canonical
RFC 8785 output and approval contracts are unchanged. This is an input-validation
control, not a claim that signed artifacts or production evidence are qualified.

## D7 npm lockfile integrity validation

For the existing single-token integrity profile, SHA-256/384/512 digests
must decode from canonical standard Base64 to exactly 32/48/64 bytes.
Malformed lengths, padding, alphabet, or nonzero unused padding bits are
`INVALID_INTEGRITY` and keep the inventory `INCOMPLETE`. Missing integrity
remains `MISSING_INTEGRITY`. The digest token is bounded before decoding.
Valid declarations are retained unchanged; no tarball is downloaded or
verified by this inspector. Multi-token SRI and other unsupported forms
remain incomplete. See [RFC 4648 §3.5](https://www.rfc-editor.org/rfc/rfc4648#section-3.5)
and [W3C SRI](https://www.w3.org/TR/sri/). This is metadata validation,
not artifact provenance, semantic safety, or production qualification.

## Unicode scalar validation

Strict UTF-8 transport decoding does not reject unpaired surrogate code points
represented by JSON escapes. After the bounded JSON parse, the shared decoder
checks every string value and property name, including nested arrays and
objects, and rejects unpaired surrogates as invalid Unicode. Valid paired
escapes and literal Unicode remain unchanged; no normalization is introduced.
This enforces the relevant Unicode requirement of RFC 8785 §3.2.2.2 without
changing canonical serialization, signed artifacts or authorization behavior.
The additional walk is linear in the bounded decoded input; existing byte and
depth limits remain in force. Full canonicalization and independent production
qualification remain separate requirements.
