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
