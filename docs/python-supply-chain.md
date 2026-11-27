# Python supply-chain locking and CycloneDX source inventory

## Implemented reference controls

- `backend/requirements.lock` was generated for CPython 3.12 from
  `backend/pyproject.toml` with the `dev` extra and SHA-256 distribution
  hashes. The CI jobs install its requirements in pip hash-checking mode
  before installing the local project without dependency resolution.
- Both `frontend/package-lock.json` and `infra/package-lock.json`
  remain exact npm v3 lockfiles installed with `npm ci`.
- `scripts/supply_chain.py` validates all three files without network
  access and generates a deterministic CycloneDX 1.5 JSON inventory.
  Duplicate Python identity, missing hash, unpinned package, unexpected
  npm download URL, malformed package identity, or missing declared
  direct dependency fails the job.
- Direct npm runtime, development and optional dependencies must have an
  exact root `node_modules/<name>` lock entry (including scoped names).
  A nested transitive copy cannot substitute for a missing root entry;
  valid root and nested copies remain distinct inventory components.
  This checks declared lockfile closure, not installed bytes or provenance.
- Native npm packages marked `inBundle` may have no separate integrity
  field; they are listed explicitly as **bundled-with-parent** rather
  than being incorrectly labeled independently hashed.
- The security workflow publishes the inventory as the
  `source-dependency-sbom` GitHub Actions artifact, with a 14-day
  retention policy and SHA-256 digests of the source lockfiles.

## Regenerating a dependency lock (review required)

Generate from a clean native Windows Python 3.12 environment so the shared
lock includes Windows transitive dependencies. Review the proposed graph
and rerun the existing advisory, unit, integration and adversarial gates.

```bash
python -m pip install 'pip-tools==7.6.2'
pip-compile --extra=dev --generate-hashes --output-file=backend/requirements.lock --strip-extras backend/pyproject.toml
cd backend
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e '.[dev]'
python -m pip check
cd ..
python scripts/supply_chain.py generate /tmp/aegentra-source.cdx.json
python scripts/supply_chain.py verify /tmp/aegentra-source.cdx.json
```

Changes to a lockfile are security-relevant code changes. Review changed
versions, source project, transitive edges and integrity digests before
committing. The Python lock targets CPython 3.12 in Linux CI and on Windows.
It pins and hashes `colorama`, which pytest and Click require on Windows.
The shared lock includes that pin on both platforms.

## Security boundaries

The inventory is **unsigned and lockfile-derived**. It identifies pinned
package metadata but cannot prove which wheels were actually installed in
a deployed guest, that a publisher's package is benign, or that the same
byte-for-byte native artifact was produced from the source. pip's build
isolation bootstrap and npm's development toolchain are also not yet
independently signed release inputs.

Remaining gates include independent signed artifact provenance, reproducible
native AMI builds, physical source-to-image comparison, hardware-backed
review signatures, cross-account trust and deletion/isolated-host drills.
These are mandatory for protected production. Passing CI remains a
development/shadow signal, not an ENFORCED release approval.

## Unambiguous npm JSON input

The offline inventory now rejects duplicate property names at every object
level in both npm manifests and lockfiles rather than allowing Python's
last-value interpretation. Both inputs must be UTF-8 JSON objects. The
regression exercises full inventory generation for frontend and infrastructure
inputs and confirms that restoring valid input restores deterministic output.
This uses the standard library and adds no dependencies to the CI tool.
See [RFC 8259 §4](https://www.rfc-editor.org/rfc/rfc8259#section-4).
The inventory remains unsigned; this check does not verify installed bytes.
