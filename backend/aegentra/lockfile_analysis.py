"""Conservative npm package-lock v3 inspection (read-only, no npm execution).

The lockfile is evidence about declared resolution, never proof of package
safety or provenance. Unknown formats are incomplete, not clean.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from aegentra.bounded_json import ManifestError, strict_json

MAX_LOCK_BYTES = 10 * 1024 * 1024
MAX_PACKAGES = 2_000
_DIGEST_BYTES = {"sha256": 32, "sha384": 48, "sha512": 64}


def _valid_integrity(value: object) -> bool:
    # Keep the existing single-token standard-base64 profile; do not infer
    # integrity from an unsupported format or an incorrectly sized digest.
    if not isinstance(value, str) or len(value) > 95:
        return False
    algorithm, separator, encoded = value.partition("-")
    size = _DIGEST_BYTES.get(algorithm)
    if not separator or size is None or len(encoded) != 4 * ((size + 2) // 3):
        return False
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(digest) == size and base64.b64encode(digest).decode("ascii") == encoded


@dataclass(frozen=True)
class LockedPackage:
    path: str
    version: str
    integrity: str | None


@dataclass(frozen=True)
class LockfileReport:
    status: str
    packages: tuple[LockedPackage, ...]
    gaps: tuple[str, ...]


def inspect_package_lock(data: bytes) -> LockfileReport:
    try:
        value = strict_json(data, max_bytes=MAX_LOCK_BYTES)
    except ManifestError as exc:
        return LockfileReport("INCOMPLETE", (), (str(exc),))
    if not isinstance(value, dict) or type(value.get("lockfileVersion")) is not int:
        return LockfileReport("INCOMPLETE", (), ("INVALID_LOCKFILE",))
    if value["lockfileVersion"] != 3:
        return LockfileReport("INCOMPLETE", (), ("UNSUPPORTED_LOCKFILE_VERSION",))
    entries = value.get("packages")
    if not isinstance(entries, dict) or len(entries) > MAX_PACKAGES:
        return LockfileReport("INCOMPLETE", (), ("INVALID_PACKAGE_GRAPH",))
    if not entries:
        return LockfileReport("INCOMPLETE", (), ("EMPTY_PACKAGE_GRAPH",))

    packages: list[LockedPackage] = []
    gaps: set[str] = set()
    for path, meta in sorted(entries.items()):
        if not isinstance(path, str) or len(path) > 512 or not isinstance(meta, dict):
            gaps.add("INVALID_PACKAGE_ENTRY")
            continue
        if path and (
            path.startswith("/") or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            gaps.add("AMBIGUOUS_PACKAGE_PATH")
            continue
        version = meta.get("version")
        integrity = meta.get("integrity")
        if path == "":
            # Root workspace is not a downloaded dependency.
            continue
        if not isinstance(version, str) or not 1 <= len(version) <= 128:
            gaps.add("UNKNOWN_RESOLVED_VERSION")
            continue
        if integrity is not None and not _valid_integrity(integrity):
            gaps.add("INVALID_INTEGRITY")
            continue
        if integrity is None:
            gaps.add("MISSING_INTEGRITY")
        packages.append(LockedPackage(path, version, integrity))
    return LockfileReport(
        "INCOMPLETE" if gaps else "REVIEWABLE",
        tuple(packages), tuple(sorted(gaps)),
    )
