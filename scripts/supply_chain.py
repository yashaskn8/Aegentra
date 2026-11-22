"""Offline, deterministic CycloneDX inventory of committed dependency locks.

This is unsigned source-dependency metadata, not verified runtime provenance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!~-]*)")
SHA256 = re.compile(r"--hash=sha256:([0-9a-f]{64})")


class SupplyChainError(ValueError):
    pass


def python_components(raw: str, *, minimum: int = 10) -> list[dict]:
    """Deny unpinned names, absent wheel hashes and executable pip directives."""
    packages: dict[str, dict] = {}
    current: str | None = None
    for original in raw.splitlines():
        line = original.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        digest = SHA256.fullmatch(line)
        if digest:
            if current is None:
                raise SupplyChainError("Python hash has no pinned package")
            packages[current]["hashes"].append(
                {"alg": "SHA-256", "content": digest.group(1)}
            )
            continue
        pin = PIN.fullmatch(line)
        if pin:
            name, version = pin.groups()
            key = re.sub(r"[-_.]+", "-", name).lower()
            if key in packages:
                raise SupplyChainError("duplicate pinned Python dependency")
            packages[key] = {
                "type": "library",
                "bom-ref": f"python:{key}@{version}",
                "name": key,
                "version": version,
                "purl": f"pkg:pypi/{quote(key, safe='')}@{quote(version, safe='')}",
                "hashes": [],
            }
            current = key
            continue
        raise SupplyChainError("unknown or unpinned Python lock directive")
    if len(packages) < minimum or any(not p["hashes"] for p in packages.values()):
        raise SupplyChainError("Python lock must pin every package with SHA-256")
    return [packages[k] for k in sorted(packages)]


def _npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        if name.count("/") != 1:
            raise SupplyChainError("invalid npm scope")
        scope, package = name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(package, safe='')}@{quote(version, safe='')}"
    if "/" in name or not name:
        raise SupplyChainError("invalid npm package name")
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def npm_components(lock: dict, manifest: dict, project: str, *, minimum: int = 10) -> list[dict]:
    """Allow integrity-less packages only when npm marks them bundled."""
    if lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise SupplyChainError(f"{project}: requires npm lockfile v3")
    root = lock["packages"].get("")
    if not isinstance(root, dict) or root.get("name") != manifest.get("name"):
        raise SupplyChainError(f"{project}: package manifest identity mismatch")
    for kind in ("dependencies", "devDependencies", "optionalDependencies"):
        if root.get(kind, {}) != manifest.get(kind, {}):
            raise SupplyChainError(f"{project}: declared dependency range changed")
    components = []
    for location, package in sorted(lock["packages"].items()):
        if not location:
            continue
        if not isinstance(package, dict) or "node_modules/" not in location:
            raise SupplyChainError(f"{project}: invalid npm package location")
        name = location.rsplit("node_modules/", 1)[1]
        version = package.get("version")
        if not isinstance(version, str) or not version or any(x.isspace() for x in version):
            raise SupplyChainError(f"{project}: npm package lacks exact version")
        item = {
            "type": "library",
            "bom-ref": f"npm:{project}:{location}",
            "name": name,
            "version": version,
            "purl": _npm_purl(name, version),
        }
        integrity = package.get("integrity")
        if integrity is None:
            if package.get("inBundle") is not True or package.get("resolved"):
                raise SupplyChainError(f"{project}: unverified standalone npm package")
            item["properties"] = [{"name": "aegentra:bundled-with-parent", "value": "true"}]
        else:
            if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
                raise SupplyChainError(f"{project}: weak or unrecognized npm integrity")
            try:
                digest = base64.b64decode(integrity[7:], validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise SupplyChainError(f"{project}: corrupt npm integrity") from exc
            if len(digest) != 64:
                raise SupplyChainError(f"{project}: invalid npm SHA-512")
            resolved = package.get("resolved")
            if not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/"):
                raise SupplyChainError(f"{project}: external npm registry denied")
            item["hashes"] = [{"alg": "SHA-512", "content": digest.hex()}]
        components.append(item)
    if len(components) < minimum:
        raise SupplyChainError(f"{project}: npm inventory unexpectedly small")
    return components


def build_sbom(root: Path = ROOT) -> dict:
    components = []
    properties = []
    for relative in ("backend/requirements.lock", "frontend/package-lock.json", "infra/package-lock.json"):
        content = (root / relative).read_bytes()
        properties.append({
            "name": f"aegentra:lock-sha256:{relative}",
            "value": hashlib.sha256(content).hexdigest(),
        })
        if relative.startswith("backend/"):
            components.extend(python_components(content.decode("utf-8")))
        else:
            project = relative.split("/")[0]
            components.extend(npm_components(
                json.loads(content),
                json.loads((root / project / "package.json").read_text("utf-8")),
                project,
            ))
    refs = [component["bom-ref"] for component in components]
    if len(refs) != len(set(refs)):
        raise SupplyChainError("duplicate SBOM component reference")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "aegentra-source", "version": "0.1.0"},
            "properties": sorted(properties, key=lambda p: p["name"]) + [
                {"name": "aegentra:evidence-class", "value": "unsigned-lockfile-inventory"},
            ],
        },
        "components": sorted(components, key=lambda p: p["bom-ref"]),
    }


def serialized_sbom(root: Path = ROOT) -> bytes:
    return (json.dumps(build_sbom(root), sort_keys=True, indent=2) + "\n").encode()


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"generate", "verify"}:
        print("Usage: supply_chain.py generate|verify <sbom.json>", file=sys.stderr)
        return 2
    target = Path(sys.argv[2])
    content = serialized_sbom()
    if sys.argv[1] == "generate":
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    elif not target.is_file() or target.read_bytes() != content:
        raise SupplyChainError("generated SBOM differs from committed lockfiles")
    print(f"Unsigned dependency inventory: {len(build_sbom()['components'])} entries")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SupplyChainError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"supply chain check blocked: {exc}", file=sys.stderr)
        sys.exit(1)
