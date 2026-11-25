"""Adversarial fixtures for the offline CycloneDX inventory gate."""
from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from supply_chain import (
    SupplyChainError, build_sbom, npm_components, python_components, serialized_sbom,
)


def python_lock() -> str:
    return "\n".join(
        f"pkg{i}==1.2.3 \\\n    --hash=sha256:{'a' * 64}"
        for i in range(11)
    )


def npm_fixture() -> tuple[dict, dict]:
    manifest = {"name": "test-project", "dependencies": {"pkg0": "^1.2.0"}}
    digest = "sha512-" + base64.b64encode(bytes(range(64))).decode()
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": copy.deepcopy(manifest),
            **{
                f"node_modules/pkg{i}": {
                    "version": "1.2.3",
                    "resolved": f"https://registry.npmjs.org/pkg{i}/-/pkg{i}-1.2.3.tgz",
                    "integrity": digest,
                }
                for i in range(11)
            },
        },
    }
    return lock, manifest


class SupplyChainTests(unittest.TestCase):
    def test_all_python_requirements_are_pinned_and_hashed(self):
        self.assertEqual(len(python_components(python_lock())), 11)
        for poison in ("pkg1>=1.0", "--index-url https://untrusted.invalid", "pkg0==1.0"):
            with self.assertRaises(SupplyChainError):
                python_components(python_lock() + "\n" + poison)

    def test_missing_hash_fails_closed(self):
        with self.assertRaises(SupplyChainError):
            python_components(python_lock() + "\nnewpkg==1.0")
        with self.assertRaises(SupplyChainError):
            python_components(python_lock().replace("a" * 64, "g" * 64))

    def test_npm_integrity_bundle_and_registry_rules(self):
        lock, manifest = npm_fixture()
        components = npm_components(lock, manifest, "frontend")
        self.assertEqual(len(components), 11)
        lock["packages"]["node_modules/pkg1"].pop("integrity")
        with self.assertRaises(SupplyChainError):
            npm_components(lock, manifest, "frontend")
        lock["packages"]["node_modules/pkg1"].pop("resolved")
        lock["packages"]["node_modules/pkg1"]["inBundle"] = True
        self.assertEqual(
            sum(bool(x.get("properties")) for x in npm_components(lock, manifest, "frontend")),
            1,
        )
        lock["packages"]["node_modules/pkg2"]["resolved"] = "https://foreign.invalid/pkg2.tgz"
        with self.assertRaises(SupplyChainError):
            npm_components(lock, manifest, "frontend")

    def test_manifest_drift_blocks_sbom(self):
        lock, manifest = npm_fixture()
        manifest["dependencies"]["pkg0"] = "^2.0.0"
        with self.assertRaises(SupplyChainError):
            npm_components(lock, manifest, "frontend")

    def test_declared_npm_dependency_cannot_disappear_from_lock(self):
        lock, manifest = npm_fixture()
        lock["packages"].pop("node_modules/pkg0")
        with self.assertRaises(SupplyChainError):
            npm_components(lock, manifest, "frontend")

    def test_nested_copy_cannot_satisfy_root_dependency(self):
        for kind in ("dependencies", "devDependencies", "optionalDependencies"):
            for name in ("pkg0", "@scope/pkg0"):
                with self.subTest(kind=kind, name=name):
                    lock, manifest = npm_fixture()
                    manifest.pop("dependencies")
                    manifest[kind] = {name: "^1.2.0"}
                    lock["packages"][""] = copy.deepcopy(manifest)
                    package = lock["packages"].pop("node_modules/pkg0")
                    lock["packages"][f"node_modules/pkg1/node_modules/{name}"] = package
                    with self.assertRaisesRegex(SupplyChainError, "missing from root lock"):
                        npm_components(lock, manifest, "frontend")

    def test_root_and_nested_copies_remain_distinct(self):
        lock, manifest = npm_fixture()
        manifest["dependencies"]["@scope/pkg0"] = "^1.2.0"
        lock["packages"][""] = copy.deepcopy(manifest)
        for location in ("node_modules/@scope/pkg0", "node_modules/pkg1/node_modules/@scope/pkg0"):
            lock["packages"][location] = copy.deepcopy(lock["packages"]["node_modules/pkg0"])
        components = npm_components(lock, manifest, "frontend")
        refs = {item["bom-ref"] for item in components if item["name"] == "@scope/pkg0"}
        self.assertEqual(refs, {
            "npm:frontend:node_modules/@scope/pkg0",
            "npm:frontend:node_modules/pkg1/node_modules/@scope/pkg0",
        })

    def test_duplicate_npm_json_keys_block_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for project in ("backend", "frontend", "infra"):
                (root / project).mkdir()
            (root / "backend/requirements.lock").write_text(python_lock(), encoding="utf-8")
            (root / "backend/pyproject.toml").write_text(
                "[project]\ndependencies=['pkg0>=1']\n", encoding="utf-8",
            )
            for project in ("frontend", "infra"):
                lock, manifest = npm_fixture()
                (root / project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
                (root / project / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
            original = serialized_sbom(root)
            for project in ("frontend", "infra"):
                for name, member in (("package-lock.json", '"lockfileVersion": 3'),
                                     ("package.json", '"pkg0": "^1.2.0"')):
                    path = root / project / name
                    raw = path.read_text("utf-8")
                    with self.subTest(project=project, file=name):
                        self.assertIn(member, raw)
                        path.write_text(raw.replace(member, member + ", " + member, 1), encoding="utf-8")
                        try:
                            with self.assertRaisesRegex(SupplyChainError, "duplicate JSON property"):
                                serialized_sbom(root)
                        finally:
                            path.write_text(raw, encoding="utf-8")
            self.assertEqual(serialized_sbom(root), original)

    def test_deterministic_sbom_and_mutation_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for project in ("backend", "frontend", "infra"):
                (root / project).mkdir()
            (root / "backend/requirements.lock").write_text(python_lock(), encoding="utf-8")
            (root / "backend/pyproject.toml").write_text(
                "[project]\nname='aegentra-backend'\nversion='0.1.0'\n"
                "dependencies=['pkg0>=1']\n"
                "[project.optional-dependencies]\ndev=['pkg1>=1']\n",
                encoding="utf-8",
            )
            for project in ("frontend", "infra"):
                lock, manifest = npm_fixture()
                (root / project / "package-lock.json").write_text(json.dumps(lock))
                (root / project / "package.json").write_text(json.dumps(manifest))
            original = serialized_sbom(root)
            self.assertEqual(original, serialized_sbom(root))
            self.assertEqual(len(build_sbom(root)["components"]), 33)
            self.assertEqual(build_sbom(root)["bomFormat"], "CycloneDX")
            (root / "infra/package-lock.json").write_text('{"lockfileVersion": 2}')
            with self.assertRaises(SupplyChainError):
                serialized_sbom(root)


if __name__ == "__main__":
    unittest.main()
