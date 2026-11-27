"""Check the SA-1.1 register and enumerate its repository implementation surface."""

import argparse
import ast
import csv
import io
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
INVENTORY = DOCS / "sa11-component-inventory.tsv"
STATES = {"implemented_and_verified", "partially_implemented", "pending", "blocked"}
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def source_items(path, text):
    if path.startswith(("backend/aegentra/", "backend/migrations/versions/")):
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "create_table" and node.args and isinstance(node.args[0], ast.Constant):
                    yield "postgres_table", node.args[0].value
                if node.func.attr in {"create_check_constraint", "CheckConstraint"}:
                    for arg in node.args:
                        if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                                and re.search(r"\b(status|mode|guard|state|grant_type|coverage)\s+IN\s*\(",
                                              arg.value, re.IGNORECASE)):
                            yield "postgres_state_constraint", arg.value
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and re.fullmatch(r"AEGENTRA_[A-Z0-9_]+", node.value)):
                yield "environment_key", node.value
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                            and decorator.func.attr in METHODS and decorator.args
                            and isinstance(decorator.args[0], ast.Constant)):
                        continue
                    route = decorator.args[0].value
                    if path.endswith("/auth_routes.py"):
                        route = "/v1" + route
                    yield "http_route", f"{decorator.func.attr.upper()} {route}"
            if isinstance(node, ast.ClassDef) and any(
                isinstance(base, ast.Name) and base.id in {"Enum", "StrEnum"} for base in node.bases
            ):
                yield "state_enum", node.name
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.endswith("_TRANSITIONS"):
                        yield "transition_map", target.id
    if path.startswith("frontend/src/") and path.endswith(".tsx") and ".test." not in path:
        for component in re.findall(r"(?:^|\n)(?:export (?:default )?)?function ([A-Z]\w+)\(", text):
            yield "react_component", component
    if path.startswith("infra/lib/"):
        for name, identity in re.findall(r'new\s+([\w.]+)\(this,\s*"([^"]+)"', text):
            yield "cdk_construct", f"{name} {identity}"
        for identity in re.findall(r'\.addInterfaceEndpoint\("([^"]+)"', text):
            yield "cdk_construct", f"InterfaceVpcEndpoint {identity}"


def file_category(path):
    if path.startswith("backend/aegentra/"):
        return "backend_module"
    if path.startswith("backend/migrations/versions/"):
        return "migration"
    if path.startswith("frontend/src/") and path.endswith(".tsx") and ".test." not in path:
        return "frontend_component"
    if path.startswith(("ops/", "infra/bin/", "infra/lib/")):
        return "runtime_definition"
    if path.startswith(".github/workflows/") or (
        path.startswith(("backend/", "frontend/", "infra/")) and path.count("/") == 1
        and not path.endswith("/README.md")
    ):
        return "configuration"
    if path in {"backend/migrations/env.py", "frontend/src/styles.css"}:
        return "configuration"
    return None


def fallback_profile(path, item):
    if path.startswith("frontend/src/"):
        return "console"
    if path.startswith("infra/"):
        return "cloud"
    if item.startswith(("GET /v1/auth", "POST /v1/auth", "GET /v1/me", "GET /v1/assets", "POST /v1/assets")):
        return "identity"
    if path.startswith("backend/migrations/"):
        return "data"
    if path.startswith("backend/aegentra/"):
        return "platform"
    return "supply"


def inventory(profiles):
    files = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT,
    ).decode("utf-8").rstrip("\0").split("\0")
    rows = []
    for path in files:
        category = file_category(path)
        if category is None:
            continue
        matches = sorted(
            key for key, profile in profiles.items()
            if any(path == entry or path.startswith(entry + "/") for entry in profile["implementation"])
        )
        items = set(source_items(path, (ROOT / path).read_text(encoding="utf-8")))
        items.add((category, path))
        for kind, name in items:
            keys = matches or [fallback_profile(path, name)]
            if kind == "http_route":
                if name.endswith("/exports"):
                    keys = ["export"]
                elif "/timeline" in name or "/cases" in name:
                    keys = ["case"] if not name.endswith("/transition") else ["incident"]
                elif "/uploads" in name or "validate-manifest" in name:
                    keys = ["intake"]
                elif "/operations" in name:
                    keys = ["operations"]
                else:
                    keys = [fallback_profile(path, name)]
            rows.append((kind, name, path, ",".join(keys)))
    output = io.StringIO()
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(("kind", "component", "source", "evidence_profiles"))
    writer.writerows(sorted(rows))
    return output.getvalue(), len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-inventory", action="store_true")
    args = parser.parse_args()
    evidence = json.loads((DOCS / "sa11-evidence.json").read_text(encoding="utf-8"))
    profiles = evidence["profiles"]
    with (DOCS / "sa11-requirements.tsv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    ids = set()
    pages = Counter()
    for row in rows:
        identity = row["id"]
        page = int(row["pdf_page"])
        if (identity in ids or not re.fullmatch(fr"SA11-P{page:02d}-\d{{3}}", identity)
                or row["state"] not in STATES or row["evidence_profile"] not in profiles
                or not all(row.values())):
            raise SystemExit(f"Invalid SA-1.1 register row {identity}")
        ids.add(identity)
        pages[page] += 1
    if set(pages) != set(range(1, 16)):
        raise SystemExit("SA-1.1 register must account for all 15 PDF pages")
    floor = {int(page): count for page, count in evidence["register_floor_by_page"].items()}
    if set(floor) != set(pages) or any(pages[page] < count for page, count in floor.items()):
        raise SystemExit("SA-1.1 page coverage fell below its recorded requirement count")
    references = {row["specification_reference"] for row in rows}
    if any(f"10 stage S{number}" not in references for number in range(6)):
        raise SystemExit("SA-1.1 register lost a staged exit")
    decisions = set()
    for row in rows:
        match = re.match(r"D(\d+) F(\d+) T(\d+) P[01] ", row["acceptance_criterion"])
        if match and row["specification_reference"] == "10 decision-to-test index":
            decisions.add(tuple(map(int, match.groups())))
    if decisions != {(number, number, number) for number in range(1, 16)}:
        raise SystemExit("SA-1.1 register lost a D/F/T qualification entry")
    for name, profile in profiles.items():
        if not any(row["evidence_profile"] == name for row in rows):
            raise SystemExit(f"Unused SA-1.1 evidence profile {name}")
        files = profile["implementation"] + profile["backend_regression_files"] + profile.get(
            "other_regression_files", [],
        )
        for path in files:
            if not (ROOT / path).exists():
                raise SystemExit(f"Missing evidence path {path} in profile {name}")
        verification = profile.get("verification")
        if verification is not None:
            bound_ids = {row["id"] for row in rows if row["evidence_profile"] == name}
            if not set(verification["requirement_ids"]) <= bound_ids:
                raise SystemExit(f"Unbound verification evidence in profile {name}")
    generated, count = inventory(profiles)
    if args.write_inventory:
        INVENTORY.write_text(generated, encoding="utf-8", newline="")
    if not INVENTORY.is_file() or INVENTORY.read_text(encoding="utf-8") != generated:
        raise SystemExit("SA-1.1 component inventory differs. Run with --write-inventory and review the diff.")
    print(f"{len(rows)} requirements across {len(pages)} pages, {count} component records")
    for state, amount in sorted(Counter(row["state"] for row in rows).items()):
        print(f"  {state}: {amount}")


if __name__ == "__main__":
    main()
