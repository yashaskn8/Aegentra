"""Fail-closed, repo-local security CI guard (Python stdlib only).

This is a defense-in-depth policy and high-confidence secret scanner, not a
complete secret detector, an external penetration test or a production oracle.
"""
from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# These are executed in the security workflow; a JUnit check ensures none
# silently disappear or skip. Real PostgreSQL/RLS tests run in backend.yml.
ADVERSARIAL = (
    "test_native_deadline_supervisor",
    "test_native_creation_controller",
    "test_native_physical_controller",
    "test_native_attachment_inventory",
    "test_native_ami_preflight",
    "test_native_isolation_guard",
    "test_native_isolation_collector",
    "test_native_launch_preflight",
    "test_native_detach_collector",
    "test_native_detach_worker",
    "test_guest_protocol",
    "test_security_veto",
    "test_protected_gateway",
    "test_review_crypto",
    "test_origin_binding",
    "test_staging_proof",
)

REQUIRED_WORKFLOWS = ("backend.yml", "frontend.yml", "infra.yml", "security.yml")
SOURCE_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".mjs", ".json",
    ".yml", ".yaml", ".toml", ".md", ".env", ".sh",
}
# Exact matched credentials only; this is not entropy-based secret discovery.
SECRET_PATTERNS = {
    "AWS access key ID": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{45,})\b"),
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{35,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
}


class SecurityGateError(ValueError):
    pass


def find_secrets(source: str) -> list[tuple[str, int]]:
    findings = []
    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(source):
            findings.append((label, source.count("\n", 0, match.start()) + 1))
    return findings


def scan_tracked_secrets(root: Path = ROOT) -> None:
    """Scan tracked text. Do not output the suspected credential itself."""
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    findings = []
    for raw in paths:
        if not raw:
            continue
        rel = raw.decode("utf-8", errors="surrogateescape")
        path = root / rel
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue  # Binary assets are not a text secret-scanning surface.
        for label, line in find_secrets(content):
            findings.append(f"{rel}:{line}: suspected {label}")
    if findings:
        raise SecurityGateError("Tracked-text credential scan blocked:\n" + "\n".join(findings))


def check_workflow_source(path: Path, contents: str) -> None:
    if not re.search(r"(?m)^  push:\s*$", contents) or not re.search(
        r"(?m)^  pull_request:\s*$", contents
    ):
        raise SecurityGateError(f"{path.name}: push and pull_request checks required")
    for forbidden in (
        "pull_request_target:", "workflow_run:", "repository_dispatch:",
        "continue-on-error: true", "set +e", "|| true", "runs-on: self-hosted",
        "curl | bash", "curl | sh", "npm audit --force", "pip-audit --ignore-vuln",
    ):
        if forbidden in contents:
            raise SecurityGateError(f"{path.name}: forbidden CI bypass {forbidden}")
    if re.search(
        r"(?m)^\s+(?:contents|actions|id-token|packages|statuses|pull-requests):\s*write\s*$",
        contents,
    ):
        raise SecurityGateError(f"{path.name}: CI token privileges exceed read-only")
    if "security-events: write" in contents and path.name != "security.yml":
        raise SecurityGateError(f"{path.name}: unexpected code scanning write permission")
    actions = re.findall(r"(?m)^\s*-\s*uses:\s*(\S+)", contents)
    if not actions:
        raise SecurityGateError(f"{path.name}: no pinned actions")
    for action in actions:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}", action):
            raise SecurityGateError(f"{path.name}: action not pinned to a full commit")
    if path.name == "security.yml":
        required = ("pip-audit", "npm audit", "codeql-action/init", "codeql-action/analyze",
                    "ci_security_gate.py junit", "ci_security_gate.py secrets")
        for item in required:
            if item not in contents:
                raise SecurityGateError(f"security.yml: missing {item}")
        for module in ADVERSARIAL:
            if f"tests/{module}.py" not in contents:
                raise SecurityGateError(f"security.yml: adversarial tests missing {module}")


def check_workflows(root: Path = ROOT) -> None:
    directory = root / ".github" / "workflows"
    for required in REQUIRED_WORKFLOWS:
        if not (directory / required).is_file():
            raise SecurityGateError(f"missing security-required workflow: {required}")
    if not (root / "backend/requirements.lock").is_file():
        raise SecurityGateError("missing SHA-256-hashed Python 3.12 lock")
    backend = (directory / "backend.yml").read_text(encoding="utf-8")
    if backend.count("python -m pip install --require-hashes -r requirements.lock") < 2:
        raise SecurityGateError("backend CI no longer uses hashed Python dependencies")
    security = (directory / "security.yml").read_text(encoding="utf-8")
    for item in (
        "python -m pip install --require-hashes -r requirements.lock",
        "pip-audit --strict --disable-pip -r backend/requirements.lock",
        "scripts/supply_chain.py generate",
        "scripts/supply_chain.py verify",
        "source-dependency-sbom",
    ):
        if item not in security:
            raise SecurityGateError(f"required supply-chain gate missing: {item}")
    for project in ("frontend", "infra"):
        if not (root / project / "package-lock.json").is_file():
            raise SecurityGateError(f"missing committed, audited npm lock: {project}")
        source = (directory / f"{project}.yml").read_text(encoding="utf-8")
        if "npm ci --no-audit --no-fund" not in source:
            raise SecurityGateError(f"{project}: reproducible npm ci is mandatory")
    if "npm ci --ignore-scripts --no-audit --no-fund" not in (
        directory / "security.yml"
    ).read_text(encoding="utf-8"):
        raise SecurityGateError("npm security audit must use immutable lockfiles")
    workflows = sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    for path in workflows:
        check_workflow_source(path, path.read_text(encoding="utf-8"))


def verify_junit(
    path: Path, *, required_modules: tuple[str, ...] = ADVERSARIAL,
    minimum_cases: int = 75,
) -> None:
    try:
        report = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise SecurityGateError("missing or invalid adversarial JUnit evidence") from exc
    cases = report.findall(".//testcase")
    if not cases and report.tag == "testcase":
        cases = [report]
    if len(cases) < minimum_cases:
        raise SecurityGateError(
            f"adversarial regression coverage collapsed: {len(cases)} < {minimum_cases}"
        )
    if any(
        case.find("failure") is not None
        or case.find("error") is not None
        or case.find("skipped") is not None
        for case in cases
    ):
        raise SecurityGateError("adversarial test failed, errored or was skipped")
    classes = {case.get("classname", "") for case in cases}
    missing = [
        module for module in required_modules
        if not any(name == module or name.endswith("." + module) for name in classes)
    ]
    if missing:
        raise SecurityGateError("adversarial modules absent from JUnit: " + ", ".join(missing))


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "policy":
        check_workflows()
    elif len(sys.argv) == 2 and sys.argv[1] == "secrets":
        scan_tracked_secrets()
    elif len(sys.argv) == 3 and sys.argv[1] == "junit":
        verify_junit(Path(sys.argv[2]))
    else:
        print("Usage: python scripts/ci_security_gate.py policy|secrets|junit <report.xml>", file=sys.stderr)
        return 2
    print("Security gate passed: " + sys.argv[1])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SecurityGateError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
