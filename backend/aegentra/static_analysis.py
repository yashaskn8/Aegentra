"""Bounded JavaScript syntax evidence for a future isolated analysis guest.

This parser MUST NOT be exposed to untrusted submissions in the API process.
It is permitted for inert fixtures until the SA-1.1 offline guest is qualified.
A syntax report is an investigative lead, never deployment authorization.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import tree_sitter_javascript
from tree_sitter import Language, Parser

MAX_JS_BYTES = 1 * 1024 * 1024
MAX_NODES = 2_000
MAX_DEPTH = 128
MAX_FINDINGS = 2_000

# Direct syntax only: a local binding could shadow any of these names.
# The label intentionally does not assert the runtime target of a call.
REVIEW_CALLS = frozenset({"eval", "Function", "fetch", "WebSocket"})


@dataclass(frozen=True)
class SyntaxFinding:
    rule_id: str
    symbol: str
    start_byte: int
    end_byte_exclusive: int
    interpretation: str = "UNRESOLVED_BINDING"


@dataclass(frozen=True)
class StaticReport:
    content_sha256: str
    status: str
    coverage: str
    node_count: int
    findings: tuple[SyntaxFinding, ...]
    reason: str | None = None


def _report(data: bytes, status: str, coverage: str, count: int,
            findings: list[SyntaxFinding], reason: str | None = None) -> StaticReport:
    return StaticReport(
        content_sha256=hashlib.sha256(data).hexdigest(),
        status=status,
        coverage=coverage,
        node_count=count,
        findings=tuple(findings),
        reason=reason,
    )


def inspect_inert_javascript(data: bytes) -> StaticReport:
    """Parse, never evaluate, import, build or execute supplied bytes.

    No timeout is claimed here: the production guest supervisor must impose
    its own deadline and resource limits before hostile inputs are allowed.
    """
    if not isinstance(data, bytes):
        raise TypeError("original JavaScript bytes are required")
    if len(data) > MAX_JS_BYTES:
        return _report(data, "INCOMPLETE", "UNSUPPORTED", 0, [],
                       "BYTE_LIMIT_EXCEEDED")
    if b"\x00" in data:
        return _report(data, "INCOMPLETE", "UNSUPPORTED", 0, [],
                       "NUL_BYTE")

    parser = Parser(Language(tree_sitter_javascript.language()))
    tree = parser.parse(data)
    if tree.root_node.has_error:
        return _report(data, "INCOMPLETE", "UNKNOWN", 0, [],
                       "SYNTAX_ERROR_OR_RECOVERY")

    nodes = 0
    findings: list[SyntaxFinding] = []
    stack = [(tree.root_node, 0)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            return _report(data, "INCOMPLETE", "UNSUPPORTED", nodes, [],
                           "NODE_LIMIT_EXCEEDED")
        if depth > MAX_DEPTH:
            return _report(data, "INCOMPLETE", "UNSUPPORTED", nodes, [],
                           "DEPTH_LIMIT_EXCEEDED")

        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None and callee.type == "identifier":
                symbol = data[callee.start_byte:callee.end_byte].decode("ascii", "ignore")
                if symbol in REVIEW_CALLS:
                    findings.append(SyntaxFinding(
                        rule_id="DIRECT_CALL_REVIEW",
                        symbol=symbol,
                        start_byte=node.start_byte,
                        end_byte_exclusive=node.end_byte,
                    ))
        # Traverse only grammar nodes, not comments or string contents as code.
        for child in reversed(node.children):
            stack.append((child, depth + 1))

        if len(findings) > MAX_FINDINGS:
            return _report(data, "INCOMPLETE", "UNSUPPORTED", nodes, [],
                           "FINDING_LIMIT_EXCEEDED")

    return _report(data, "COMPLETE", "VERIFIED", nodes, findings)


def report_for_release(report: StaticReport) -> str:
    """Never return an ALLOW/SAFE decision from the advisory analyzer."""
    if report.coverage != "VERIFIED":
        return "REQUIRED_ANALYSIS_INCOMPLETE"
    return "REQUIRES_INDEPENDENT_REVIEW"
