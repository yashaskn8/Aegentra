"""Fixed SA-1.1 browser entry + one digest-addressed classic JavaScript.

No customer-supplied HTML, template variable, dependency loader or inline
script. The browser, not Aegentra, may execute an independently approved JS
artifact. A static digest is an identity check, never a safety assessment.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

import rfc8785

MAX_SCRIPT_BYTES = 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])?\Z")
_ENTRY = "/index.html"
_TEMPLATE = "aegentra-fixed-entry-v1"

# Hash-only external classic script with mandatory matching SRI. No 'self',
# wildcard, data:, blob: or dynamic/inline script entitlement.
_CSP_PREFIX = (
    "default-src 'none'; "
    "worker-src 'none'; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; "
    "img-src 'none'; style-src 'none'; frame-src 'none'; "
    "script-src-attr 'none'; "
)


class UnsupportedDelivery(ValueError):
    pass


@dataclass(frozen=True)
class FixedStaticProfile:
    host: str
    script_sha256: str
    script_length: int
    entry_path: str = _ENTRY
    template_version: str = _TEMPLATE

    def __post_init__(self) -> None:
        if (
            not isinstance(self.host, str) or not _HOST.fullmatch(self.host)
            or not isinstance(self.script_sha256, str)
            or not _HEX.fullmatch(self.script_sha256)
            or type(self.script_length) is not int
            or not 0 < self.script_length <= MAX_SCRIPT_BYTES
            or self.entry_path != _ENTRY
            or self.template_version != _TEMPLATE
        ):
            raise UnsupportedDelivery("not the qualified fixed static delivery profile")

    @property
    def script_path(self) -> str:
        return "/app-" + self.script_sha256 + ".js"

    @property
    def sri(self) -> str:
        digest = bytes.fromhex(self.script_sha256)
        return "sha256-" + base64.b64encode(digest).decode("ascii")

    @property
    def csp(self) -> str:
        allowed = "'" + self.sri + "'"
        return (
            _CSP_PREFIX + "script-src " + allowed + "; "
            "script-src-elem " + allowed
        )

    def generated_html(self) -> bytes:
        # Only format values proven by strict ASCII lowercase hex grammar.
        markup = (
            '<!doctype html>\n<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            '<title>Protected release</title>\n'
            '</head>\n<body>\n'
            '<script src="' + self.script_path + '" integrity="' + self.sri
            + '" crossorigin="anonymous"></script>\n'
            '</body>\n</html>\n'
        )
        return markup.encode("ascii")

    def check_representation(self, *, path: str, content: bytes) -> str:
        """Return immutable content type, reject every non-profile representation."""
        if not isinstance(content, bytes):
            raise UnsupportedDelivery("original representation must be bytes")
        if path == self.entry_path:
            if content != self.generated_html():
                raise UnsupportedDelivery("HTML is not the reviewed fixed template")
            return "text/html; charset=utf-8"
        if path == self.script_path:
            if (
                len(content) != self.script_length
                or hashlib.sha256(content).hexdigest() != self.script_sha256
            ):
                raise UnsupportedDelivery("script bytes do not match pinned digest")
            return "text/javascript; charset=utf-8"
        raise UnsupportedDelivery("request path is not in the two-resource profile")

    def headers(self, *, path: str, content: bytes) -> dict[str, str]:
        content_type = self.check_representation(path=path, content=content)
        return {
            "cache-control": "no-store, max-age=0",
            "content-type": content_type,
            "content-length": str(len(content)),
            "content-security-policy": self.csp,
            "x-content-type-options": "nosniff",
            "cross-origin-resource-policy": "same-origin",
        }

    def manifest(self) -> dict[str, object]:
        """Canonical two-resource identity; not itself a signed release."""
        html = self.generated_html()
        return {
            "kind": "aegentra.fixed-delivery.v1",
            "template_version": self.template_version,
            "host": self.host,
            "entry_path": self.entry_path,
            "entry_sha256": hashlib.sha256(html).hexdigest(),
            "entry_length": len(html),
            "script_path": self.script_path,
            "script_sha256": self.script_sha256,
            "script_length": self.script_length,
            "sri": self.sri,
            "csp": self.csp,
        }

    def manifest_sha256(self) -> str:
        return hashlib.sha256(
            b"aegentra.fixed-delivery.manifest.v1\x00"
            + rfc8785.dumps(self.manifest())
        ).hexdigest()
