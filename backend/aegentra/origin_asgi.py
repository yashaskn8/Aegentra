"""Minimal ASGI protected static-origin reference gateway.

No alternative assets, route fallback, conditional response, compression,
partial range or streaming before digest checks. The origin operator must
enforce exclusive routing and live TLS termination independently.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from aegentra.protected_gateway import ProtectedAdmission


class ProtectedOriginASGI:
    def __init__(self, admission: ProtectedAdmission):
        self.admission = admission

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("only the enrolled HTTP origin is supported")
        headers: dict[str, str] = {}
        invalid = False
        for raw_name, raw_value in scope.get("headers", ()):
            try:
                name = raw_name.decode("ascii").lower()
                value = raw_value.decode("ascii")
            except UnicodeDecodeError:
                invalid = True
                break
            if name in headers:
                invalid = True
                break
            headers[name] = value

        path = scope.get("path", "")
        raw_path = scope.get("raw_path", b"")
        try:
            path_bytes = path.encode("ascii") if isinstance(path, str) else None
        except UnicodeEncodeError:
            path_bytes = None
        if (
            scope.get("scheme") != "https"
            or invalid or not isinstance(path, str)
            or raw_path != path_bytes
            or scope.get("query_string") not in (b"", None)
            or headers.get("content-length") not in (None, "0")
            or "transfer-encoding" in headers
        ):
            await self._deny(send)
            return

        try:
            result = await self.admission.admit(
                method=scope.get("method", ""),
                host=headers.get("host", ""),
                path=path, request_headers=headers,
            )
        except Exception:
            # Never surface fault details or partial candidate bytes on failure.
            await self._deny(send)
            return

        # No other work and no awaited dependency calls between the final
        # signed veto and the first response-start action.
        wire_headers = [
            (name.encode("ascii"), value.encode("ascii"))
            for name, value in result.headers.items()
        ]
        await send({
            "type": "http.response.start", "status": 200,
            "headers": wire_headers,
        })
        try:
            async with asyncio.timeout(0.5):
                await send({
                    "type": "http.response.body", "body": result.body,
                    "more_body": False,
                })
        except TimeoutError:
            # Cannot un-send any bytes; host must abort the connection and
            # report an incomplete response to its independent observer.
            return

    async def _deny(self, send: Callable) -> None:
        body = b"protected resource unavailable"
        await send({
            "type": "http.response.start", "status": 503,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store, max-age=0"),
                (b"x-content-type-options", b"nosniff"),
            ],
        })
        await send({
            "type": "http.response.body", "body": body, "more_body": False,
        })
