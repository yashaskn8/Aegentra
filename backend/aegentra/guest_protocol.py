"""Versioned bounded raw frame protocol for an offline native analysis guest.

Guest input is an exact original-byte payload; output is advisory JSON only.
No filesystem mount, executable import, network fetch or code execution occurs.
The bridge and guest must run on independently scoped native hosts.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Literal
from uuid import UUID

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegentra.content_manifest import ManifestError, strict_json
from aegentra.static_analysis import MAX_FINDINGS, MAX_JS_BYTES, MAX_NODES

INPUT_MAGIC = b"AEGI"
OUTPUT_MAGIC = b"AEGO"
MAX_HEADER = 4_096
MAX_RESULT = 1024 * 1024
_HEX = r"^[0-9a-f]{64}$"


class FrameError(ValueError):
    pass


class GuestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.guest.input.v1"]
    org_id: UUID
    job_id: UUID
    generation: int = Field(strict=True, ge=1)
    nonce: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")
    toolchain_sha256: str = Field(pattern=_HEX)
    source_sha256: str = Field(pattern=_HEX)
    byte_length: int = Field(strict=True, ge=1, le=MAX_JS_BYTES)


class GuestFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: Literal["DIRECT_CALL_REVIEW"]
    symbol: Literal["eval", "Function", "fetch", "WebSocket"]
    start_byte: int = Field(strict=True, ge=0)
    end_byte_exclusive: int = Field(strict=True, gt=0)
    interpretation: Literal["UNRESOLVED_BINDING"]


class GuestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["aegentra.guest.result.v1"]
    org_id: UUID
    job_id: UUID
    generation: int = Field(strict=True, ge=1)
    nonce: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")
    toolchain_sha256: str = Field(pattern=_HEX)
    source_sha256: str = Field(pattern=_HEX)
    byte_length: int = Field(strict=True, ge=1, le=MAX_JS_BYTES)
    status: Literal["COMPLETE", "INCOMPLETE"]
    coverage: Literal["VERIFIED", "UNKNOWN", "UNSUPPORTED"]
    node_count: int = Field(strict=True, ge=0, le=MAX_NODES + 1)
    reason: Literal[
        "BYTE_LIMIT_EXCEEDED", "NUL_BYTE", "SYNTAX_ERROR_OR_RECOVERY",
        "NODE_LIMIT_EXCEEDED", "DEPTH_LIMIT_EXCEEDED", "FINDING_LIMIT_EXCEEDED"
    ] | None
    findings: tuple[GuestFinding, ...] = Field(max_length=MAX_FINDINGS)

    @model_validator(mode="after")
    def coverage_consistency(self) -> "GuestResponse":
        if self.status == "COMPLETE":
            if self.coverage != "VERIFIED" or self.reason is not None:
                raise ValueError("complete result requires verified parser coverage")
        elif self.coverage == "VERIFIED" or self.reason is None or self.findings:
            raise ValueError("incomplete result must declare a gap and no findings")
        if any(item.end_byte_exclusive <= item.start_byte for item in self.findings):
            raise ValueError("invalid byte span")
        return self


def _json(model: BaseModel) -> bytes:
    return rfc8785.dumps(model.model_dump(mode="json"))


def _decode_header(data: bytes, *, limit: int) -> dict:
    if len(data) > limit:
        raise FrameError("header exceeds byte limit")
    try:
        parsed = strict_json(data, max_bytes=limit)
    except ManifestError as exc:
        raise FrameError("invalid framed JSON") from exc
    if not isinstance(parsed, dict) or rfc8785.dumps(parsed) != data:
        raise FrameError("noncanonical frame")
    return parsed


def encode_input(request: GuestRequest, source: bytes) -> bytes:
    if not isinstance(source, bytes) or len(source) != request.byte_length:
        raise FrameError("source length differs from request")
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), request.source_sha256):
        raise FrameError("source digest differs from request")
    header = _json(request)
    if len(header) > MAX_HEADER:
        raise FrameError("input header too large")
    return INPUT_MAGIC + struct.pack(">I", len(header)) + header + source


def decode_input(frame: bytes) -> tuple[GuestRequest, bytes]:
    if len(frame) < 8 or len(frame) > 8 + MAX_HEADER + MAX_JS_BYTES:
        raise FrameError("input frame outside bounds")
    if frame[:4] != INPUT_MAGIC:
        raise FrameError("wrong input domain")
    header_length = struct.unpack(">I", frame[4:8])[0]
    if header_length == 0 or header_length > MAX_HEADER:
        raise FrameError("invalid input header length")
    end = 8 + header_length
    try:
        request = GuestRequest.model_validate(_decode_header(frame[8:end], limit=MAX_HEADER))
    except ValueError as exc:
        raise FrameError("invalid input request") from exc
    source = frame[end:]
    if len(source) != request.byte_length:
        raise FrameError("input payload length mismatch")
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), request.source_sha256):
        raise FrameError("input payload digest mismatch")
    return request, source


def encode_output(response: GuestResponse) -> bytes:
    body = _json(response)
    if len(body) > MAX_RESULT:
        raise FrameError("guest output exceeds 1 MiB")
    return OUTPUT_MAGIC + struct.pack(">I", len(body)) + body


def decode_output(frame: bytes) -> GuestResponse:
    if len(frame) < 9 or len(frame) > 8 + MAX_RESULT or frame[:4] != OUTPUT_MAGIC:
        raise FrameError("invalid result framing")
    size = struct.unpack(">I", frame[4:8])[0]
    if size == 0 or size > MAX_RESULT or size != len(frame) - 8:
        raise FrameError("invalid result length")
    try:
        return GuestResponse.model_validate(_decode_header(frame[8:], limit=MAX_RESULT))
    except ValueError as exc:
        raise FrameError("invalid guest result") from exc
