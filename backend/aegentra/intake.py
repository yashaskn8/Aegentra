"""Strict, side-effect-free validation of declared artifact metadata.

This module does not accept file bytes, create trusted baselines, or authorize releases.
"""
from __future__ import annotations

import hashlib
import json
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MIB = 1024 * 1024
MAX_PARTS = 64
MAX_PART_BYTES = 10 * MIB
MAX_TOTAL_BYTES = 25 * MIB
_PATH = re.compile(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*\Z")


class ArtifactPart(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    path: str
    byte_length: int = Field(ge=1, le=MAX_PART_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def safe_path(cls, path: str) -> str:
        if len(path) > 128 or not _PATH.fullmatch(path):
            raise ValueError("path must be a short relative ASCII path")
        if any(segment in {".", ".."} for segment in path.split("/")):
            raise ValueError("dot segments are not allowed")
        return path


class IntakeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    parts: tuple[ArtifactPart, ...] = Field(min_length=1, max_length=MAX_PARTS)

    @model_validator(mode="after")
    def validate_collection(self) -> "IntakeManifest":
        paths = [part.path.casefold() for part in self.parts]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate or case-ambiguous paths")
        if sum(part.byte_length for part in self.parts) > MAX_TOTAL_BYTES:
            raise ValueError("manifest exceeds total byte limit")
        return self

    @property
    def total_bytes(self) -> int:
        return sum(part.byte_length for part in self.parts)

    def shadow_fingerprint(self) -> str:
        """Stable preview identity, NOT a signed release/content manifest.

        Only integer, ASCII-string fields are included. Production authority will
        use its independently reviewed, versioned canonical manifest protocol.
        """
        parts = [
            {"path": p.path, "byte_length": p.byte_length, "sha256": p.sha256}
            for p in sorted(self.parts, key=lambda item: item.path)
        ]
        payload = json.dumps(
            {"schema": "aegentra.shadow-manifest.v1", "parts": parts},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(payload.encode("ascii")).hexdigest()
