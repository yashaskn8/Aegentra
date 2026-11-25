"""Canonical pre-upload content identity; not an approval or a signed release.

RFC 8785 canonicalization is applied to a closed schema. No uploaded bytes,
source maps, external URLs or package code are loaded by this module.
"""
from __future__ import annotations

import hashlib
from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegentra.bounded_json import ManifestError as ManifestError
from aegentra.bounded_json import strict_json as strict_json
from aegentra.intake import ArtifactPart, MAX_PARTS, MAX_TOTAL_BYTES


class ContentPart(ArtifactPart):
    media_type: Literal["application/javascript", "application/json", "text/plain"]


class DependencyEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source: str
    target: str


class ContentManifest(BaseModel):
    """Closed immutable manifest for exact known paths; no implicit dependency fetch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["aegentra.content.v1"]
    parts: tuple[ContentPart, ...] = Field(min_length=1, max_length=MAX_PARTS)
    edges: tuple[DependencyEdge, ...] = Field(max_length=2_000)

    @model_validator(mode="after")
    def validate_graph(self) -> "ContentManifest":
        paths = [part.path for part in self.parts]
        if len(paths) != len(set(p.casefold() for p in paths)):
            raise ValueError("duplicate or ambiguous content paths")
        if sum(part.byte_length for part in self.parts) > MAX_TOTAL_BYTES:
            raise ValueError("manifest exceeds total byte budget")
        known = set(paths)
        edges = [(edge.source, edge.target) for edge in self.edges]
        if len(edges) != len(set(edges)):
            raise ValueError("duplicate dependency edge")
        if any(src not in known or dst not in known for src, dst in edges):
            raise ValueError("dependency edge names undeclared part")
        return self

    def canonical_bytes(self) -> bytes:
        """RFC 8785 over a minimal fixed-key schema and deterministic arrays."""
        body = {
            "schema": self.schema_id,
            "parts": [
                {
                    "path": item.path,
                    "byte_length": item.byte_length,
                    "sha256": item.sha256,
                    "media_type": item.media_type,
                }
                for item in sorted(self.parts, key=lambda p: p.path)
            ],
            "edges": [
                {"source": item.source, "target": item.target}
                for item in sorted(self.edges, key=lambda e: (e.source, e.target))
            ],
        }
        return rfc8785.dumps(body)

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def parse_manifest_json(data: bytes) -> ContentManifest:
    return ContentManifest.model_validate(strict_json(data, max_bytes=100_000))
