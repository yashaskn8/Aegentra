"""Closed response schemas for the scoped case workspace."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_serializer, model_validator


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Revision = Annotated[int, Field(ge=1, le=2147483647, strict=True)]


class CaseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    asset_id: UUID
    title: str
    status: Literal["OPEN", "TRIAGED", "CONTAINMENT_REQUESTED", "CONTAINED", "RECOVERING", "CLOSED"]
    revision: Revision


class CaseList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CaseSummary]
    truncated: bool


class EvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    kind: str
    sha256: Digest
    case_id: UUID


class EvidenceLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: UUID
    evidence_id: UUID


class IncidentTransition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    asset_id: UUID
    status: Literal["TRIAGED", "CONTAINMENT_REQUESTED"]
    revision: Revision
    enforcement_effect: Literal["NONE"]


class EvidencePageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    kind: str
    sha256: Digest
    linked_at: AwareDatetime

    @field_serializer("linked_at", when_used="json")
    def serialize_linked_at(self, value: datetime) -> str:
        # Preserve the existing timestamp spelling in the evidence API.
        return value.isoformat()


class EvidencePage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidencePageItem]
    next_cursor: str | None


class CaseTimelineKind(StrEnum):
    CASE_CREATED = "CASE_CREATED"
    CASE_EVIDENCE_LINKED = "CASE_EVIDENCE_LINKED"
    INCIDENT_TRIAGED = "INCIDENT_TRIAGED"
    INCIDENT_CONTAINMENT_REQUESTED = "INCIDENT_CONTAINMENT_REQUESTED"
    INCIDENT_CONTAINMENT_VERIFIED = "INCIDENT_CONTAINMENT_VERIFIED"


class CaseTimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: Digest
    occurred_at: AwareDatetime
    kind: CaseTimelineKind
    evidence_id: UUID | None
    revision: Revision | None

    @model_validator(mode="after")
    def validate_details(self) -> CaseTimelineEvent:
        if (self.evidence_id is not None) != (self.kind is CaseTimelineKind.CASE_EVIDENCE_LINKED):
            raise ValueError("evidence identity is required only for a link event")
        if (self.revision is not None) != self.kind.startswith("INCIDENT_"):
            raise ValueError("case revision is required only for an incident event")
        return self


class CaseTimelinePage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    items: list[CaseTimelineEvent]
    next_cursor: str | None
