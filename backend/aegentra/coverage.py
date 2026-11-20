"""Explicit scan coverage: completion does not establish that code is safe."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CoverageState(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_REQUIRED = "NOT_REQUIRED"


class CoverageCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1, max_length=64)
    required: bool
    state: CoverageState

    @model_validator(mode="after")
    def check_required(self) -> "CoverageCheck":
        if self.required and self.state is CoverageState.NOT_REQUIRED:
            raise ValueError("required checks cannot be NOT_REQUIRED")
        return self


class CoverageAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: str
    gaps: tuple[str, ...]


def assess_coverage(checks: tuple[CoverageCheck, ...]) -> CoverageAssessment:
    if not checks:
        return CoverageAssessment(status="INCOMPLETE", gaps=("NO_CHECKS",))
    gaps = tuple(
        check.name
        for check in checks
        if check.required and check.state is not CoverageState.VERIFIED
    )
    return CoverageAssessment(
        status="INCOMPLETE" if gaps else "REVIEWABLE",
        gaps=gaps,
    )
