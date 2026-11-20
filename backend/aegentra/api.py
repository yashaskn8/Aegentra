"""Public API entry point. No unauthenticated scan or release endpoints."""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from aegentra.intake import IntakeManifest


class ShadowValidation(BaseModel):
    status: str
    parts: int
    total_bytes: int
    shadow_fingerprint: str


def create_app(*, enable_local_shadow_preview: bool = False) -> FastAPI:
    app = FastAPI(
        title="Aegentra",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/v1/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "live", "mode": "shadow"}

    # Explicitly opt-in for local tests. Never exposed by the deployable app.
    if enable_local_shadow_preview:

        @app.post("/v1/local/validate-manifest", response_model=ShadowValidation)
        def validate_manifest(manifest: IntakeManifest) -> ShadowValidation:
            return ShadowValidation(
                status="VALID_METADATA_ONLY",
                parts=len(manifest.parts),
                total_bytes=manifest.total_bytes,
                shadow_fingerprint=manifest.shadow_fingerprint(),
            )

    return app


app = create_app()
