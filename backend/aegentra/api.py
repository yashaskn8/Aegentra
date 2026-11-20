"""Public API entry point. No unauthenticated scan or release endpoints."""
from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from aegentra.oidc import OidcClient, OidcSettings
from pydantic import BaseModel

from aegentra.intake import IntakeManifest


class ShadowValidation(BaseModel):
    status: str
    parts: int
    total_bytes: int
    shadow_fingerprint: str


def create_app(
    *,
    enable_local_shadow_preview: bool = False,
    settings: OidcSettings | None = None,
    sessions: async_sessionmaker[AsyncSession] | None = None,
    provider: OidcClient | None = None,
    lifespan=None,
) -> FastAPI:
    app = FastAPI(
        title="Aegentra",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
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

    if any(value is not None for value in (settings, sessions, provider)):
        if settings is None or sessions is None or provider is None:
            raise ValueError("auth settings, database sessions and OIDC provider must be configured together")
        from aegentra.auth_routes import enable_auth
        enable_auth(app, settings=settings, sessions=sessions, provider=provider)

    return app


app = create_app()
