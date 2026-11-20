"""Explicit deployment entry point. Missing OIDC/DB config fails startup."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.api import create_app
from aegentra.oidc import OidcClient, OidcSettings
from aegentra.persistence import make_engine


def create_configured_app() -> FastAPI:
    settings = OidcSettings.from_env()
    if settings is None:
        raise RuntimeError("AEGENTRA_OIDC_ISSUER must be configured for authenticated mode")
    url = os.environ.get("AEGENTRA_DATABASE_URL")
    if not url:
        raise RuntimeError("AEGENTRA_DATABASE_URL must be configured")
    engine = make_engine(url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await engine.dispose()

    return create_app(
        settings=settings,
        sessions=async_sessionmaker(engine, expire_on_commit=False),
        provider=OidcClient(settings),
        lifespan=lifespan,
    )
