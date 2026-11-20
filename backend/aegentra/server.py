"""Explicit deployment entry point. Missing OIDC/DB config fails startup."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegentra.api import create_app
from aegentra.oidc import OidcClient, OidcSettings
from aegentra.persistence import make_engine
from aegentra.staging_signer import StagingSigner


def create_configured_app() -> FastAPI:
    settings = OidcSettings.from_env()
    if settings is None:
        raise RuntimeError("AEGENTRA_OIDC_ISSUER must be configured for authenticated mode")
    url = os.environ.get("AEGENTRA_DATABASE_URL")
    if not url:
        raise RuntimeError("AEGENTRA_DATABASE_URL must be configured")
    engine = make_engine(url)
    staging_signer = None
    bucket = os.getenv("AEGENTRA_STAGING_BUCKET")
    if bucket:
        region = os.getenv("AEGENTRA_STAGING_REGION")
        if not region:
            raise RuntimeError("AEGENTRA_STAGING_REGION is required with staging bucket")
        import boto3

        staging_signer = StagingSigner(
            client=boto3.client("s3", region_name=region), bucket=bucket
        )

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
        staging_signer=staging_signer,
        lifespan=lifespan,
    )
