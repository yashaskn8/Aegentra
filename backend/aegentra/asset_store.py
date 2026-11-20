"""Internal tenant-scoped asset operations; not exposed via HTTP before OIDC."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegentra.db import Asset


async def list_assets(session: AsyncSession, *, org_id: UUID) -> list[Asset]:
    # Explicit SQL scope complements PostgreSQL RLS.
    result = await session.scalars(
        select(Asset).where(Asset.org_id == org_id).order_by(Asset.slug, Asset.id)
    )
    return list(result.all())


async def create_asset(
    session: AsyncSession,
    *,
    org_id: UUID,
    slug: str,
    criticality: str,
) -> Asset:
    asset = Asset(org_id=org_id, slug=slug, criticality=criticality)
    session.add(asset)
    await session.flush()
    return asset
