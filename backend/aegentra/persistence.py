"""Database sessions for already-authenticated, server-derived organization IDs.

The application must never obtain org_id from a client-supplied request field.
RLS is defense in depth: database roles, per-object authorization, and explicit
org_id predicates remain necessary.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def make_engine(url: str) -> AsyncEngine:
    if not url.startswith("postgresql+asyncpg://"):
        raise ValueError("Aegentra requires a PostgreSQL asyncpg database URL")
    return create_async_engine(url, pool_pre_ping=True)


@asynccontextmanager
async def organization_session(
    sessions: async_sessionmaker[AsyncSession], org_id: UUID
) -> AsyncIterator[AsyncSession]:
    """Run one unit of work in a transaction scoped to an authorized org.

    PostgreSQL set_config(..., true) is transaction-local. A pooled connection
    cannot carry this setting into the next transaction.
    """
    if not isinstance(org_id, UUID):
        raise TypeError("org_id must be a verified UUID")

    async with sessions() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('aegentra.org_id', :org_id, true)"),
                {"org_id": str(org_id)},
            )
            yield session
