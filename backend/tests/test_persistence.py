from uuid import uuid4

import pytest

from aegentra.persistence import make_engine, organization_session


def test_reject_non_postgresql_url() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        make_engine("sqlite+aiosqlite:///:memory:")


def test_reject_untrusted_scope_type_without_opening_connection() -> None:
    # The scope is always resolved from verified server-side identity.
    import asyncio

    async def check() -> None:
        engine = make_engine("postgresql+asyncpg://localhost:5432/test")
        try:
            from sqlalchemy.ext.asyncio import async_sessionmaker

            factory = async_sessionmaker(engine)
            with pytest.raises(TypeError, match="verified UUID"):
                async with organization_session(factory, str(uuid4())):  # type: ignore[arg-type]
                    pass
        finally:
            await engine.dispose()

    asyncio.run(check())
