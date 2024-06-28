import asyncio
from httpx import AsyncClient
import pytest_asyncio
from config import PG_DB, PG_HOST, PG_PASS, PG_PORT, PG_USER, TEST_PG_DB
from database.FDataBase import Base
from main import app

from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession)
from sqlalchemy.orm import sessionmaker



@pytest_asyncio.fixture(scope="module")
async def async_test_client():
    async with AsyncClient(app=app,
                           base_url="http://127.0.0.1:8000/") as client:
        test_engine = create_async_engine(
            f"postgresql+asyncpg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{TEST_PG_DB}",
            echo=True)

        test_async_session = sessionmaker(
            test_engine, class_=AsyncSession, expire_on_commit=False
        )

        async def test_create_tables() -> None:
            """Функция создания таблиц."""
            async with test_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        async def test_delete_tables() -> None:
            """Функция удаления таблиц."""
            async with test_engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(test_create_tables())
        yield client
        loop.run_until_complete(test_create_tables())


