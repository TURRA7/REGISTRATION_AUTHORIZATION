from httpx import AsyncClient
import pytest_asyncio
from main import app


@pytest_asyncio.fixture(scope="module")
async def async_test_client():
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
