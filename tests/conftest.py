from httpx import AsyncClient
import pytest
import pytest_asyncio
from main import app


@pytest.fixture(scope="module")
async def async_test_client():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client
