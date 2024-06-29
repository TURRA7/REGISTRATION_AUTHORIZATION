import asyncio
import uvicorn

import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from sentry_sdk.integrations.fastapi import FastApiIntegration

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from api.api import app_auth, app_reg
from config import SECRET_KEY, SENTRY_DNS
from database.FDataBase import create_tables, delete_tables
from redis_tools.redis_tools import lifespan


sentry_sdk.init(
    dsn=SENTRY_DNS,
    integrations=[
        FastApiIntegration(),
    ],
    traces_sample_rate=1.0,
)


app = FastAPI(lifespan=lifespan)

app.include_router(app_reg)
app.include_router(app_auth)


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   max_age=360)
app.add_middleware(SentryAsgiMiddleware)


async def main():
    await create_tables()

if __name__ == "__main__":
    asyncio.run(main())

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
