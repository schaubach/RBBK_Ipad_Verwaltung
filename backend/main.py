"""Application entry point.

Assembles the FastAPI app from the modular routes/core/models package: importing ``routes``
registers every endpoint on the shared ``core.router.api_router`` (see routes/__init__.py),
which is then mounted here together with the same middleware/limiter/scheduler setup that used
to live inline in the old monolithic server.py.
"""

import asyncio
import logging
import os

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware

from core.config import client, limiter
from core.middleware import SecurityHeadersMiddleware
from core.router import api_router
import routes  # noqa: F401  (import side-effect: registers all endpoints on api_router)
from routes.backup import backup_scheduler_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="iPad Management System")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(api_router)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get(
        "CORS_ORIGINS", "http://localhost:3000,https://vertraege-lab.preview.emergentagent.com"
    ).split(","),
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
async def start_backup_scheduler():
    asyncio.create_task(backup_scheduler_loop())


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
