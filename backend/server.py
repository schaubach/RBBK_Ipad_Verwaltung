"""iPad Management System – FastAPI entry point.

This module is intentionally thin: it wires together the app, middleware,
CORS, logging and the shared `api_router` populated by the modules under
`routes/`. All business logic lives in `routes/`, all helpers in `core/`,
all Pydantic models in `models/`.
"""

import logging
import os

from core.config import client, limiter
from core.middleware import SecurityHeadersMiddleware
from core.router import api_router
from fastapi import FastAPI

# Importing the route modules registers their endpoints onto `api_router`.
# Keep the imports here even though some IDEs flag them as unused.
from routes import (  # noqa: F401
    admin_users,
    assignments,
    auth,
    contract_generation,
    contracts,
    data_protection,
    imports_exports,
    ipads,
    settings,
    students,
)
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# FastAPI app setup
# ---------------------------------------------------------------------------
app = FastAPI(title="iPad Management System")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register all routes (single router shared across modules)
app.include_router(api_router)

# Security headers + CORS
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,https://vertraege-lab.preview.emergentagent.com",
    ).split(","),
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
