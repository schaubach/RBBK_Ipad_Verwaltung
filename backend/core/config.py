"""Central configuration: env, MongoDB, JWT secret, rate limiter, password context."""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi.security import HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address

ROOT_DIR = Path(__file__).parent.parent
load_dotenv(ROOT_DIR / ".env")

# MongoDB
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client["iPadDatabase"]

# Auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    print("WARNING: No secure SECRET_KEY found. Generating random key for this session.")
    SECRET_KEY = secrets.token_urlsafe(64)

# Business config
MAX_IPADS_PER_STUDENT = int(os.environ.get("MAX_IPADS_PER_STUDENT", 3))
MAX_CONTRACTS_PER_STUDENT = int(os.environ.get("MAX_CONTRACTS_PER_STUDENT", 3))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
