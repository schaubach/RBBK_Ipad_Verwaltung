"""Shared APIRouter singleton. All route modules decorate against this single instance."""
from fastapi import APIRouter

api_router = APIRouter(prefix="/api")
