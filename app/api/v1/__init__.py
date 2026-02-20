"""API v1 routes."""

from fastapi import APIRouter

from app.api.v1 import clusters, exploitability, health, reasoning, upload

router = APIRouter()
router.include_router(health.router, prefix="/health", tags=["health"])
router.include_router(upload.router, prefix="/upload", tags=["upload"])
router.include_router(clusters.router, prefix="/clusters", tags=["clusters"])
router.include_router(reasoning.router, prefix="/reasoning", tags=["reasoning"])
router.include_router(exploitability.router, prefix="/exploitability", tags=["exploitability"])
