"""API v1 routes."""

from fastapi import APIRouter

from app.api.v1 import clusters, health, upload

router = APIRouter()
router.include_router(health.router, prefix="/health", tags=["health"])
router.include_router(upload.router, prefix="/upload", tags=["upload"])
router.include_router(clusters.router, prefix="/clusters", tags=["clusters"])
