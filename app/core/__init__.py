"""Core app configuration and database."""

from app.core.config import get_settings, settings
from app.core.database import get_db

__all__ = ["get_settings", "settings", "get_db"]
