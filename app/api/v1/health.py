"""Health check endpoint with optional database connectivity check."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import check_db_connected, get_db
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)) -> HealthResponse:
    """
    Return service health status and database connectivity.
    Used by load balancers and monitoring.
    """
    db_status = "connected" if check_db_connected(db) else "disconnected"

    return HealthResponse(
        status="ok",
        environment=settings.APP_ENV,
        database=db_status,
    )
