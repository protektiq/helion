"""JWT login and auth dependencies (get_current_user, require_admin)."""

from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    USERNAME_MAX_LEN,
    USERNAME_MIN_LEN,
    PASSWORD_MAX_LEN,
    PASSWORD_MIN_LEN,
    create_access_token,
    decode_access_token,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import (
    CurrentUser,
    LoginRequest,
    TokenResponse,
    UserListItem,
    UsersListResponse,
)

router = APIRouter()
security = HTTPBearer(auto_error=False)


def _validate_username(username: str) -> None:
    if not (USERNAME_MIN_LEN <= len(username) <= USERNAME_MAX_LEN):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid username length.",
        )


def _validate_password(password: str) -> None:
    if not (PASSWORD_MIN_LEN <= len(password) <= PASSWORD_MAX_LEN):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid password length.",
        )


@router.post("", response_model=TokenResponse)
def login(
    body: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """
    Authenticate with username and password; returns a JWT access token.
    Include the token in the Authorization header as: Bearer <access_token>
    """
    _validate_username(body.username)
    _validate_password(body.password)

    user = db.query(User).filter(User.username == body.username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    token = create_access_token(sub=user.id, role=user.role)
    return TokenResponse(access_token=token, token_type="bearer")


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[Session, Depends(get_db)],
) -> CurrentUser:
    """Dependency: require valid Bearer JWT and return the current user. Raises 401 if missing or invalid."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(id=user.id, username=user.username, role=user.role)


def require_admin(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Dependency: require authenticated user with role 'admin'. Raises 403 for non-admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


@router.get("/users", response_model=UsersListResponse)
def list_users(
    _admin: Annotated[CurrentUser, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
) -> UsersListResponse:
    """List all users (admin only). Demonstrates RBAC."""
    users = db.query(User).order_by(User.id).all()
    return UsersListResponse(
        users=[UserListItem(id=u.id, username=u.username, role=u.role) for u in users]
    )
