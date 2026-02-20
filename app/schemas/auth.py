"""Request/response schemas for auth endpoints."""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credentials for login."""

    username: str = Field(..., min_length=1, max_length=255, description="Username")
    password: str = Field(..., min_length=8, max_length=128, description="Password")


class TokenResponse(BaseModel):
    """JWT access token returned after successful login."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


class CurrentUser(BaseModel):
    """Authenticated user (id, username, role) for dependency injection."""

    id: int
    username: str
    role: str

    class Config:
        from_attributes = True


class UserListItem(BaseModel):
    """User entry for admin list (no password)."""

    id: int
    username: str
    role: str

    class Config:
        from_attributes = True


class UsersListResponse(BaseModel):
    """Response for GET /users (admin only)."""

    users: list[UserListItem]
