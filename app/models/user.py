"""ORM model for application users (auth and RBAC)."""

from sqlalchemy import Column, Integer, String

from app.models.base import Base


class User(Base):
    """
    User account for JWT authentication and role-based access control.

    role: 'admin' or 'user'
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="user")
