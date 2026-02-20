"""
Create a user (e.g. first admin). Run from project root:
  python -m app.scripts.create_user USERNAME PASSWORD [role]
Example:
  python -m app.scripts.create_user admin your-secure-password admin
"""
import argparse
import sys

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.user import User


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Helion user (no registration UI).")
    parser.add_argument("username", help="Username (1-255 chars)")
    parser.add_argument("password", help="Password (8-128 chars)")
    parser.add_argument("role", nargs="?", default="user", choices=["user", "admin"])
    args = parser.parse_args()

    username = args.username.strip()
    if not username or len(username) > 255:
        print("Invalid username length.", file=sys.stderr)
        return 1
    if len(args.password) < 8 or len(args.password) > 128:
        print("Password must be 8-128 characters.", file=sys.stderr)
        return 1

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"User '{username}' already exists.", file=sys.stderr)
            return 1
        user = User(
            username=username,
            password_hash=hash_password(args.password),
            role=args.role,
        )
        db.add(user)
        db.commit()
        print(f"Created user '{username}' with role '{args.role}'.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
