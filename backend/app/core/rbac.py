"""
Role-Based Access Control (RBAC)
FastAPI dependencies for protecting routes by role.
"""
from typing import List
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.security import verify_token, hash_api_key
from app.database import get_db
from app.models.user import User, UserRole, APIKey

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ─── Role hierarchy ──────────────────────────────────────────────────────────
ROLE_HIERARCHY = {
    UserRole.ADMIN: 100,
    UserRole.SECURITY_ENGINEER: 80,
    UserRole.BUG_BOUNTY_HUNTER: 70,
    UserRole.DEVELOPER: 50,
    UserRole.VIEWER: 10,
}


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Authenticate via JWT bearer token OR API Key header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # ── Try JWT first ──────────────────────────────────────────
    if token:
        payload = verify_token(token)
        if not payload or payload.get("type") != "access":
            raise credentials_exception
        user_id = payload.get("sub")
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise credentials_exception
        return user

    # ── Try API Key ────────────────────────────────────────────
    if api_key:
        key_hash = hash_api_key(api_key)
        result = await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)
        )
        api_key_obj = result.scalar_one_or_none()
        if not api_key_obj:
            raise credentials_exception
        result = await db.execute(select(User).where(User.id == api_key_obj.user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise credentials_exception
        return user

    raise credentials_exception


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_roles(*roles: UserRole):
    """Factory: returns a FastAPI dependency that enforces role membership."""
    async def _check(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {[r.value for r in roles]}",
            )
        return current_user
    return _check


def require_min_role(min_role: UserRole):
    """Require at least a certain role level in the hierarchy."""
    min_level = ROLE_HIERARCHY[min_role]

    async def _check(current_user: User = Depends(get_current_active_user)) -> User:
        user_level = ROLE_HIERARCHY.get(current_user.role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {min_role.value}+",
            )
        return current_user
    return _check


# ─── Convenience dependencies ─────────────────────────────────────────────────
require_admin = require_roles(UserRole.ADMIN)
require_security_or_above = require_min_role(UserRole.SECURITY_ENGINEER)
require_developer_or_above = require_min_role(UserRole.DEVELOPER)
