"""
Auth Router — Login, Register, Token Refresh, Profile
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, verify_token,
    generate_api_key, hash_api_key,
)
from app.core.rbac import get_current_active_user
from app.database import get_db
from app.models.user import User, UserRole, APIKey

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8)
    full_name: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserProfile(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime


class APIKeyResponse(BaseModel):
    key: str  # Shown once only
    prefix: str
    name: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user account."""
    # Check uniqueness
    result = await db.execute(
        select(User).where(
            (User.email == data.email) | (User.username == data.username)
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email or username already registered")

    user = User(
        email=data.email,
        username=data.username,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"message": "Account created", "user_id": str(user.id)}


@router.post("/login", response_model=LoginResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate and return JWT tokens."""
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is disabled")

    # Update last login
    await db.execute(
        update(User).where(User.id == user.id).values(last_login=datetime.now(timezone.utc))
    )
    await db.commit()

    return LoginResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id)),
        user_id=str(user.id),
        username=user.username,
        role=user.role.value,
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(data: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a refresh token for new access token."""
    payload = verify_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    return LoginResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id)),
        user_id=str(user.id),
        username=user.username,
        role=user.role.value,
    )


@router.get("/me", response_model=UserProfile)
async def get_profile(current_user: User = Depends(get_current_active_user)):
    """Get current user profile."""
    return UserProfile(
        id=str(current_user.id),
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        role=current_user.role.value,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    name: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new API key. The raw key is shown only once."""
    raw_key, key_hash, key_prefix = generate_api_key()
    api_key = APIKey(
        user_id=current_user.id,
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
    )
    db.add(api_key)
    await db.commit()
    return APIKeyResponse(key=raw_key, prefix=key_prefix, name=name)
