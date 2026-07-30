from sqlalchemy.orm import Session
from fastapi import HTTPException
from jose import jwt, JWTError

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
)
from app.models.user_model import User


def rotate_refresh_token(old_token: str, db: Session):

    try:
        payload = jwt.decode(
            old_token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Wrong token type"
        )

    user_id = int(payload["sub"])

    # User find karo
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # DB wala refresh token match hona chahiye
    if user.refresh_token != old_token:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    # New Tokens
    new_access_token = create_access_token(str(user.id))
    new_refresh_token = create_refresh_token(str(user.id))

    # Update Users Table
    user.access_token = new_access_token
    user.refresh_token = new_refresh_token

    db.commit()
    db.refresh(user)

    return new_access_token, new_refresh_token