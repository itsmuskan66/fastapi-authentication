from sqlalchemy.orm import Session
from fastapi import HTTPException
from jose import jwt, JWTError

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    push_refresh_token,
    remove_refresh_token,
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

    # DB wali refresh_token LIST mein yeh token maujood hona chahiye
    if not user.refresh_token or old_token not in user.refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    # New Tokens
    new_access_token = create_access_token(str(user.id))
    new_refresh_token = create_refresh_token(str(user.id))

    # access_token DB mein save nahi karte.
    # refresh_token rotation: purana token list se hatao (consume),
    # naya token list mein push karo (FIFO — limit se zyada hone par
    # sabse purana token automatically pop ho jayega).
    remove_refresh_token(user, old_token)
    push_refresh_token(user, new_refresh_token)

    db.commit()
    db.refresh(user)

    return new_access_token, new_refresh_token