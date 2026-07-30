from typing import Any
from datetime import datetime, timedelta, timezone
import bcrypt
from fastapi import HTTPException , Response
from app.core.config import settings
from jose import jwt
from jose import JWTError, ExpiredSignatureError

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_password.decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(subject: str) -> str:
    payload: dict[str, Any] = {"sub": subject, "type": "access"}
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload["exp"] = expire
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

def create_refresh_token(subject: str) -> str:
    payload: dict[str, Any] = {"sub": subject, "type": "refresh"}
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload["exp"] = expire
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

MAX_REFRESH_TOKENS = 5  # kitne refresh tokens history/sessions mein rakhne hain


def push_refresh_token(user, new_token: str, max_tokens: int = MAX_REFRESH_TOKENS) -> list:
    """
    Naya refresh_token list mein append karta hai.
    Agar list size max_tokens se zyada ho jaye to sabse purana token
    (index 0) hata deta hai — FIFO (First In First Out).

    Example (max_tokens=3):
        shuru:        []
        1st login:    [t1]
        2nd login:    [t1, t2]
        3rd login:    [t1, t2, t3]
        4th login:    [t2, t3, t4]   <- t1 pop ho gaya, t4 append hua
    """
    tokens = list(user.refresh_token) if user.refresh_token else []
    tokens.append(new_token)

    if len(tokens) > max_tokens:
        tokens.pop(0)  # sabse purana token (list ka pehla item) nikal do

    # SQLAlchemy JSON column ke liye poori list dobara assign karni zaroori
    # hai, warna change track nahi hoga.
    user.refresh_token = tokens
    return tokens


def remove_refresh_token(user, old_token: str) -> list:
    """
    Rotation ke waqt use hone wala purana refresh_token list se hata deta hai
    (kyunke woh consume ho chuka hai), taake dobara use na ho sake.
    """
    tokens = list(user.refresh_token) if user.refresh_token else []
    if old_token in tokens:
        tokens.remove(old_token)
    user.refresh_token = tokens
    return tokens


def verify_token(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")



 
def set_refresh_cookie(response: Response, token: str):
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=False,          # localhost ke liye False
        samesite="lax",        # localhost ke liye lax
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/"
    )

