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