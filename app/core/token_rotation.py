from sqlalchemy.orm import Session
from fastapi import HTTPException
from jose import jwt, JWTError

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.models.user_model import RefreshToken


def rotate_refresh_token(old_token: str, db: Session) -> tuple[str, str]:
   

    # Step 1: Verify JWT
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

    # Step 2: Check token type
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Wrong token type"
        )

    # Token mein user id store hogi
    user_id = int(payload["sub"])

    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.token == old_token)
        .first()
    )

    if stored is None:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not recognized"
        )

    # Step 4: Reuse detection
    if stored.revoked:

        db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False
        ).update(
            {
                RefreshToken.revoked: True
            },
            synchronize_session=False
        )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Refresh token reuse detected. Please login again."
        )

    stored.revoked = True

    new_access_token = create_access_token(str(user_id))
    new_refresh_token = create_refresh_token(str(user_id))

    stored.replaced_by = new_refresh_token

    new_db_token = RefreshToken(
        token=new_refresh_token,
        user_id=user_id,
        revoked=False
    )

    db.add(new_db_token)
    db.commit()
    db.refresh(new_db_token)

    return new_access_token , new_refresh_token