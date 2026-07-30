import re
from fastapi import FastAPI, HTTPException, Response,status, Depends
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session
from app.core.security import hash_password, verify_password,  create_access_token, create_refresh_token, verify_token
from app.db.database import engine, Base, get_db
from app.models.user_model import User
from fastapi.responses import JSONResponse
from fastapi import Request

app = FastAPI()

Base.metadata.create_all(bind=engine)

# *****************USER REGISTER***************************


class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError("Name cannot be empty.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError("Password must contain at least one special character.")
        return value




#**************REGISTER API***************

@app.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    print("Register endpoint called")
    existing_user = db.query(User).filter(User.user_email == user.email).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email already exists"
        )

    new_user = User(
        name=user.name,
        user_email=user.email,
        user_hashed_password=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Registration successful"
    }



# *******************   LOGIN API *************************




class UserLogin(BaseModel):
    email: EmailStr
    password: str


@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    print("Login endpoint called")

    # Check user
    existing_user = (
        db.query(User)
        .filter(User.user_email == user.email)
        .first()
    )

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    # Verify password
    if not verify_password(
        user.password,
        existing_user.user_hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    # Generate Tokens
    access_token = create_access_token(str(existing_user.id))
    refresh_token = create_refresh_token(str(existing_user.id))

    # Save Tokens in Database
    existing_user.access_token = access_token
    existing_user.refresh_token = refresh_token

    db.commit()

    # Create Response
    response = JSONResponse(
        content={
            "message": "Login successful"
        }
    )

    # Access Token Cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,      # True in Production (HTTPS)
        samesite="lax",
        max_age=15 * 60
    )

    # Refresh Token Cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 60 * 60
    )

    return response

#********** REFRESH  TOKEN API *****************


@app.post("/refresh")
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):

    # Cookie se refresh token lo
    old_refresh_token = request.cookies.get("refresh_token")

    if not old_refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing"
        )

    # JWT verify
    payload = verify_token(old_refresh_token)

    # Refresh token hi hona chahiye
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid token type"
        )

    user_id = int(payload["sub"])

    # User dhoondo
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Database wale refresh token se match karo
    if user.refresh_token != old_refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token is invalid"
        )
      
    # New Tokens
    new_access_token = create_access_token(str(user.id))
    new_refresh_token = create_refresh_token(str(user.id))

    # Database update
    user.access_token = new_access_token
    user.refresh_token = new_refresh_token

    db.commit()

    # Access Cookie overwrite
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=15 * 60
    )

    # Refresh Cookie overwrite
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 60 * 60
    )

    return {
        "message": "Tokens refreshed successfully"
    }

#*********** LOGOUT API ***************


@app.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:

        payload = verify_token(refresh_token)

        user_id = int(payload["sub"])

        user = db.query(User).filter(User.id == user_id).first()

        if user:
            user.access_token = None
            user.refresh_token = None
            db.commit()

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return {
        "message": "Logged out successfully"
    }