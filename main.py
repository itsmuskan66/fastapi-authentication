import re
from fastapi import FastAPI, HTTPException, Response,status, Depends
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session
from app.core.security import hash_password, verify_password,  create_access_token, create_refresh_token
from app.db.database import engine, Base, get_db
from app.models.user_model import User
from fastapi.responses import JSONResponse
from fastapi import Request
from app.core.token_rotation import rotate_refresh_token
from app.core.security import set_refresh_cookie
from app.models.user_model import RefreshToken

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

    try:
        existing_user = db.query(User).filter(
            User.user_email == user.email
        ).first()

        if not existing_user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )

        if not verify_password(
            user.password,
            existing_user.user_hashed_password
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )

        # Generate Tokens
        access_token = create_access_token(str(existing_user.id))
        refresh_token = create_refresh_token(str(existing_user.id))

        # Save Refresh Token in Database
        db.add(
            RefreshToken(
                token=refresh_token,
                user_id=existing_user.id,
                revoked=False
            )
        )
        db.commit()

        # Response
        response = JSONResponse(
            content={"message": "Login successful"}
        )

        # Set Access Token Cookie
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="lax"
        )

        # Set Refresh Token Cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="lax"
        )

        return response

    except Exception as e:
        print("LOGIN ERROR:", e)
        raise

#********** REFRESH  TOKEN API *****************

@app.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    old_token = request.cookies.get("refresh_token")

    if not old_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing"
        )

    new_access_token, new_refresh_token = rotate_refresh_token(old_token, db)

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="lax"
    )

    set_refresh_cookie(response, new_refresh_token)

    return {
        "message": "Token refreshed successfully"
    }


#*********** LOGOUT API ***************


@app.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    old_token = request.cookies.get("refresh_token")

    if old_token:
        db.query(RefreshToken).filter_by(token=old_token).update(
            {"revoked": True}
        )
        db.commit()

    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")

    return {
        "message": "Logged out successfully"
    }