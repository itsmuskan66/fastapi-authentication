from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError, ExpiredSignatureError

from app.core.config import settings

# Yeh routes bina access_token ke bhi allow honi chahiyen
EXCLUDED_PATHS = {
    "/register",
    "/login",
    "/refresh",
    "/docs",
    "/openapi.json",
    "/redoc",
}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):

        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        token = request.cookies.get("access_token")

        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

        if not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Access token missing. Please login."}
            )

        try:
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=[settings.algorithm]
            )
        except ExpiredSignatureError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Access token expired. Please refresh."}
            )
        except JWTError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid access token."}
            )
        if payload.get("type") != "access":
            return JSONResponse(
                status_code=401,
                content={"detail": "Wrong token type."}
            )
        request.state.user = payload                                                   # payload["sub"] mein user_id hai
        response = await call_next(request)
        return response