from fastapi import APIRouter, Depends, HTTPException, status

from apps.api.auth import (
    AuthenticatedUser,
    create_access_token,
    require_current_user,
    verify_admin_credentials,
)
from llmsec.schemas import AuthLoginRequest, AuthSessionResponse

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=AuthSessionResponse)
def login(request: AuthLoginRequest) -> AuthSessionResponse:
    password = request.password.get_secret_value()
    if not verify_admin_credentials(request.username, password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return AuthSessionResponse(
        username=request.username,
        role="admin",
        access_token=create_access_token(request.username),
    )


@router.get("/auth/me", response_model=AuthSessionResponse)
def me(user: AuthenticatedUser = Depends(require_current_user)) -> AuthSessionResponse:
    return AuthSessionResponse(
        username=user.username,
        role=user.role,
        access_token="",
    )
