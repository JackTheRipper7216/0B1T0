from fastapi import APIRouter, Depends, HTTPException, status

from apps.api.auth import (
    AuthenticatedUser,
    authenticate_user,
    create_access_token,
    register_user,
    require_current_user,
)
from llmsec.infrastructure.user_accounts import UsernameUnavailableError
from llmsec.schemas import AuthLoginRequest, AuthSessionResponse, AuthSignupRequest

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=AuthSessionResponse)
def login(request: AuthLoginRequest) -> AuthSessionResponse:
    password = request.password.get_secret_value()
    user = authenticate_user(request.username, password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return AuthSessionResponse(
        username=user.username,
        role=user.role,
        access_token=create_access_token(user),
    )


@router.post("/auth/signup", response_model=AuthSessionResponse, status_code=201)
def signup(request: AuthSignupRequest) -> AuthSessionResponse:
    try:
        account = register_user(
            request.username,
            request.password.get_secret_value(),
        )
    except UsernameUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    user = AuthenticatedUser(
        user_id=account.id,
        username=account.username,
        role=account.role,
    )
    return AuthSessionResponse(
        username=user.username,
        role=user.role,
        access_token=create_access_token(user),
    )


@router.get("/auth/me", response_model=AuthSessionResponse)
def me(user: AuthenticatedUser = Depends(require_current_user)) -> AuthSessionResponse:
    return AuthSessionResponse(
        username=user.username,
        role=user.role,
        access_token="",
    )
