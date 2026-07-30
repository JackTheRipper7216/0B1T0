from fastapi import APIRouter, Depends

from apps.api.auth import AuthenticatedUser, require_current_user
from llmsec.catalog import build_catalog
from llmsec.schemas import CatalogResponse

router = APIRouter(tags=["catalog"])


@router.get("/catalog", response_model=CatalogResponse)
def get_catalog(
    _user: AuthenticatedUser = Depends(require_current_user),
) -> CatalogResponse:
    return build_catalog()
