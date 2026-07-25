from fastapi import APIRouter

from llmsec.catalog import build_catalog
from llmsec.schemas import CatalogResponse


router = APIRouter(tags=["catalog"])


@router.get("/catalog", response_model=CatalogResponse)
def get_catalog() -> CatalogResponse:
    return build_catalog()
