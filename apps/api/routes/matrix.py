import os

from fastapi import APIRouter, HTTPException

from llmsec.application.ports import ModelGateway
from llmsec.application.services import (
    run_adaptive_matrix,
    run_static_matrix,
    validate_adaptive_request,
    validate_static_matrix_request,
)
from llmsec.catalog import PROVIDERS_BY_ID
from llmsec.infrastructure.providers import ModelGatewayError, build_model_gateway
from llmsec.infrastructure.providers.factory import EXECUTABLE_PROVIDER_IDS
from apps.api.routes.runs import run_archive
from llmsec.matrix import estimate_matrix
from llmsec.schemas import (
    AdaptiveRunRequest,
    AdaptiveRunResponse,
    MatrixEstimateRequest,
    MatrixEstimateResponse,
    MatrixRunRequest,
    MatrixRunResponse,
)


router = APIRouter(tags=["matrix"])


@router.post("/matrix/estimate", response_model=MatrixEstimateResponse)
def get_matrix_estimate(request: MatrixEstimateRequest) -> MatrixEstimateResponse:
    try:
        return estimate_matrix(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/matrix/run-static", response_model=MatrixRunResponse)
async def run_matrix_static(request: MatrixRunRequest) -> MatrixRunResponse:
    try:
        validate_static_matrix_request(request)
        gateways = _build_gateways(request)
        result = await run_static_matrix(request, gateways)
        run_archive.save("static", result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ModelGatewayError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/matrix/run-adaptive", response_model=AdaptiveRunResponse)
async def run_matrix_adaptive(request: AdaptiveRunRequest) -> AdaptiveRunResponse:
    try:
        validate_adaptive_request(request)
        gateways = _build_gateways(request)
        result = await run_adaptive_matrix(request, gateways)
        run_archive.save("adaptive", result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ModelGatewayError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def _build_gateways(
    request: MatrixRunRequest | AdaptiveRunRequest,
) -> dict[str, ModelGateway]:
    provider_ids = {model_ref.partition(":")[0] for model_ref in request.model_ids}
    if isinstance(request, AdaptiveRunRequest) and request.attacker_model_id:
        provider_ids.add(request.attacker_model_id.partition(":")[0])
    gateways: dict[str, ModelGateway] = {}
    for provider_id in provider_ids:
        if provider_id not in EXECUTABLE_PROVIDER_IDS:
            raise ValueError(f"Provider {provider_id!r} is not executable")
        provider = PROVIDERS_BY_ID[provider_id]
        supplied = request.credentials.get(provider_id)
        supplied_key = supplied.get_secret_value().strip() if supplied else ""
        api_key = supplied_key or os.getenv(provider.credential_env, "").strip()
        if not api_key:
            raise ValueError(
                f"Provide a {provider.name} key or configure {provider.credential_env}"
            )
        gateways[provider_id] = build_model_gateway(provider_id, api_key)
    return gateways
