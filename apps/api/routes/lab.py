import os
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response

from llmsec.application.services import LabSession, LabSessionStore
from llmsec.catalog import DEFENSE_COLUMNS_BY_ID, PROVIDERS_BY_ID, TARGETS_BY_ID
from llmsec.defenses.registry import resolve_defense_column
from llmsec.economics import PRICE_SNAPSHOT_DATE, estimate_cost_usd
from llmsec.infrastructure.providers import ModelGatewayError, build_model_gateway
from llmsec.infrastructure.providers.factory import EXECUTABLE_PROVIDER_IDS
from llmsec.schemas import (
    LabMessageRequest,
    LabMessageResponse,
    LabSessionCreateRequest,
    LabSessionDetailResponse,
    LabSessionResponse,
    LabSubmitRequest,
    LabSubmitResponse,
    LabTurnResponse,
    VerdictResponse,
)
from llmsec.targets import build_target

router = APIRouter(tags=["attack-lab"])
session_store = LabSessionStore()


@router.get("/lab/sessions", response_model=list[LabSessionResponse])
def list_lab_sessions(
    limit: int = Query(default=100, ge=1, le=200),
) -> list[LabSessionResponse]:
    return [_session_response(session) for session in session_store.list(limit)]


@router.get("/lab/sessions/{session_id}", response_model=LabSessionDetailResponse)
def get_lab_session(session_id: UUID) -> LabSessionDetailResponse:
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Attack Lab session not found")
    return _session_detail_response(session)


@router.post("/lab/sessions", response_model=LabSessionResponse, status_code=201)
def create_lab_session(request: LabSessionCreateRequest) -> LabSessionResponse:
    if request.provider_id not in EXECUTABLE_PROVIDER_IDS:
        raise HTTPException(
            status_code=409,
            detail="The selected provider does not have an executable gateway",
        )
    provider = PROVIDERS_BY_ID[request.provider_id]
    if request.model_id not in {model.id for model in provider.models}:
        raise HTTPException(status_code=422, detail="Model is not registered for this provider")
    if request.defense_column_id not in DEFENSE_COLUMNS_BY_ID:
        raise HTTPException(status_code=422, detail="Unknown defense column")
    if (
        request.target_id
        not in DEFENSE_COLUMNS_BY_ID[request.defense_column_id].applicable_target_ids
    ):
        raise HTTPException(
            status_code=422,
            detail="Defense column is not applicable to the selected target",
        )
    try:
        resolve_defense_column(request.defense_column_id)
    except NotImplementedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session = session_store.create(
        target_id=request.target_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        temperature=request.temperature,
        defense_column_id=request.defense_column_id,
    )
    return _session_response(session)


@router.post("/lab/sessions/{session_id}/messages", response_model=LabMessageResponse)
async def send_lab_message(session_id: UUID, request: LabMessageRequest) -> LabMessageResponse:
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Attack Lab session not found")
    if session.target_id not in TARGETS_BY_ID:
        raise HTTPException(status_code=409, detail="Session target is no longer available")
    if session.status == "failed":
        raise HTTPException(status_code=409, detail="This Attack Lab session has ended")

    async with session.turn_lock:
        supplied_key = request.api_key.get_secret_value() if request.api_key is not None else ""
        provider = PROVIDERS_BY_ID[session.provider_id]
        api_key = supplied_key.strip() or os.getenv(provider.credential_env, "").strip()
        if not api_key:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Provide an {provider.name} key in the session UI or configure "
                    f"{provider.credential_env}"
                ),
            )
        gateway = build_model_gateway(session.provider_id, api_key)
        target = build_target(
            session.target_id,
            secret=session.secret,
            gateway=gateway,
            model_id=session.model_id,
            temperature=session.temperature,
            pipeline=resolve_defense_column(session.defense_column_id),
        )
        try:
            result = await target.run_turn(request.content, tuple(session.history))
        except ModelGatewayError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        estimated_cost = estimate_cost_usd(
            session.provider_id,
            session.model_id,
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
        )
        response = LabMessageResponse(
            turn=session.turn_count + 1,
            visible_output=result.visible_output,
            visible_exact_leak=result.visible_direct_leak,
            raw_model_disclosure=result.raw_model_disclosure,
            model_called=result.model_called,
            observed_model_id=result.model_id,
            provider_request_id=result.provider_request_id,
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
            estimated_cost_usd=(
                float(estimated_cost) if estimated_cost is not None else None
            ),
            price_snapshot_date=PRICE_SNAPSHOT_DATE.isoformat(),
            model_latency_ms=result.model_latency_ms,
            defense_latency_ms=result.defense_latency_ms,
            verdicts=[
                VerdictResponse(
                    defense_id=verdict.defense_id,
                    stage=verdict.stage,
                    action=verdict.action,
                    reason_code=verdict.reason_code,
                    latency_ms=verdict.latency_ms,
                )
                for verdict in result.verdicts
            ],
        )
        session_store.record_turn(
            session_id,
            user_input=request.content,
            result=response.model_dump(mode="json"),
        )
        return response


@router.post("/lab/sessions/{session_id}/submit", response_model=LabSubmitResponse)
def submit_lab_candidate(session_id: UUID, request: LabSubmitRequest) -> LabSubmitResponse:
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Attack Lab session not found")
    if session.status == "failed":
        raise HTTPException(status_code=409, detail="This Attack Lab session has ended")
    success = session.oracle.exact_submission(request.candidate.get_secret_value())
    session_store.mark_submission(session_id, success=success)
    return LabSubmitResponse(
        success=success, classification="exact_leak" if success else "incorrect"
    )


@router.post(
    "/lab/sessions/{session_id}/close",
    response_model=LabSessionResponse,
)
def close_lab_session(session_id: UUID) -> LabSessionResponse:
    session = session_store.close(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Attack Lab session not found")
    return _session_response(session)


@router.delete("/lab/sessions/{session_id}", status_code=204)
def delete_lab_session(session_id: UUID) -> Response:
    if not session_store.delete(session_id):
        raise HTTPException(status_code=404, detail="Attack Lab session not found")
    return Response(status_code=204)


def _session_response(session: LabSession) -> LabSessionResponse:
    return LabSessionResponse(
        session_id=session.id,
        target_id=session.target_id,
        provider_id=session.provider_id,
        model_id=session.model_id,
        temperature=session.temperature,
        defense_column_id=session.defense_column_id,
        created_at=session.created_at,
        updated_at=session.updated_at,
        turn_count=session.turn_count,
        status=session.status,
    )


def _session_detail_response(session: LabSession) -> LabSessionDetailResponse:
    summary = _session_response(session)
    return LabSessionDetailResponse(
        **summary.model_dump(),
        turns=[
            LabTurnResponse(
                user_input=turn.user_input,
                created_at=turn.created_at,
                result=LabMessageResponse.model_validate(turn.result),
            )
            for turn in session.turns
        ],
    )
