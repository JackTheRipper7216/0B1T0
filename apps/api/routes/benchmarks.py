from fastapi import APIRouter, Depends, HTTPException

from apps.api.auth import AuthenticatedUser, require_current_user
from llmsec.benchmarks import run_benign_benchmark
from llmsec.catalog import DEFENSE_COLUMNS_BY_ID
from llmsec.defenses import resolve_defense_column
from llmsec.schemas import BenignBenchmarkRequest, BenignBenchmarkResponse

router = APIRouter(tags=["benchmarks"])


@router.post("/benchmarks/benign", response_model=BenignBenchmarkResponse)
async def run_benign_preflight(
    request: BenignBenchmarkRequest,
    _user: AuthenticatedUser = Depends(require_current_user),
) -> BenignBenchmarkResponse:
    try:
        for column_id in request.defense_column_ids:
            column = DEFENSE_COLUMNS_BY_ID.get(column_id)
            if column is None:
                raise ValueError(f"Unknown defense column: {column_id}")
            resolve_defense_column(column_id)
            for target_id in request.target_ids:
                if target_id not in column.applicable_target_ids:
                    raise ValueError(
                        f"Defense column {column_id!r} is not applicable to {target_id!r}"
                    )
        return await run_benign_benchmark(request)
    except (ValueError, NotImplementedError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
