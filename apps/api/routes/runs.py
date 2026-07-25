import csv
import io
import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from llmsec.infrastructure.run_archive import ArchivedRun, RunArchive
from llmsec.schemas import ArchivedRunDetailResponse, ArchivedRunSummaryResponse


router = APIRouter(tags=["run-archive"])
run_archive = RunArchive()


@router.get("/runs", response_model=list[ArchivedRunSummaryResponse])
def list_runs(limit: int = Query(default=50, ge=1, le=200)) -> list[ArchivedRunSummaryResponse]:
    return [_summary(record) for record in run_archive.list(limit)]


@router.get("/runs/{run_id}", response_model=ArchivedRunDetailResponse)
def get_run(run_id: UUID) -> ArchivedRunDetailResponse:
    record = run_archive.get(str(run_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Archived run not found")
    return _detail(record)


@router.delete("/runs/{run_id}", status_code=204)
def delete_run(run_id: UUID) -> Response:
    if not run_archive.delete(str(run_id)):
        raise HTTPException(status_code=404, detail="Archived run not found")
    return Response(status_code=204)


@router.get("/runs/{run_id}/export")
def export_run(
    run_id: UUID,
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> Response:
    record = run_archive.get(str(run_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Archived run not found")
    if format == "json":
        body = json.dumps(record.result, indent=2)
        return Response(
            body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.json"'},
        )
    body = _csv_export(record)
    return Response(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{run_id}.csv"'},
    )


def _summary(record: ArchivedRun) -> ArchivedRunSummaryResponse:
    return ArchivedRunSummaryResponse(
        run_id=record.run_id,
        kind=record.kind,
        target_id=record.target_id,
        status=record.status,
        started_at=record.started_at,
        completed_at=record.completed_at,
        success_count=record.success_count,
        total_units=record.total_units,
    )


def _detail(record: ArchivedRun) -> ArchivedRunDetailResponse:
    return ArchivedRunDetailResponse(**_summary(record).model_dump(), result=record.result)


def _csv_export(record: ArchivedRun) -> str:
    rows = (
        record.result.get("episodes", [])
        if record.kind == "adaptive"
        else record.result.get("trials", [])
    )
    if not rows:
        return ""
    flat_rows = [
        {
            key: json.dumps(value, separators=(",", ":"))
            if isinstance(value, (dict, list))
            else value
            for key, value in row.items()
        }
        for row in rows
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(flat_rows[0].keys()))
    writer.writeheader()
    writer.writerows(flat_rows)
    return output.getvalue()
