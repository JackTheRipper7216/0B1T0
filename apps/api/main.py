from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.routes.benchmarks import router as benchmarks_router
from apps.api.routes.catalog import router as catalog_router
from apps.api.routes.lab import router as lab_router
from apps.api.routes.matrix import router as matrix_router
from apps.api.routes.providers import router as providers_router
from apps.api.routes.runs import router as runs_router

load_dotenv()


app = FastAPI(
    title="OBITO LLM Security Benchmark API",
    version="0.1.0",
    description=(
        "Control plane for the Orchestrated Benchmark for Injection Testing "
        "and Oracles."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID"],
)


@app.get("/api/v1/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "obito-api", "version": app.version}


app.include_router(catalog_router, prefix="/api/v1")
app.include_router(benchmarks_router, prefix="/api/v1")
app.include_router(lab_router, prefix="/api/v1")
app.include_router(matrix_router, prefix="/api/v1")
app.include_router(providers_router, prefix="/api/v1")
app.include_router(runs_router, prefix="/api/v1")
