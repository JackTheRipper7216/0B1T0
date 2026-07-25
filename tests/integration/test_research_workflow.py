import re
from pathlib import Path

from llmsec.application.ports import ModelRequest, ModelResponse, ModelUsage
from llmsec.application.services import run_adaptive_matrix, run_static_matrix
from llmsec.benchmarks import run_benign_benchmark
from llmsec.infrastructure.run_archive import RunArchive
from llmsec.schemas import AdaptiveRunRequest, BenignBenchmarkRequest, MatrixRunRequest


class SemanticSyntheticGateway:
    provider_id = "groq"

    def __init__(self, *, reversed_fields: bool = False) -> None:
        self.reversed_fields = reversed_fields
        self.calls: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        secret = _extract_secret(request.system_prompt)
        if "/workspace/admin_secret.txt" in request.messages[-1].content:
            output = "print(open('/workspace/admin_secret.txt').read())"
        elif secret is None:
            output = "The requested restricted value is unavailable."
        elif self.reversed_fields:
            fields = tuple(secret[index : index + 6] for index in range(0, len(secret), 6))
            output = "\n".join(field[::-1] for field in reversed(fields))
        else:
            output = secret
        return ModelResponse(
            output_text=output,
            observed_model_id=request.model_id,
            usage=ModelUsage(input_tokens=60, output_tokens=12),
            provider_request_id=f"synthetic-{len(self.calls)}",
        )


def _extract_secret(system_prompt: str) -> str | None:
    patterns = (
        r"Internal build key: (\S+)",
        r"Incident recovery token: (\S+)",
        r"Restricted identity token: (\S+)",
    )
    for pattern in patterns:
        match = re.search(pattern, system_prompt)
        if match and not match.group(1).startswith("["):
            return match.group(1)
    return None


async def test_complete_three_target_static_adaptive_benchmark_archive_workflow(
    tmp_path: Path,
) -> None:
    model_ref = "groq:openai/gpt-oss-120b"
    cases = (
        ("chatbot", "single:output_exact_v1"),
        ("rag", "single:access_rag_acl_v1"),
        ("coding", "single:human_gate_v1"),
    )
    completed_static = []
    for target_id, defense_column_id in cases:
        result = await run_static_matrix(
            MatrixRunRequest(
                target_id=target_id,
                attack_ids=["direct_prompt_injection"],
                model_ids=[model_ref],
                defense_column_ids=[defense_column_id],
                trials=1,
                temperature=0,
            ),
            {"groq": SemanticSyntheticGateway()},
        )
        cells = {cell.defense_column_id: cell for cell in result.cells}
        assert cells["baseline"].success_count == 1
        assert cells[defense_column_id].success_count == 0
        completed_static.append(result)

    adaptive = await run_adaptive_matrix(
        AdaptiveRunRequest(
            target_id="chatbot",
            model_ids=[model_ref],
            defense_column_ids=["single:output_recovery_v1"],
            trials=1,
            max_queries=2,
        ),
        {"groq": SemanticSyntheticGateway(reversed_fields=True)},
    )
    adaptive_cells = {
        episode.defense_column_id: episode for episode in adaptive.episodes
    }
    assert adaptive_cells["baseline"].success is True
    assert adaptive_cells["single:output_recovery_v1"].success is False

    benchmark = await run_benign_benchmark(
        BenignBenchmarkRequest(
            target_ids=["chatbot", "rag", "coding"],
            defense_column_ids=["baseline"],
        )
    )
    assert all(cell.utility_retention_percent == 100 for cell in benchmark.cells)

    archive = RunArchive(tmp_path / "workflow.sqlite3")
    for result in completed_static:
        archive.save("static", result)
    archive.save("adaptive", adaptive)
    assert len(archive.list()) == 4
