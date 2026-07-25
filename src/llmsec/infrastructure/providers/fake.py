from collections import deque
from dataclasses import dataclass, field

from llmsec.application.ports.model_gateway import (
    ModelRequest,
    ModelResponse,
    ModelUsage,
)


@dataclass(slots=True)
class FakeModelGateway:
    outputs: deque[str] = field(default_factory=deque)
    provider_id: str = "fake"
    calls: list[ModelRequest] = field(default_factory=list)

    @classmethod
    def returning(cls, *outputs: str) -> "FakeModelGateway":
        return cls(outputs=deque(outputs))

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        if not self.outputs:
            raise RuntimeError("FakeModelGateway has no configured output")
        output = self.outputs.popleft()
        return ModelResponse(
            output_text=output,
            observed_model_id=request.model_id,
            usage=ModelUsage(input_tokens=0, output_tokens=0),
            provider_request_id=f"fake-{len(self.calls)}",
        )
