from dataclasses import dataclass
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: Literal["user", "assistant"]
    content: str


@dataclass(frozen=True, slots=True)
class ModelRequest:
    model_id: str
    system_prompt: str
    messages: tuple[ChatMessage, ...]
    temperature: float
    max_output_tokens: int = 1024


@dataclass(frozen=True, slots=True)
class ModelUsage:
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class ModelResponse:
    output_text: str
    observed_model_id: str
    usage: ModelUsage
    provider_request_id: str | None = None


class ModelGateway(Protocol):
    provider_id: str

    async def complete(self, request: ModelRequest) -> ModelResponse: ...
