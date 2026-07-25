from dataclasses import dataclass, field

import httpx

from llmsec.application.ports.model_gateway import (
    ModelRequest,
    ModelResponse,
    ModelUsage,
)
from llmsec.infrastructure.providers.errors import ModelGatewayError


class AnthropicGatewayError(ModelGatewayError):
    """Raised when Anthropic rejects a request or returns an invalid response."""


MODELS_WITHOUT_SAMPLING_PARAMETERS = frozenset(
    {"claude-sonnet-5", "claude-opus-4-8"}
)


@dataclass(slots=True)
class AnthropicModelGateway:
    api_key: str = field(repr=False)
    provider_id: str = "anthropic"
    api_base: str = "https://api.anthropic.com/v1"
    api_version: str = "2023-06-01"
    timeout_seconds: float = 90.0
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        payload = {
            "model": request.model_id,
            "system": request.system_prompt,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "max_tokens": request.max_output_tokens,
        }
        if request.model_id not in MODELS_WITHOUT_SAMPLING_PARAMETERS:
            payload["temperature"] = request.temperature
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.api_version,
            "content-type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.api_base}/messages",
                    headers=headers,
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise AnthropicGatewayError(
                "Anthropic request failed before a response was received"
            ) from exc

        request_id = response.headers.get("request-id") or response.headers.get("x-request-id")
        if response.status_code >= 400:
            detail = _safe_error_detail(response, secret=self.api_key)
            raise AnthropicGatewayError(
                f"Anthropic returned HTTP {response.status_code}: {detail}"
            )

        try:
            body = response.json()
            content = body["content"]
            if not isinstance(content, list):
                raise TypeError
            text_parts = [
                block["text"]
                for block in content
                if isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
            ]
            usage = body.get("usage") or {}
            observed_model = body.get("model") or request.model_id
        except (KeyError, TypeError, ValueError) as exc:
            raise AnthropicGatewayError(
                "Anthropic returned an unexpected response shape"
            ) from exc

        return ModelResponse(
            output_text="".join(text_parts),
            observed_model_id=observed_model,
            usage=ModelUsage(
                input_tokens=int(usage.get("input_tokens", 0)),
                output_tokens=int(usage.get("output_tokens", 0)),
            ),
            provider_request_id=request_id,
        )


def _safe_error_detail(response: httpx.Response, *, secret: str) -> str:
    try:
        body = response.json()
        detail = body.get("error", {}).get("message")
        if isinstance(detail, str) and detail:
            return detail.replace(secret, "[REDACTED]")[:300]
    except (TypeError, ValueError):
        pass
    return "provider request rejected"
