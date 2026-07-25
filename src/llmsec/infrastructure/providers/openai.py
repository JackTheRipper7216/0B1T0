from dataclasses import dataclass, field

import httpx

from llmsec.application.ports.model_gateway import (
    ModelRequest,
    ModelResponse,
    ModelUsage,
)
from llmsec.infrastructure.providers.errors import ModelGatewayError


class OpenAIGatewayError(ModelGatewayError):
    """Raised when OpenAI rejects a request or returns an invalid response."""


@dataclass(slots=True)
class OpenAIModelGateway:
    api_key: str = field(repr=False)
    provider_id: str = "openai"
    api_base: str = "https://api.openai.com/v1"
    timeout_seconds: float = 90.0
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        payload = {
            "model": request.model_id,
            "instructions": request.system_prompt,
            "input": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "temperature": request.temperature,
            "reasoning": {"effort": "none"},
            "text": {"format": {"type": "text"}},
            "max_output_tokens": request.max_output_tokens,
            "store": False,
        }
        headers = {
            "authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.api_base}/responses",
                    headers=headers,
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise OpenAIGatewayError(
                "OpenAI request failed before a response was received"
            ) from exc

        request_id = response.headers.get("x-request-id")
        if response.status_code >= 400:
            detail = _safe_error_detail(response, secret=self.api_key)
            raise OpenAIGatewayError(
                f"OpenAI returned HTTP {response.status_code}: {detail}"
            )

        try:
            body = response.json()
            output = body["output"]
            if not isinstance(output, list):
                raise TypeError
            output_text = _extract_visible_text(output)
            usage = body.get("usage") or {}
            observed_model = body.get("model") or request.model_id
            response_id = body.get("id")
        except (KeyError, TypeError, ValueError) as exc:
            raise OpenAIGatewayError(
                "OpenAI returned an unexpected response shape"
            ) from exc

        return ModelResponse(
            output_text=output_text,
            observed_model_id=observed_model,
            usage=ModelUsage(
                input_tokens=int(usage.get("input_tokens", 0)),
                output_tokens=int(usage.get("output_tokens", 0)),
            ),
            provider_request_id=request_id or response_id,
        )


def _extract_visible_text(output: list[object]) -> str:
    parts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "output_text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif block.get("type") == "refusal" and isinstance(block.get("refusal"), str):
                parts.append(block["refusal"])
    return "".join(parts)


def _safe_error_detail(response: httpx.Response, *, secret: str) -> str:
    try:
        body = response.json()
        detail = body.get("error", {}).get("message")
        if isinstance(detail, str) and detail:
            return detail.replace(secret, "[REDACTED]")[:300]
    except (TypeError, ValueError):
        pass
    return "provider request rejected"
