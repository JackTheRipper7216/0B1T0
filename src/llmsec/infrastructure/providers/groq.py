import asyncio
from dataclasses import dataclass, field

import httpx

from llmsec.application.ports.model_gateway import (
    ModelRequest,
    ModelResponse,
    ModelUsage,
)
from llmsec.infrastructure.providers.errors import ModelGatewayError


class GroqGatewayError(ModelGatewayError):
    """Raised when Groq rejects a request or returns an invalid response."""


@dataclass(slots=True)
class GroqModelGateway:
    api_key: str = field(repr=False)
    provider_id: str = "groq"
    api_base: str = "https://api.groq.com/openai/v1"
    timeout_seconds: float = 60.0
    max_rate_limit_retries: int = 5
    max_retry_after_seconds: float = 60.0
    rate_limit_padding_seconds: float = 0.25
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        messages = [
            {"role": "system", "content": request.system_prompt},
            *[{"role": message.role, "content": message.content} for message in request.messages],
        ]
        payload = {
            "model": request.model_id,
            "messages": messages,
            "temperature": request.temperature,
            "max_completion_tokens": request.max_output_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            transport=self.transport,
        ) as client:
            rate_limit_retries = 0
            for attempt in range(max(0, self.max_rate_limit_retries) + 1):
                try:
                    response = await client.post(
                        f"{self.api_base}/chat/completions",
                        headers=headers,
                        json=payload,
                    )
                except httpx.HTTPError as exc:
                    raise GroqGatewayError(
                        "Groq request failed before a response was received"
                    ) from exc
                if response.status_code != 429:
                    break
                retry_after = _retry_after_seconds(response)
                if (
                    attempt >= self.max_rate_limit_retries
                    or retry_after is None
                    or retry_after > self.max_retry_after_seconds
                ):
                    break
                await asyncio.sleep(retry_after + self.rate_limit_padding_seconds)
                rate_limit_retries += 1

        request_id = response.headers.get("x-request-id")
        if response.status_code >= 400:
            detail = _safe_error_detail(response, secret=self.api_key)
            retry_note = (
                f" after {rate_limit_retries} automatic retries"
                if response.status_code == 429 and rate_limit_retries
                else ""
            )
            raise GroqGatewayError(
                f"Groq returned HTTP {response.status_code}{retry_note}: {detail}"
            )

        try:
            body = response.json()
            output_text = body["choices"][0]["message"]["content"]
            usage = body.get("usage") or {}
            observed_model = body.get("model") or request.model_id
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise GroqGatewayError("Groq returned an unexpected response shape") from exc

        return ModelResponse(
            output_text=output_text,
            observed_model_id=observed_model,
            usage=ModelUsage(
                input_tokens=int(usage.get("prompt_tokens", 0)),
                output_tokens=int(usage.get("completion_tokens", 0)),
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


def _retry_after_seconds(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
