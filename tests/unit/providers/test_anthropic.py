import json

import httpx

from llmsec.application.ports import ChatMessage, ModelRequest
from llmsec.infrastructure.providers.anthropic import (
    AnthropicGatewayError,
    AnthropicModelGateway,
)


async def test_anthropic_gateway_maps_messages_request_and_usage() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.anthropic.com/v1/messages"
        assert request.headers["x-api-key"] == "sk-ant-test-value"
        assert request.headers["anthropic-version"] == "2023-06-01"
        payload = json.loads(request.content)
        assert payload == {
            "model": "claude-sonnet-5",
            "system": "System",
            "messages": [
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": "Hello"},
                {"role": "user", "content": "Continue"},
            ],
            "max_tokens": 1024,
        }
        return httpx.Response(
            200,
            headers={"request-id": "req-anthropic-test"},
            json={
                "id": "msg_test",
                "model": "claude-sonnet-5",
                "content": [
                    {"type": "text", "text": "Hello "},
                    {"type": "text", "text": "from Claude"},
                ],
                "usage": {"input_tokens": 21, "output_tokens": 4},
            },
        )

    gateway = AnthropicModelGateway(
        api_key="sk-ant-test-value",
        transport=httpx.MockTransport(handler),
    )
    response = await gateway.complete(
        ModelRequest(
            model_id="claude-sonnet-5",
            system_prompt="System",
            messages=(
                ChatMessage(role="user", content="Hi"),
                ChatMessage(role="assistant", content="Hello"),
                ChatMessage(role="user", content="Continue"),
            ),
            temperature=0.7,
        )
    )

    assert response.output_text == "Hello from Claude"
    assert response.observed_model_id == "claude-sonnet-5"
    assert response.usage.total_tokens == 25
    assert response.provider_request_id == "req-anthropic-test"


async def test_legacy_anthropic_model_keeps_supported_temperature_parameter() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["temperature"] == 0.3
        return httpx.Response(
            200,
            json={
                "model": "claude-legacy-test",
                "content": [{"type": "text", "text": "ok"}],
                "usage": {},
            },
        )

    gateway = AnthropicModelGateway(
        api_key="sk-ant-test-value",
        transport=httpx.MockTransport(handler),
    )
    await gateway.complete(
        ModelRequest(
            model_id="claude-legacy-test",
            system_prompt="System",
            messages=(ChatMessage(role="user", content="Hi"),),
            temperature=0.3,
        )
    )


async def test_anthropic_gateway_redacts_key_from_provider_error() -> None:
    api_key = "sk-ant-secret-value"

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            401,
            json={"error": {"type": "authentication_error", "message": f"Bad key {api_key}"}},
        )

    gateway = AnthropicModelGateway(
        api_key=api_key,
        transport=httpx.MockTransport(handler),
    )
    request = ModelRequest(
        model_id="claude-sonnet-5",
        system_prompt="System",
        messages=(ChatMessage(role="user", content="Hi"),),
        temperature=0.0,
    )

    try:
        await gateway.complete(request)
    except AnthropicGatewayError as exc:
        assert "HTTP 401" in str(exc)
        assert api_key not in str(exc)
        assert "[REDACTED]" in str(exc)
    else:
        raise AssertionError("Expected AnthropicGatewayError")
