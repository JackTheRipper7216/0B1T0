import json

import httpx

from llmsec.application.ports import ChatMessage, ModelRequest
from llmsec.infrastructure.providers.groq import GroqGatewayError, GroqModelGateway


async def test_groq_gateway_maps_chat_completion_and_usage() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer gsk_test_value"
        payload = json.loads(request.content)
        assert payload["model"] == "llama-3.3-70b-versatile"
        assert payload["messages"][0] == {"role": "system", "content": "System"}
        return httpx.Response(
            200,
            headers={"x-request-id": "req-test"},
            json={
                "model": "llama-3.3-70b-versatile",
                "choices": [{"message": {"content": "Hello"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )

    gateway = GroqModelGateway(
        api_key="gsk_test_value",
        transport=httpx.MockTransport(handler),
    )
    response = await gateway.complete(
        ModelRequest(
            model_id="llama-3.3-70b-versatile",
            system_prompt="System",
            messages=(ChatMessage(role="user", content="Hi"),),
            temperature=0.7,
        )
    )

    assert response.output_text == "Hello"
    assert response.usage.total_tokens == 15
    assert response.provider_request_id == "req-test"


async def test_groq_gateway_redacts_provider_error_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            401,
            json={"error": {"message": "invalid key gsk_bad_value"}},
        )

    gateway = GroqModelGateway(
        api_key="gsk_bad_value",
        transport=httpx.MockTransport(handler),
    )
    request = ModelRequest(
        model_id="llama-3.3-70b-versatile",
        system_prompt="System",
        messages=(ChatMessage(role="user", content="Hi"),),
        temperature=0.0,
    )

    try:
        await gateway.complete(request)
    except GroqGatewayError as exc:
        assert "HTTP 401" in str(exc)
        assert "gsk_bad_value" not in str(exc)
    else:
        raise AssertionError("Expected GroqGatewayError")


async def test_groq_gateway_retries_temporary_rate_limit() -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        del request
        call_count += 1
        if call_count == 1:
            return httpx.Response(
                429,
                headers={"retry-after": "0"},
                json={"error": {"message": "Rate limit reached"}},
            )
        return httpx.Response(
            200,
            json={
                "model": "openai/gpt-oss-120b",
                "choices": [{"message": {"content": "Recovered"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            },
        )

    gateway = GroqModelGateway(
        api_key="gsk_test_value",
        transport=httpx.MockTransport(handler),
        rate_limit_padding_seconds=0,
    )
    response = await gateway.complete(
        ModelRequest(
            model_id="openai/gpt-oss-120b",
            system_prompt="System",
            messages=(ChatMessage(role="user", content="Hi"),),
            temperature=0,
        )
    )

    assert call_count == 2
    assert response.output_text == "Recovered"


async def test_groq_gateway_stops_after_rate_limit_retry_budget() -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        del request
        call_count += 1
        return httpx.Response(
            429,
            headers={"retry-after": "0"},
            json={"error": {"message": "Rate limit reached for gsk_test_value"}},
        )

    gateway = GroqModelGateway(
        api_key="gsk_test_value",
        transport=httpx.MockTransport(handler),
        max_rate_limit_retries=2,
        rate_limit_padding_seconds=0,
    )
    request = ModelRequest(
        model_id="openai/gpt-oss-120b",
        system_prompt="System",
        messages=(ChatMessage(role="user", content="Hi"),),
        temperature=0,
    )

    try:
        await gateway.complete(request)
    except GroqGatewayError as exc:
        assert call_count == 3
        assert "after 2 automatic retries" in str(exc)
        assert "gsk_test_value" not in str(exc)
    else:
        raise AssertionError("Expected GroqGatewayError")


def test_gateway_repr_never_contains_api_key() -> None:
    gateway = GroqModelGateway(api_key="gsk_repr_secret")
    assert "gsk_repr_secret" not in repr(gateway)
