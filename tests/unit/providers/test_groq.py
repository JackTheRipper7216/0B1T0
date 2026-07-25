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


def test_gateway_repr_never_contains_api_key() -> None:
    gateway = GroqModelGateway(api_key="gsk_repr_secret")
    assert "gsk_repr_secret" not in repr(gateway)
