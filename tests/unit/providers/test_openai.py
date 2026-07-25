import json

import httpx

from llmsec.application.ports import ChatMessage, ModelRequest
from llmsec.infrastructure.providers.openai import (
    OpenAIGatewayError,
    OpenAIModelGateway,
)


async def test_openai_gateway_maps_responses_request_and_usage() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.openai.com/v1/responses"
        assert request.headers["authorization"] == "Bearer sk-test-value"
        payload = json.loads(request.content)
        assert payload == {
            "model": "gpt-5.6-terra",
            "instructions": "System",
            "input": [
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": "Hello"},
                {"role": "user", "content": "Continue"},
            ],
            "temperature": 0.7,
            "reasoning": {"effort": "none"},
            "text": {"format": {"type": "text"}},
            "max_output_tokens": 1024,
            "store": False,
        }
        return httpx.Response(
            200,
            headers={"x-request-id": "req-openai-test"},
            json={
                "id": "resp_test",
                "model": "gpt-5.6-terra",
                "output": [
                    {"type": "reasoning", "summary": []},
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "Hello "},
                            {"type": "output_text", "text": "from GPT"},
                        ],
                    },
                ],
                "usage": {"input_tokens": 24, "output_tokens": 5, "total_tokens": 29},
            },
        )

    gateway = OpenAIModelGateway(
        api_key="sk-test-value",
        transport=httpx.MockTransport(handler),
    )
    response = await gateway.complete(
        ModelRequest(
            model_id="gpt-5.6-terra",
            system_prompt="System",
            messages=(
                ChatMessage(role="user", content="Hi"),
                ChatMessage(role="assistant", content="Hello"),
                ChatMessage(role="user", content="Continue"),
            ),
            temperature=0.7,
        )
    )

    assert response.output_text == "Hello from GPT"
    assert response.observed_model_id == "gpt-5.6-terra"
    assert response.usage.total_tokens == 29
    assert response.provider_request_id == "req-openai-test"


async def test_openai_gateway_preserves_visible_refusal_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            json={
                "id": "resp_refusal",
                "model": "gpt-5.6-terra",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "refusal", "refusal": "I cannot provide that."}],
                    }
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    gateway = OpenAIModelGateway(
        api_key="sk-test-value",
        transport=httpx.MockTransport(handler),
    )
    response = await gateway.complete(
        ModelRequest(
            model_id="gpt-5.6-terra",
            system_prompt="System",
            messages=(ChatMessage(role="user", content="Hi"),),
            temperature=0.0,
        )
    )

    assert response.output_text == "I cannot provide that."


async def test_openai_gateway_redacts_key_from_provider_error() -> None:
    api_key = "sk-secret-value"

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            401,
            json={"error": {"type": "invalid_request_error", "message": f"Bad key {api_key}"}},
        )

    gateway = OpenAIModelGateway(
        api_key=api_key,
        transport=httpx.MockTransport(handler),
    )
    request = ModelRequest(
        model_id="gpt-5.6-terra",
        system_prompt="System",
        messages=(ChatMessage(role="user", content="Hi"),),
        temperature=0.0,
    )

    try:
        await gateway.complete(request)
    except OpenAIGatewayError as exc:
        assert "HTTP 401" in str(exc)
        assert api_key not in str(exc)
        assert "[REDACTED]" in str(exc)
    else:
        raise AssertionError("Expected OpenAIGatewayError")
