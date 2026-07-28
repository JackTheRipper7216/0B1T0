from llmsec.application.ports.model_gateway import ModelGateway
from llmsec.infrastructure.providers.anthropic import AnthropicModelGateway
from llmsec.infrastructure.providers.groq import GroqModelGateway
from llmsec.infrastructure.providers.openai import OpenAIModelGateway

EXECUTABLE_PROVIDER_IDS = frozenset({"groq", "openai", "anthropic"})


def build_model_gateway(provider_id: str, api_key: str) -> ModelGateway:
    if provider_id == "groq":
        return GroqModelGateway(api_key=api_key)
    if provider_id == "anthropic":
        return AnthropicModelGateway(api_key=api_key)
    if provider_id == "openai":
        return OpenAIModelGateway(api_key=api_key)
    raise ValueError(f"Provider {provider_id!r} does not have an executable gateway")
