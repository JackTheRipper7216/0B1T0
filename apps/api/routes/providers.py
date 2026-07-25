from fastapi import APIRouter, HTTPException

from llmsec.catalog import PROVIDERS_BY_ID
from llmsec.schemas import CredentialCheckRequest, CredentialCheckResponse


router = APIRouter(tags=["providers"])


@router.post(
    "/providers/{provider_id}/credential-check",
    response_model=CredentialCheckResponse,
)
def check_credential(
    provider_id: str,
    request: CredentialCheckRequest,
) -> CredentialCheckResponse:
    provider = PROVIDERS_BY_ID.get(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Unknown provider")

    key = request.api_key.strip()
    expected_prefixes = {
        "groq": ("gsk_",),
        "openai": ("sk-",),
        "anthropic": ("sk-ant-",),
    }
    accepted = len(key) >= 12 and key.startswith(expected_prefixes[provider_id])
    masked = f"••••••••{key[-4:]}" if len(key) >= 4 else "••••••••"

    return CredentialCheckResponse(
        provider_id=provider_id,
        accepted_format=accepted,
        masked_key=masked,
        persisted=False,
        message=(
            "Key format accepted for this browser session. No key was stored."
            if accepted
            else "The key does not match the expected provider format."
        ),
    )
