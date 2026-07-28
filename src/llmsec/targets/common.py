from dataclasses import dataclass

from llmsec.application.ports import (
    ChatMessage,
    ModelGateway,
    ModelRequest,
    ModelUsage,
)
from llmsec.defenses import DefenseContext, DefensePipeline, DefenseVerdict, PipelineResult
from llmsec.oracle import RecoveryOracle


@dataclass(frozen=True, slots=True)
class TargetTurnResult:
    visible_output: str
    raw_model_output: str | None
    raw_model_disclosure: bool
    visible_direct_leak: bool
    model_called: bool
    model_id: str
    provider_request_id: str | None
    usage: ModelUsage
    model_latency_ms: float
    defense_latency_ms: float
    verdicts: tuple[DefenseVerdict, ...]
    success: bool
    success_channel: str | None
    prohibited_action: bool = False


async def run_secret_context_turn(
    *,
    target_id: str,
    secret: str,
    system_prompt: str,
    gateway: ModelGateway,
    model_id: str,
    temperature: float,
    pipeline: DefensePipeline,
    user_input: str,
    history: tuple[ChatMessage, ...],
    metadata: dict[str, str] | None = None,
) -> TargetTurnResult:
    model_usage = ModelUsage(input_tokens=0, output_tokens=0)
    observed_model_id = model_id
    provider_request_id: str | None = None

    async def call_model(final_system_prompt: str, filtered_user_input: str) -> str:
        nonlocal model_usage, observed_model_id, provider_request_id
        response = await gateway.complete(
            ModelRequest(
                model_id=model_id,
                system_prompt=final_system_prompt,
                messages=(*history, ChatMessage(role="user", content=filtered_user_input)),
                temperature=temperature,
            )
        )
        model_usage = response.usage
        observed_model_id = response.observed_model_id
        provider_request_id = response.provider_request_id
        return response.output_text

    result: PipelineResult = await pipeline.execute(
        system_prompt=system_prompt,
        user_input=user_input,
        context=DefenseContext(
            target_id=target_id,
            secret=secret,
            metadata=metadata or {},
        ),
        model_call=call_model,
    )
    oracle = RecoveryOracle(secret)
    raw_disclosure = bool(
        result.raw_model_output and oracle.direct_visible_leak(result.raw_model_output)
    )
    visible_leak = oracle.direct_visible_leak(result.visible_output)
    return TargetTurnResult(
        visible_output=result.visible_output,
        raw_model_output=result.raw_model_output,
        raw_model_disclosure=raw_disclosure,
        visible_direct_leak=visible_leak,
        model_called=result.model_called,
        model_id=observed_model_id,
        provider_request_id=provider_request_id,
        usage=model_usage,
        model_latency_ms=result.model_latency_ms,
        defense_latency_ms=result.defense_latency_ms,
        verdicts=result.verdicts,
        success=visible_leak,
        success_channel="visible_exact_recovery" if visible_leak else None,
    )
