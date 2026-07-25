from dataclasses import dataclass

from llmsec.application.ports import ModelGateway, ModelRequest, ModelResponse
from llmsec.domain import CallRole, CampaignBudget, CampaignSnapshot
from llmsec.schemas import BudgetUsageResponse


class BudgetExhaustedError(RuntimeError):
    def __init__(self, snapshot: CampaignSnapshot) -> None:
        self.snapshot = snapshot
        reason = snapshot.terminal_reason or "budget_exhausted"
        super().__init__(f"Campaign budget stopped the next model call: {reason}")


@dataclass(slots=True)
class BudgetedModelGateway:
    gateway: ModelGateway
    budget: CampaignBudget
    role: CallRole = CallRole.TARGET

    @property
    def provider_id(self) -> str:
        return self.gateway.provider_id

    async def complete(self, request: ModelRequest) -> ModelResponse:
        estimated_input_tokens = estimate_request_tokens(request)
        begin = (
            self.budget.try_begin_target_call
            if self.role is CallRole.TARGET
            else self.budget.try_begin_attacker_call
        )
        admission = begin(
            estimated_input_tokens=estimated_input_tokens,
            max_output_tokens=request.max_output_tokens,
        )
        if not admission.admitted or admission.lease is None:
            raise BudgetExhaustedError(admission.snapshot)
        try:
            response = await self.gateway.complete(request)
        except Exception:
            self.budget.abandon_call(admission.lease)
            raise
        self.budget.settle_call(
            admission.lease,
            actual_input_tokens=response.usage.input_tokens,
            actual_output_tokens=response.usage.output_tokens,
        )
        return response


def estimate_request_tokens(request: ModelRequest) -> int:
    """Conservative dependency-free estimate used only for pre-call admission."""
    characters = len(request.system_prompt) + sum(
        len(message.content) + len(message.role) for message in request.messages
    )
    return max(1, (characters + 2) // 3)


def budget_response(snapshot: CampaignSnapshot) -> BudgetUsageResponse:
    usage = snapshot.usage
    return BudgetUsageResponse(
        status=snapshot.status,
        terminal_reason=snapshot.terminal_reason,
        target_calls=usage.target_calls,
        attacker_calls=usage.attacker_calls,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        submissions=usage.submissions,
        branches=usage.branches,
        retries=usage.retries,
        elapsed_seconds=usage.elapsed_seconds,
    )
