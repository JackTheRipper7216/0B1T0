from typing import Protocol

from llmsec.application.ports import ChatMessage, ModelGateway
from llmsec.defenses import DefensePipeline
from llmsec.schemas import TargetId
from llmsec.targets.chatbot import ChatbotTarget
from llmsec.targets.coding import CodingTarget
from llmsec.targets.common import TargetTurnResult
from llmsec.targets.rag import RagTarget


class TargetRuntime(Protocol):
    async def run_turn(
        self,
        user_input: str,
        history: tuple[ChatMessage, ...] = (),
    ) -> TargetTurnResult: ...


TARGET_TYPES = {
    "chatbot": ChatbotTarget,
    "rag": RagTarget,
    "coding": CodingTarget,
}


def build_target(
    target_id: TargetId,
    *,
    secret: str,
    gateway: ModelGateway,
    model_id: str,
    temperature: float,
    pipeline: DefensePipeline,
) -> TargetRuntime:
    target_type = TARGET_TYPES[target_id]
    return target_type(
        secret=secret,
        gateway=gateway,
        model_id=model_id,
        temperature=temperature,
        pipeline=pipeline,
    )
