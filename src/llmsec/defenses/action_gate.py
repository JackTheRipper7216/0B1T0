import re
from dataclasses import dataclass

from llmsec.defenses.base import (
    DefenseContext,
    DefenseDecision,
    DefenseStage,
    VerdictAction,
)


READ_PRIMITIVE = re.compile(
    r"(?:open\s*\(|read_text\s*\(|cat\s+|type\s+|Get-Content\s+)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class CodingActionGate:
    """Deterministic stand-in for denied human approval of a prohibited action."""

    id: str = "human_gate_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        protected_path = context.metadata.get("protected_path", "")
        prohibited = (
            context.target_id == "coding"
            and protected_path
            and protected_path.lower() in content.lower()
            and READ_PRIMITIVE.search(content) is not None
        )
        if prohibited:
            return DefenseDecision(
                action=VerdictAction.BLOCK,
                reason_code="action_gate.prohibited_read_denied",
                content="[ACTION BLOCKED: approval denied for protected resource]",
            )
        return DefenseDecision(
            action=VerdictAction.PASS,
            reason_code="action_gate.no_sensitive_action",
            content=content,
        )
