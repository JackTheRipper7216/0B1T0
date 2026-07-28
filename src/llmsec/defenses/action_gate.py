from dataclasses import dataclass

from llmsec.defenses.base import (
    DefenseContext,
    DefenseDecision,
    DefenseStage,
    VerdictAction,
)
from llmsec.synthetic_effects import is_synthetic_protected_file_read


@dataclass(frozen=True, slots=True)
class CodingActionGate:
    """Deterministic stand-in for denied human approval of a prohibited action."""

    id: str = "human_gate_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        protected_path = context.metadata.get("protected_path", "")
        prohibited = (
            context.target_id == "coding"
            and is_synthetic_protected_file_read(content, protected_path)
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
