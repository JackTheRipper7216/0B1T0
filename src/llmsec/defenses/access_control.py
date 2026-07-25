from dataclasses import dataclass

from llmsec.defenses.base import (
    DefenseContext,
    DefenseDecision,
    DefenseStage,
    VerdictAction,
)


@dataclass(frozen=True, slots=True)
class RagAccessControl:
    """Enforce document authorization before restricted context reaches the model."""

    id: str = "access_rag_acl_v1"
    stage: DefenseStage = DefenseStage.BEFORE_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        if context.target_id != "rag":
            return _not_applicable(content, "access.rag.target_not_applicable")
        if context.metadata.get("caller_role") == "administrator":
            return _pass(content, "access.rag.authorized")
        return DefenseDecision(
            action=VerdictAction.TRANSFORM,
            reason_code="access.rag.restricted_document_removed",
            content=content.replace(context.secret, "[RESTRICTED DOCUMENT EXCLUDED]"),
        )


@dataclass(frozen=True, slots=True)
class PiiRowAccessControl:
    """Apply the synthetic row/field policy before model generation."""

    id: str = "access_pii_row_v1"
    stage: DefenseStage = DefenseStage.BEFORE_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        if context.target_id != "pii":
            return _not_applicable(content, "access.pii.target_not_applicable")
        if context.metadata.get("caller_role") == "privacy_administrator":
            return _pass(content, "access.pii.authorized")
        return DefenseDecision(
            action=VerdictAction.TRANSFORM,
            reason_code="access.pii.protected_field_removed",
            content=content.replace(context.secret, "[FIELD OUTSIDE CALLER SCOPE]"),
        )


def _pass(content: str, reason: str) -> DefenseDecision:
    return DefenseDecision(action=VerdictAction.PASS, reason_code=reason, content=content)


def _not_applicable(content: str, reason: str) -> DefenseDecision:
    return DefenseDecision(
        action=VerdictAction.NOT_APPLICABLE,
        reason_code=reason,
        content=content,
    )
