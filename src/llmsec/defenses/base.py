from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class DefenseStage(StrEnum):
    BEFORE_CONTEXT = "before_context"
    BEFORE_MODEL = "before_model"
    AFTER_MODEL = "after_model"


class VerdictAction(StrEnum):
    PASS = "pass"
    BLOCK = "block"
    TRANSFORM = "transform"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class DefenseContext:
    target_id: str
    secret: str
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DefenseDecision:
    action: VerdictAction
    reason_code: str
    content: str


@dataclass(frozen=True, slots=True)
class DefenseVerdict:
    defense_id: str
    stage: DefenseStage
    action: VerdictAction
    reason_code: str
    latency_ms: float


class Defense(Protocol):
    id: str
    stage: DefenseStage

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision: ...
