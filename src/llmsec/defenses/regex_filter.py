import re
from dataclasses import dataclass, field

from llmsec.defenses.base import (
    DefenseContext,
    DefenseDecision,
    DefenseStage,
    VerdictAction,
)


INJECTION_PATTERNS = (
    r"build key",
    r"system prompt",
    r"your (system )?instructions",
    r"the instructions",
    r"ignore .*instructions",
    r"new instructions?",
    r"system override",
    r"the secret\b",
    r"the flag\b",
    r"\breveal\b|\bexfiltrate\b|\bleak\b",
    r"characters?\b.{0,20}\b(before|inside|of|the key|the string)",
    r"list .{0,20}characters",
    r"originally (given|received)",
    r"repeat .{0,20}above",
    r"typo",
    r"\bthe key\b",
)


@dataclass(frozen=True, slots=True)
class RegexInputFilter:
    id: str = "input_regex_v1"
    stage: DefenseStage = DefenseStage.BEFORE_CONTEXT
    _patterns: tuple[re.Pattern[str], ...] = field(
        default_factory=lambda: tuple(
            re.compile(pattern, re.IGNORECASE) for pattern in INJECTION_PATTERNS
        ),
        repr=False,
    )

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        del context
        matched = next(
            (pattern.pattern for pattern in self._patterns if pattern.search(content)), None
        )
        if matched is not None:
            return DefenseDecision(
                action=VerdictAction.BLOCK,
                reason_code="input.regex.injection_detected",
                content="[INPUT BLOCKED]",
            )
        return DefenseDecision(
            action=VerdictAction.PASS,
            reason_code="input.regex.clean",
            content=content,
        )
