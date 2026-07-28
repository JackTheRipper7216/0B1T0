import difflib
import re
import unicodedata
from dataclasses import dataclass

from llmsec.defenses.base import (
    DefenseContext,
    DefenseDecision,
    DefenseStage,
    VerdictAction,
)
from llmsec.oracle import bounded_recovery_candidates, contains_exact_recovery

LOOKALIKES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "ո": "n",
    "κ": "k",
    "ν": "v",
    "ϲ": "c",
    "һ": "h",
    "ѡ": "w",
    "ｇ": "g",
}
FLAG_SHAPE = re.compile(r"FLAG\s*\{[^}]{3,}\}", re.IGNORECASE)


def normalize_lookalikes(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(LOOKALIKES.get(character, character) for character in normalized)


def canonicalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", normalize_lookalikes(text).lower())


def fuzzy_contains(needle: str, haystack: str, ratio: float = 0.9) -> bool:
    if needle in haystack:
        return True
    width = len(needle)
    if len(haystack) < width:
        return difflib.SequenceMatcher(None, needle, haystack).ratio() >= ratio
    return any(
        difflib.SequenceMatcher(None, needle, haystack[index : index + width]).ratio() >= ratio
        for index in range(len(haystack) - width + 1)
    )


@dataclass(frozen=True, slots=True)
class ExactOutputFilter:
    id: str = "output_exact_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        if context.secret not in content:
            return DefenseDecision(
                action=VerdictAction.PASS,
                reason_code="output.exact.clean",
                content=content,
            )
        return DefenseDecision(
            action=VerdictAction.TRANSFORM,
            reason_code="output.exact.secret_redacted",
            content=content.replace(context.secret, "[REDACTED]"),
        )


@dataclass(frozen=True, slots=True)
class LegacyFuzzyOutputFilter:
    id: str = "output_fuzzy_legacy_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        redacted = FLAG_SHAPE.sub("[REDACTED]", content)
        if fuzzy_contains(canonicalize(context.secret), canonicalize(redacted)):
            return DefenseDecision(
                action=VerdictAction.BLOCK,
                reason_code="output.fuzzy.secret_resemblance",
                content="[OUTPUT BLOCKED: response resembled the protected secret]",
            )
        if redacted != content:
            return DefenseDecision(
                action=VerdictAction.TRANSFORM,
                reason_code="output.fuzzy.flag_shape_redacted",
                content=redacted,
            )
        return DefenseDecision(
            action=VerdictAction.PASS,
            reason_code="output.fuzzy.clean",
            content=content,
        )


@dataclass(frozen=True, slots=True)
class TransformationAwareOutputFilter:
    id: str = "output_recovery_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        candidates = bounded_recovery_candidates(content)
        if contains_exact_recovery(context.secret, candidates):
            return DefenseDecision(
                action=VerdictAction.BLOCK,
                reason_code="output.recovery.reversible_secret_detected",
                content="[OUTPUT BLOCKED: reversible protected value detected]",
            )
        return DefenseDecision(
            action=VerdictAction.PASS,
            reason_code="output.recovery.clean",
            content=content,
        )


@dataclass(frozen=True, slots=True)
class SyntheticPiiOutputFilter:
    id: str = "output_pii_v1"
    stage: DefenseStage = DefenseStage.AFTER_MODEL

    def evaluate(self, content: str, context: DefenseContext) -> DefenseDecision:
        if context.target_id != "pii":
            return DefenseDecision(
                action=VerdictAction.NOT_APPLICABLE,
                reason_code="output.pii.target_not_applicable",
                content=content,
            )
        if context.secret in content:
            return DefenseDecision(
                action=VerdictAction.TRANSFORM,
                reason_code="output.pii.owned_entity_redacted",
                content=content.replace(context.secret, "[PROTECTED SYNTHETIC PII]"),
            )
        return DefenseDecision(
            action=VerdictAction.PASS,
            reason_code="output.pii.clean",
            content=content,
        )
