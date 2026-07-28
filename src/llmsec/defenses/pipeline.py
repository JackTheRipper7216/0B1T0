from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from time import perf_counter_ns

from llmsec.defenses.base import (
    Defense,
    DefenseContext,
    DefenseStage,
    DefenseVerdict,
    VerdictAction,
)

ModelCall = Callable[[str, str], Awaitable[str]]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    raw_model_output: str | None
    visible_output: str
    final_system_prompt: str
    final_user_input: str
    verdicts: tuple[DefenseVerdict, ...]
    model_called: bool
    blocked_stage: DefenseStage | None
    model_latency_ms: float

    @property
    def defense_latency_ms(self) -> float:
        return sum(verdict.latency_ms for verdict in self.verdicts)


class DefensePipeline:
    """Runs deterministic defense stages around exactly one model call."""

    def __init__(self, defenses: Sequence[Defense]) -> None:
        ids = [defense.id for defense in defenses]
        if len(ids) != len(set(ids)):
            raise ValueError("A defense variant may appear only once in a pipeline")
        self._defenses = tuple(defenses)

    async def execute(
        self,
        *,
        system_prompt: str,
        user_input: str,
        context: DefenseContext,
        model_call: ModelCall,
    ) -> PipelineResult:
        verdicts: list[DefenseVerdict] = []

        user_input, blocked = self._apply_stage(
            DefenseStage.BEFORE_CONTEXT,
            user_input,
            context,
            verdicts,
        )
        if blocked:
            return PipelineResult(
                raw_model_output=None,
                visible_output="[INPUT BLOCKED]",
                final_system_prompt=system_prompt,
                final_user_input=user_input,
                verdicts=tuple(verdicts),
                model_called=False,
                blocked_stage=DefenseStage.BEFORE_CONTEXT,
                model_latency_ms=0.0,
            )

        system_prompt, blocked = self._apply_stage(
            DefenseStage.BEFORE_MODEL,
            system_prompt,
            context,
            verdicts,
        )
        if blocked:
            return PipelineResult(
                raw_model_output=None,
                visible_output="[REQUEST BLOCKED]",
                final_system_prompt=system_prompt,
                final_user_input=user_input,
                verdicts=tuple(verdicts),
                model_called=False,
                blocked_stage=DefenseStage.BEFORE_MODEL,
                model_latency_ms=0.0,
            )

        model_started = perf_counter_ns()
        raw_model_output = await model_call(system_prompt, user_input)
        model_latency_ms = (perf_counter_ns() - model_started) / 1_000_000

        visible_output, blocked = self._apply_stage(
            DefenseStage.AFTER_MODEL,
            raw_model_output,
            context,
            verdicts,
        )
        if blocked and not visible_output.startswith("["):
            visible_output = "[OUTPUT BLOCKED]"

        return PipelineResult(
            raw_model_output=raw_model_output,
            visible_output=visible_output,
            final_system_prompt=system_prompt,
            final_user_input=user_input,
            verdicts=tuple(verdicts),
            model_called=True,
            blocked_stage=DefenseStage.AFTER_MODEL if blocked else None,
            model_latency_ms=model_latency_ms,
        )

    def _apply_stage(
        self,
        stage: DefenseStage,
        content: str,
        context: DefenseContext,
        verdicts: list[DefenseVerdict],
    ) -> tuple[str, bool]:
        for defense in self._defenses:
            if defense.stage != stage:
                continue
            started = perf_counter_ns()
            decision = defense.evaluate(content, context)
            latency_ms = (perf_counter_ns() - started) / 1_000_000
            verdicts.append(
                DefenseVerdict(
                    defense_id=defense.id,
                    stage=stage,
                    action=decision.action,
                    reason_code=decision.reason_code,
                    latency_ms=latency_ms,
                )
            )
            content = decision.content
            if decision.action == VerdictAction.BLOCK:
                return content, True
        return content, False
