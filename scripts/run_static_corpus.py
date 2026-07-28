"""Run and archive a bounded live static-corpus census without exposing keys."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from time import monotonic

from dotenv import dotenv_values

from llmsec.application.ports import ModelGateway, ModelRequest, ModelResponse
from llmsec.application.services import run_static_matrix
from llmsec.catalog import ATTACKS, PROVIDERS_BY_ID
from llmsec.infrastructure.providers import ModelGatewayError, build_model_gateway
from llmsec.infrastructure.run_archive import RunArchive
from llmsec.schemas import MatrixRunRequest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--targets",
        nargs="+",
        choices=("chatbot", "rag", "coding"),
        default=["chatbot", "rag", "coding"],
    )
    parser.add_argument("--provider", choices=tuple(PROVIDERS_BY_ID), default="groq")
    parser.add_argument("--model", default="openai/gpt-oss-120b")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--payloads", type=int, choices=range(1, 7), default=6)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--request-spacing",
        type=float,
        default=2.5,
        help="Minimum seconds between provider request starts.",
    )
    parser.add_argument("--rate-limit-retries", type=int, default=8)
    parser.add_argument("--progress-every", type=int, default=5)
    parser.add_argument(
        "--defense",
        action="append",
        dest="defenses",
        default=[],
        help="Defense column ID. Repeat for multiple columns; baseline is always included.",
    )
    args = parser.parse_args()
    if not 0 <= args.temperature <= 1:
        parser.error("--temperature must be between 0 and 1")
    if args.request_spacing < 0:
        parser.error("--request-spacing cannot be negative")
    return args


class RateAwareGateway:
    """Serialize calls, throttle starts, and retry only explicit HTTP 429 errors."""

    def __init__(
        self,
        gateway: ModelGateway,
        *,
        request_spacing: float,
        rate_limit_retries: int,
        progress_every: int,
    ) -> None:
        self.gateway = gateway
        self.provider_id = gateway.provider_id
        self.request_spacing = max(0.0, request_spacing)
        self.rate_limit_retries = max(0, rate_limit_retries)
        self.progress_every = max(1, progress_every)
        self._next_start = 0.0
        self._completed = 0
        self._lock = asyncio.Lock()

    async def complete(self, request: ModelRequest) -> ModelResponse:
        async with self._lock:
            for attempt in range(self.rate_limit_retries + 1):
                await asyncio.sleep(max(0.0, self._next_start - monotonic()))
                self._next_start = monotonic() + self.request_spacing
                try:
                    response = await self.gateway.complete(request)
                except ModelGatewayError as exc:
                    if "HTTP 429" not in str(exc) or attempt >= self.rate_limit_retries:
                        raise
                    await asyncio.sleep(max(self.request_spacing, 2**attempt))
                    continue
                self._completed += 1
                if self._completed % self.progress_every == 0:
                    print(
                        f"provider calls completed: {self._completed}",
                        file=sys.stderr,
                        flush=True,
                    )
                return response
        raise RuntimeError("unreachable rate-aware gateway state")


def credential(provider_id: str, env_file: Path) -> str:
    provider = PROVIDERS_BY_ID[provider_id]
    values = dotenv_values(env_file) if env_file.exists() else {}
    key = os.getenv(provider.credential_env, "").strip()
    if not key:
        key = str(values.get(provider.credential_env, "") or "").strip()
    if not key:
        raise SystemExit(
            f"Configure {provider.credential_env} in the process environment "
            f"or {env_file}; the key is never printed or archived"
        )
    return key


def static_families(target_id: str) -> list[str]:
    return [
        attack.id
        for attack in ATTACKS
        if attack.mode == "static" and target_id in attack.applicable_target_ids
    ]


async def run(args: argparse.Namespace) -> list[dict[str, object]]:
    gateway = RateAwareGateway(
        build_model_gateway(
            args.provider,
            credential(args.provider, args.env_file),
        ),
        request_spacing=args.request_spacing,
        rate_limit_retries=args.rate_limit_retries,
        progress_every=args.progress_every,
    )
    archive = RunArchive()
    summaries: list[dict[str, object]] = []
    for target_id in args.targets:
        request = MatrixRunRequest(
            target_id=target_id,
            attack_ids=static_families(target_id),
            model_ids=[f"{args.provider}:{args.model}"],
            defense_column_ids=args.defenses or ["baseline"],
            trials=args.payloads,
            temperature=args.temperature,
            max_wall_time_seconds=3_600,
        )
        result = await run_static_matrix(request, {args.provider: gateway})
        archive.save("static", result)
        successes = sum(trial.success for trial in result.trials)
        summaries.append(
            {
                "run_id": str(result.run_id),
                "target": target_id,
                "status": result.status,
                "families": len(request.attack_ids),
                "payloads_per_family": request.trials,
                "arms": result.total_arms,
                "successes": successes,
                "asr_percent": (
                    100 * successes / result.total_arms if result.total_arms else 0
                ),
                "target_calls": result.budget.target_calls,
                "input_tokens": result.budget.input_tokens,
                "output_tokens": result.budget.output_tokens,
            }
        )
    return summaries


def main() -> None:
    print(json.dumps(asyncio.run(run(parse_args())), indent=2))


if __name__ == "__main__":
    main()
