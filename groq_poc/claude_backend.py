"""claude_backend.py — run the SAME target/defenses on an Anthropic model.

The reversal-capability wall we hit against llama-3.3-70b is a property of the
*model*, not of the defenses. To test "would a more capable model beat D6's
fuzzy output filter (whose only gap is a clean reversal)?" we swap ONLY the
underlying model and keep every defense byte-for-byte identical.

No new dependency: this hits Anthropic's /v1/messages HTTP endpoint with
`requests`, exactly like chatbot.py hits Groq. It subclasses SupportBot so the
input filter, output filter, system prompt wiring, and the ask() flow are
reused unchanged — the only override is _complete() (the actual API call).

Key handling: reads CLAUDE_API_KEY (or ANTHROPIC_API_KEY) from the environment
(.env is auto-loaded by the harness). The key is never placed in a payload,
argument, or log.
"""
import os
import time
import requests

from chatbot import SupportBot, SYSTEM_PROMPT

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

# Default to the most capable current model — the hardest, most honest test of
# the "a capable model beats D6" hypothesis. Override with CLAUDE_MODEL.
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-4-8")


class ClaudeBot(SupportBot):
    """SupportBot whose _complete() calls the Anthropic Messages API."""

    def __init__(self, temperature=0.2, input_filter=None, output_filter=None,
                 api_key=None, model=None, system_prompt=None, max_tokens=1024):
        self.api_key = (api_key or os.environ.get("CLAUDE_API_KEY")
                        or os.environ.get("ANTHROPIC_API_KEY"))
        if not self.api_key:
            raise SystemExit(
                "Set CLAUDE_API_KEY in groq_poc/.env  (CLAUDE_API_KEY=sk-ant-...)"
            )
        self.model = model or CLAUDE_MODEL
        self.temperature = temperature
        self.input_filter = input_filter
        self.output_filter = output_filter
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        self.max_tokens = max_tokens

    def _complete(self, messages, max_retries=6):
        # Anthropic takes the system prompt as a separate field, not a message.
        system = ""
        conv = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                conv.append({"role": m["role"], "content": m["content"]})

        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": conv,
        }
        # Some newer models (e.g. Opus 4.8) deprecate `temperature`; only send it
        # if set, and strip-and-retry if the API rejects it.
        if self.temperature is not None:
            body["temperature"] = self.temperature

        for attempt in range(max_retries):
            resp = requests.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=body,
                timeout=90,
            )
            if resp.status_code == 200:
                data = resp.json()
                parts = [b.get("text", "") for b in data.get("content", [])
                         if b.get("type") == "text"]
                return "".join(parts)

            # Model rejects `temperature` — drop it and retry once.
            if resp.status_code == 400 and "temperature" in resp.text \
                    and "temperature" in body:
                body.pop("temperature", None)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                retry_after = resp.headers.get("retry-after")
                wait = float(retry_after) if retry_after else min(2 ** attempt, 30)
                time.sleep(wait + 0.5)
                continue

            return f"[API ERROR {resp.status_code}] {resp.text[:300]}"

        return "[API ERROR 429] rate limited: exhausted retries"


def build_claude_bot(opts, api_key=None, model=None, temperature=0.2):
    """Mirror of defenses.build_bot(), but backed by ClaudeBot.

    Imported here (not at top) so a missing key doesn't break `import`.
    """
    from defenses import HARDENED_SYSTEM_PROMPT, input_filter, _OUTPUT_FILTERS
    return ClaudeBot(
        api_key=api_key,
        model=model,
        temperature=temperature,
        system_prompt=HARDENED_SYSTEM_PROMPT if opts.get("harden") else None,
        input_filter=input_filter if opts.get("input") else None,
        output_filter=_OUTPUT_FILTERS.get(opts.get("output")),
    )
