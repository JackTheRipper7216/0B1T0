"""probe.py — fire ONE payload at ONE defense level and report the outcome.

This is the adaptive attacker's hands: it sends a single crafted message to a
defended SupportBot and prints back everything needed to decide the next move —
did the input filter block it, what did the model actually say, and did the
recoverability oracle score a leak.

The payload is read from a FILE (not argv) so long, multi-line, unicode-heavy
attacks survive the shell intact.

Usage:
  python probe.py path/to/payload.txt          # default level D6 (MAX)
  python probe.py path/to/payload.txt D4        # any level code from DEFENSE_LEVELS
  TEMP=0.2 python probe.py payload.txt D6        # override temperature
  HISTORY=hist.json python probe.py payload.txt D6   # stage prior turns first

HISTORY points at a JSON file: a list of {"role": "user"|"assistant",
"content": "..."} turns that are prepended as conversation history before the
final payload turn — this is how a multi-turn / context-poisoning attack is
staged (e.g. a faked prior assistant turn that already agreed to comply).

The key is read from GROQ_API_KEY in the environment, or from a .env file next
to this script (KEY=VALUE lines) so it never has to live in a command argument.
"""
import os
import sys
import json


def _load_dotenv():
    """Minimal .env loader (no dependency). Only sets vars not already set."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

from defenses import DEFENSE_LEVELS, build_bot, leaked, input_filter  # noqa: E402


def _opts_for(level_code):
    for label, opts in DEFENSE_LEVELS:
        if label.split()[0] == level_code:
            return label, opts
    raise SystemExit(f"unknown level {level_code!r}; "
                     f"choose from {[d[0].split()[0] for d in DEFENSE_LEVELS]}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: python probe.py <payload_file> [LEVEL]")
    payload_file = sys.argv[1]
    level_code = sys.argv[2] if len(sys.argv) > 2 else "D6"
    temp = float(os.environ.get("TEMP", "0.4"))

    with open(payload_file, encoding="utf-8") as f:
        payload = f.read()

    history = None
    hist_file = os.environ.get("HISTORY")
    if hist_file:
        with open(hist_file, encoding="utf-8") as f:
            history = json.load(f)

    label, opts = _opts_for(level_code)
    blocked_by_input = bool(opts.get("input")) and input_filter(payload)

    bot = build_bot(opts, os.environ.get("GROQ_API_KEY"), None, temp)
    reply = bot.ask(payload, history)
    did_leak = leaked(reply)

    print("=" * 70)
    print(f"LEVEL           : {label}   {opts}")
    print(f"TEMP            : {temp}")
    print(f"PAYLOAD chars   : {len(payload)}")
    print(f"HISTORY turns   : {len(history) if history else 0}")
    print(f"INPUT BLOCKED   : {'YES' if blocked_by_input else 'no'}")
    print(f"LEAKED (oracle) : {'*** YES ***' if did_leak else 'no'}")
    print("-" * 70)
    print("MODEL REPLY:")
    print(reply)
    print("=" * 70)


if __name__ == "__main__":
    main()
