"""Showdown — run every attack against every defense level and print the grid.

Each cell = how many of N runs leaked the flag (scored by the recoverability
oracle, so typo'd / reversed / obfuscated leaks still count). This is the
attack-class x defense matrix that is the project's central deliverable, in
miniature, for App #1.

Env knobs:
  GROQ_API_KEY   required
  GROQ_MODEL     optional, override the default model
  N              runs per cell (default 3) — ASR is a rate, not a single shot
  TEMP           temperature (default 0.4; leave some randomness so borderline
                 attacks reveal themselves)

Usage:  N=3 python matrix.py
"""
import os
import re
import time
import json

from attack import ATTEMPTS
from defenses import DEFENSE_LEVELS, build_bot, leaked

N = int(os.environ.get("N", "3"))
API_KEY = os.environ.get("GROQ_API_KEY")
MODEL = os.environ.get("GROQ_MODEL") or None
TEMP = float(os.environ.get("TEMP", "0.4"))
PACE = float(os.environ.get("PACE", "0.5"))     # seconds between calls
LEVELS = os.environ.get("LEVELS")               # e.g. "D0" or "D0,D4,D6"


def _short(name):
    """'6. output-mutation (typo)' -> 'output-mutation'."""
    name = re.sub(r"^\d+\.\s*", "", name)
    return name.split(" (")[0][:18]


def run():
    if not API_KEY:
        raise SystemExit("export GROQ_API_KEY=... first")

    levels = DEFENSE_LEVELS
    if LEVELS:
        keep = set(LEVELS.split(","))
        levels = [d for d in DEFENSE_LEVELS if d[0].split()[0] in keep]

    attacks = [(_short(n), p) for (n, _d, p) in ATTEMPTS]
    codes = [d[0].split()[0] for d in levels]
    total = len(attacks) * len(levels) * N
    print(f"Running {len(attacks)} attacks x {len(levels)} defenses x "
          f"N={N}  ->  up to {total} requests (temp={TEMP}, pace={PACE}s)\n")

    grid = {}
    errors = 0  # API failures — must NOT be miscounted as defended attacks
    for aname, payload in attacks:
        for dname, opts in levels:
            leaks = 0
            for _ in range(N):
                reply = build_bot(opts, API_KEY, MODEL, TEMP).ask(payload)
                if reply.startswith("[API ERROR"):
                    errors += 1
                elif leaked(reply):
                    leaks += 1
                time.sleep(PACE)
            grid[(aname, dname)] = leaks
        row = "".join(f"{grid[(aname, d[0])]}/{N}".rjust(7) for d in levels)
        print(f"  {aname:18}{row}")

    # --- final grid ----------------------------------------------------------
    print("\n" + "=" * (20 + 7 * len(codes)))
    print("SHOWDOWN MATRIX  (leaks out of N; lower = defense winning)\n")
    print("ATTACK".ljust(20) + "".join(c.rjust(7) for c in codes))
    for aname, _ in attacks:
        row = aname.ljust(20)
        for d in levels:
            row += f"{grid[(aname, d[0])]}/{N}".rjust(7)
        print(row)

    print("\nDefense legend:")
    for label, opts in levels:
        print(f"  {label:14} {opts if opts else '(baseline)'}")

    # --- data-quality guard --------------------------------------------------
    if errors:
        print(f"\n*** WARNING: {errors} API errors (likely rate-limit 429s). "
              f"These are NOT counted as leaks, but they mean some cells saw "
              f"fewer than N real attempts. Re-run with a smaller set or higher "
              f"PACE for trustworthy numbers. ***")
    else:
        print("\nNo API errors — every cell got N real attempts.")

    # --- who survives the strongest tested defense --------------------------
    max_label = levels[-1][0]
    survivors = [a for a, _ in attacks if grid[(a, max_label)] > 0]
    print(f"Survives {max_label}: "
          + (", ".join(survivors) if survivors else "none — all attacks stopped"))

    out = os.path.join(os.path.dirname(__file__), "matrix_results.json")
    with open(out, "w") as f:
        json.dump({f"{a}|{d}": v for (a, d), v in grid.items()},
                  f, indent=2)
    print(f"\nSaved raw counts to {out}")


if __name__ == "__main__":
    run()
