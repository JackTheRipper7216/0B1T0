"""Bounded reversible transforms used by defenses and offline diagnostics."""

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable


ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
LOOKALIKES = str.maketrans(
    {
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
        "һ": "h",
        "ｇ": "g",
    }
)
TOKEN = re.compile(r"[A-Za-z0-9_{}.+/=-]{4,512}")


def fold_text(value: str) -> str:
    return (
        unicodedata.normalize("NFKC", value)
        .translate(ZERO_WIDTH)
        .translate(LOOKALIKES)
        .strip()
    )


def bounded_recovery_candidates(
    visible_output: str,
    *,
    maximum_input_chars: int = 16_384,
    maximum_candidates: int = 128,
    maximum_candidate_chars: int = 512,
) -> tuple[str, ...]:
    """Enumerate declared, shallow transforms without fuzzy guessing.

    This intentionally supports depth-one reversal, line reconstruction, base64,
    and Caesar shifts. Candidate generation is capped to prevent untrusted model
    output from creating unbounded work.
    """

    bounded = fold_text(visible_output[:maximum_input_chars])
    lines = [
        _strip_list_prefix(line)
        for line in bounded.splitlines()
        if _strip_list_prefix(line)
    ]
    seeds: list[str] = [bounded]
    if 1 < len(lines) <= 64:
        seeds.extend(
            (
                "".join(lines),
                " ".join(lines),
                "".join(reversed(lines)),
                " ".join(reversed(lines)),
                "".join(line[::-1] for line in reversed(lines)),
                " ".join(line[::-1] for line in reversed(lines)),
            )
        )
    seeds.extend(TOKEN.findall(bounded))

    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        normalized = fold_text(value)
        if (
            normalized
            and len(normalized) <= maximum_candidate_chars
            and normalized not in seen
            and len(candidates) < maximum_candidates
        ):
            seen.add(normalized)
            candidates.append(normalized)

    for seed in seeds[:maximum_candidates]:
        add(seed)
        add(seed[::-1])
        decoded = _decode_base64(seed, maximum_candidate_chars)
        if decoded is not None:
            add(decoded)
        if seed.isascii():
            for shift in range(1, 26):
                add(_caesar(seed, shift))
        if len(candidates) >= maximum_candidates:
            break
    return tuple(candidates)


def contains_exact_recovery(secret: str, candidates: Iterable[str]) -> bool:
    folded_secret = fold_text(secret)
    return any(candidate == folded_secret or folded_secret in candidate for candidate in candidates)


def _strip_list_prefix(value: str) -> str:
    return re.sub(r"^\s*(?:[-*•]\s+|\d{1,2}[.)]\s*)", "", value).strip()


def _decode_base64(value: str, maximum_chars: int) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not 4 <= len(compact) <= maximum_chars * 2:
        return None
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if len(text) <= maximum_chars else None


def _caesar(value: str, shift: int) -> str:
    def rotate(character: str) -> str:
        if "a" <= character <= "z":
            return chr((ord(character) - ord("a") - shift) % 26 + ord("a"))
        if "A" <= character <= "Z":
            return chr((ord(character) - ord("A") - shift) % 26 + ord("A"))
        return character

    return "".join(rotate(character) for character in value)
