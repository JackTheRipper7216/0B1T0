"""Deterministic success oracles."""

from llmsec.oracle.candidates import bounded_recovery_candidates, contains_exact_recovery
from llmsec.oracle.recovery import (
    CHATBOT_FLAG,
    RecoveryOracle,
    generate_campaign_canary,
    generate_target_secret,
)

__all__ = [
    "CHATBOT_FLAG",
    "RecoveryOracle",
    "bounded_recovery_candidates",
    "contains_exact_recovery",
    "generate_campaign_canary",
    "generate_target_secret",
]
