"""Deliberately vulnerable application targets."""

from llmsec.targets.chatbot import ChatbotTarget, ChatbotTurnResult
from llmsec.targets.coding import CodingTarget
from llmsec.targets.common import TargetTurnResult
from llmsec.targets.factory import TargetRuntime, build_target
from llmsec.targets.pii import PiiTarget
from llmsec.targets.rag import RagTarget

__all__ = [
    "ChatbotTarget",
    "ChatbotTurnResult",
    "CodingTarget",
    "PiiTarget",
    "RagTarget",
    "TargetTurnResult",
    "TargetRuntime",
    "build_target",
]
