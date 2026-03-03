"""
VenomX Security Module
Prompt injection defense for the agent loop
"""

from .prompt_guard import PromptGuard, CanaryViolation, SanitizedOutput

__all__ = ["PromptGuard", "CanaryViolation", "SanitizedOutput"]
