"""
VenomX Security Module
Prompt injection defense for the agent loop
"""

from .prompt_guard import CanaryViolation, PromptGuard, SanitizedOutput, ScopeViolation

__all__ = ["PromptGuard", "CanaryViolation", "ScopeViolation", "SanitizedOutput"]
