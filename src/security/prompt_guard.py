"""
Prompt Injection Guard
Defense-in-depth security layer protecting the VenomX agent loop from
malicious instructions embedded in tool output (SSH banners, HTTP headers,
nmap service strings, etc.)

Three layers:
  1. Pattern Stripping  - sanitize_for_llm() strips known injection patterns
                          and wraps output in explicit trust-boundary markers
  2. Per-Iteration Canary - unique UUID injected into system role only,
                            must be echoed back as first token of any tool decision
  3. Post-Response Intent Validation - LLM tool targets validated against scope
                                       before execution
"""

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class CanaryViolation(Exception):
    """
    Raised when an LLM response fails canary validation.
    Always halt-and-log - never retry on a canary failure.
    A retry gives an injected payload a second attempt.
    """
    pass


class ScopeViolation(Exception):
    """Raised when the LLM requests a tool call targeting an out-of-scope IP."""
    pass


@dataclass
class SanitizedOutput:
    """Result of sanitize_for_llm()"""
    tool_name: str
    sanitized_content: str          # Trust-boundary-wrapped, injection-stripped output
    raw_content: str                # Original pre-sanitization output (never sent to LLM)
    patterns_stripped: list[str]    # Names of patterns that matched and were removed
    was_modified: bool              # True if any stripping occurred


class PromptGuard:
    """
    Prompt injection defense for the VenomX agent loop.

    Usage in FunctionCallHandler.execute_function_call():
        guard = PromptGuard(audit_log_path=..., scope_cidrs=[...])

        # Layer 1 - before format_for_llm()
        sanitized = guard.sanitize_for_llm(raw_output, tool_name)

        # Layer 2 - inject canary into system message before LLM call
        system_msg_with_canary, canary = guard.inject_canary(system_message)

        # Layer 2 - validate canary after LLM responds
        guard.validate_canary(llm_response_text, canary)  # raises CanaryViolation on failure

        # Layer 3 - validate tool targets before execution
        guard.validate_scope(tool_name, arguments)  # raises ScopeViolation on out-of-scope
    """

    # Layer 1: Injection pattern definitions
    # Each entry: (compiled_regex, human_readable_name)
    INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'ignore\s+(previous|above|all)\s+instructions?', re.IGNORECASE), "ignore_instructions"),
        (re.compile(r'\bsystem\s*:', re.IGNORECASE), "system_prefix"),
        (re.compile(r'new\s+instructions?\s+(received|follow|below)', re.IGNORECASE), "new_instructions"),
        (re.compile(r'you\s+are\s+now\s+', re.IGNORECASE), "role_reassignment"),
        (re.compile(r'disregard\s+(all\s+)?(previous|prior|above)', re.IGNORECASE), "disregard_previous"),
        (re.compile(r'<\|.*?\|>', re.DOTALL), "llama_special_tokens"),
        (re.compile(r'\[INST\].*?\[/INST\]', re.DOTALL), "instruction_tags"),
        (re.compile(r'<s>.*?</s>', re.DOTALL), "sequence_tags"),
        (re.compile(r'###\s*(instruction|system|prompt)\s*:', re.IGNORECASE), "markdown_injection"),
        (re.compile(r'Human\s*:\s*|Assistant\s*:\s*', re.IGNORECASE), "conversation_role_spoofing"),
        (re.compile(r'curl\s+https?://', re.IGNORECASE), "exfil_curl"),
        (re.compile(r'POST\s+https?://', re.IGNORECASE), "exfil_http_post"),
        (re.compile(r'wget\s+https?://', re.IGNORECASE), "exfil_wget"),
    ]

    # Layer 3: Fields in tool arguments that contain target IPs/hosts
    TARGET_FIELDS = {"target", "host", "ip", "url", "destination", "address"}

    def __init__(
        self,
        audit_log_path: Optional[Path] = None,
        scope_cidrs: Optional[list[str]] = None,
        scope_ips: Optional[list[str]] = None,
        disable_canary: bool = False,
    ):
        """
        Args:
            audit_log_path: Path to audit.log for forensic writes.
                            If None, audit events are written to the logger only.
            scope_cidrs:    Allowed CIDR blocks (e.g. ["192.168.1.0/24"]).
                            If None, scope validation is skipped.
            scope_ips:      Explicit allowed IPs in addition to CIDRs.
            disable_canary: If True, canary injection and validation are skipped.
                            Use only in dev/test environments with small models that
                            do not reliably follow canary echo instructions.
                            Production deployments must leave this False.
        """
        self.audit_log_path = audit_log_path
        self.scope_cidrs = scope_cidrs or []
        self.scope_ips = set(scope_ips or [])
        self.disable_canary = disable_canary

        # Per-iteration state - replaced on each inject_canary() call
        self._current_canary: Optional[str] = None
        self._canary_iteration: int = 0

    # -------------------------------------------------------------------------
    # Layer 1: Pattern Stripping
    # -------------------------------------------------------------------------

    def sanitize_for_llm(self, raw_output: str, tool_name: str) -> SanitizedOutput:
        """
        Strip injection patterns from raw tool output and wrap in trust-boundary markers.

        The returned SanitizedOutput.sanitized_content is what gets passed to
        format_for_llm() - never the raw_content.

        Args:
            raw_output:  Raw stdout/output from the tool
            tool_name:   Name of the tool (nmap, nikto, hydra, etc.)

        Returns:
            SanitizedOutput with sanitized content and metadata about what was stripped
        """
        sanitized = raw_output
        patterns_stripped: list[str] = []

        for pattern, name in self.INJECTION_PATTERNS:
            if pattern.search(sanitized):
                patterns_stripped.append(name)
                # Replace match with a visible placeholder so the LLM sees
                # that something was removed (transparency > silent deletion)
                sanitized = pattern.sub(f"[REDACTED:{name}]", sanitized)

        was_modified = len(patterns_stripped) > 0

        if was_modified:
            self._audit(
                event="injection_pattern_stripped",
                tool=tool_name,
                patterns=patterns_stripped,
                raw_snippet=raw_output[:300],  # First 300 chars for forensics
            )
            logger.warning(
                "[PromptGuard] Stripped %d injection pattern(s) from %s output: %s",
                len(patterns_stripped), tool_name, patterns_stripped
            )

        # Wrap in explicit trust-boundary markers so the LLM model can
        # distinguish tool data from authoritative system instructions
        wrapped = (
            f"[TOOL OUTPUT - {tool_name.upper()}]\n"
            f"{sanitized}\n"
            f"[END TOOL OUTPUT - {tool_name.upper()}]"
        )

        return SanitizedOutput(
            tool_name=tool_name,
            sanitized_content=wrapped,
            raw_content=raw_output,
            patterns_stripped=patterns_stripped,
            was_modified=was_modified,
        )

    # -------------------------------------------------------------------------
    # Layer 2: Per-Iteration Canary Tokens
    # -------------------------------------------------------------------------

    def inject_canary(self, system_message: str, iteration: int) -> tuple[str, str]:
        """
        Generate a new UUID canary for this iteration and inject it into the
        system message.

        CRITICAL TIMING: Call this AFTER collecting tool output but BEFORE
        the LLM call. The canary must never appear in tool output context.

        The LLM is instructed to echo [CANARY: {uuid}] as the first token of
        any tool call decision. This makes replay attacks impossible - the
        canary is generated after tool output is collected, so a payload in
        tool output cannot know it in advance.

        Args:
            system_message: Base system prompt for this iteration
            iteration:      Current agent loop iteration number

        Returns:
            (modified_system_message, canary_token)
        """
        if self.disable_canary:
            return system_message, ""

        canary_uuid = uuid4().hex
        canary_token = f"[CANARY: {canary_uuid}]"

        self._current_canary = canary_token
        self._canary_iteration = iteration

        canary_instruction = (
            f"\n\n[SECURITY] Iteration {iteration} canary: {canary_token}\n"
            "You MUST begin any tool call decision with this exact canary token "
            "as your first output token. Do not include the canary in tool arguments. "
            "This token verifies response integrity."
        )

        return system_message + canary_instruction, canary_token

    def validate_canary(self, llm_response_text: str, expected_canary: str) -> None:
        """
        Validate that the LLM response echoes the expected canary token.

        On failure: halt-and-log. Never retry - a retry gives an injected
        payload a second attempt at canary exfiltration.

        Args:
            llm_response_text: The raw text of the LLM's response
            expected_canary:   The canary token returned by inject_canary()

        Raises:
            CanaryViolation: If the canary is missing or malformed
        """
        if self.disable_canary:
            return

        if expected_canary not in llm_response_text:
            self._audit(
                event="canary_violation",
                iteration=self._canary_iteration,
                expected_canary=expected_canary,
                raw_response=llm_response_text[:500],  # First 500 chars for forensics
            )
            logger.critical(
                "[PromptGuard] CANARY VIOLATION at iteration %d — halting agent. "
                "Raw response logged to audit log.",
                self._canary_iteration,
            )
            raise CanaryViolation(
                f"Canary token missing from LLM response at iteration {self._canary_iteration}. "
                "This may indicate prompt injection. Agent halted. See audit.log for full response."
            )

        logger.debug(
            "[PromptGuard] Canary validated at iteration %d.", self._canary_iteration
        )

    # -------------------------------------------------------------------------
    # Layer 3: Post-Response Intent Validation
    # -------------------------------------------------------------------------

    def validate_scope(self, tool_name: str, arguments: dict) -> None:
        """
        Validate that the target in a tool call is within the declared scope.

        Called BEFORE executing a tool call the LLM has decided on.
        Scope is checked at decision time, not just at execution time.

        Args:
            tool_name:  Name of the tool being called
            arguments:  Arguments the LLM is passing to the tool

        Raises:
            ScopeViolation: If any target field resolves to an out-of-scope IP
        """
        if not self.scope_cidrs and not self.scope_ips:
            # No scope configured - skip validation
            return

        for field_name, value in arguments.items():
            if field_name.lower() not in self.TARGET_FIELDS:
                continue
            if not isinstance(value, str):
                continue

            target = value.strip()
            if not self._is_in_scope(target):
                self._audit(
                    event="scope_violation",
                    tool=tool_name,
                    field=field_name,
                    target=target,
                    allowed_cidrs=self.scope_cidrs,
                    allowed_ips=list(self.scope_ips),
                )
                logger.critical(
                    "[PromptGuard] SCOPE VIOLATION — %s requested target '%s' "
                    "via field '%s', which is outside declared scope. Tool call blocked.",
                    tool_name, target, field_name
                )
                raise ScopeViolation(
                    f"Tool '{tool_name}' requested out-of-scope target '{target}' "
                    f"(field: '{field_name}'). Allowed scope: {self.scope_cidrs + list(self.scope_ips)}. "
                    "Tool call blocked."
                )

    def _is_in_scope(self, target: str) -> bool:
        """
        Check if a target IP/host string is within declared scope.

        Args:
            target: IP address or hostname string

        Returns:
            True if in scope or if scope is unconfigured
        """
        import ipaddress

        # Explicit IP whitelist
        if target in self.scope_ips:
            return True

        # CIDR range check
        try:
            target_ip = ipaddress.ip_address(target)
            for cidr in self.scope_cidrs:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            # target is a hostname, not a raw IP — allow through
            # (hostname resolution is outside the guard's scope)
            return True

        return False

    # -------------------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------------------

    def _audit(self, event: str, **kwargs) -> None:
        """
        Write a structured audit event to audit.log.

        Each entry is a single JSON line with a UTC timestamp.
        The audit log is append-only and is the forensic record for:
          - Injection patterns stripped from tool output
          - Canary violations (full LLM response included)
          - Scope violations

        Args:
            event:   Event type string
            **kwargs: Arbitrary key-value pairs to include in the log entry
        """
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }

        # Always log to Python logger
        logger.warning("[PromptGuard][AUDIT] %s", json.dumps(entry))

        # Write to audit.log if path configured
        if self.audit_log_path:
            try:
                self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.audit_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError as e:
                logger.error("[PromptGuard] Failed to write audit log: %s", e)
