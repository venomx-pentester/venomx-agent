"""
Base Tool Wrapper
Abstract class for all security tool integrations
"""

from abc import ABC, abstractmethod
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import subprocess
import shlex
import json


class ToolStatus(Enum):
    """Tool execution status"""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "unauthorized"
    SANITIZATION_FAILED = "sanitization_failed"


@dataclass
class ToolResult:
    """
    Standardized result format for all tools
    """
    tool_name: str
    status: ToolStatus
    output: str
    error: str = ""
    exit_code: int = 0
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    raw_command: str = ""
    sanitized_command: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp.isoformat(),
            "raw_command": self.raw_command,
            "sanitized_command": self.sanitized_command,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    def is_success(self) -> bool:
        """Check if execution was successful"""
        return self.status == ToolStatus.SUCCESS


class BaseTool(ABC):
    """
    Abstract base class for all security tools

    Provides:
    - Command execution with timeout
    - Output parsing
    - Error handling
    - Logging integration
    - IP whitelisting safety checks
    """

    def __init__(
        self,
        name: str,
        command: str,
        default_timeout: int = 300,
        requires_approval: bool = False,
        is_loud: bool = False
    ):
        self.name = name
        self.command = command  # Base command (e.g., "nmap", "nikto")
        self.default_timeout = default_timeout
        self.requires_approval = requires_approval
        self.is_loud = is_loud

    @abstractmethod
    def build_command(self, **kwargs) -> str:
        """
        Build the command string from parameters
        Must be implemented by each tool
        """
        pass

    @abstractmethod
    def parse_output(self, output: str) -> dict:
        """
        Parse tool output into structured data
        Must be implemented by each tool
        """
        pass

    def execute(
        self,
        timeout: Optional[int] = None,
        **kwargs
    ) -> ToolResult:
        """
        Execute the tool with given parameters

        Args:
            timeout: Command timeout in seconds (uses default if not specified)
            **kwargs: Tool-specific parameters matching schema

        Returns:
            ToolResult with execution details and parsed output
        """
        start_time = datetime.now()
        timeout = timeout or self.default_timeout

        try:
            # Build command
            raw_command = self.build_command(**kwargs)

            # Sanitize command (security layer)
            from ..parsers.sanitizer import CommandSanitizer
            sanitizer = CommandSanitizer()
            is_safe, sanitized_command, reason = sanitizer.sanitize(raw_command, self.name)

            if not is_safe:
                return ToolResult(
                    tool_name=self.name,
                    status=ToolStatus.SANITIZATION_FAILED,
                    output="",
                    error=f"Command failed sanitization: {reason}",
                    raw_command=raw_command,
                    sanitized_command=""
                )

            # Execute command
            result = subprocess.run(
                shlex.split(sanitized_command),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # Security: never use shell=True
            )

            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()

            # Parse output
            parsed_data = self.parse_output(result.stdout)

            # Determine status
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.FAILURE

            return ToolResult(
                tool_name=self.name,
                status=status,
                output=result.stdout,
                error=result.stderr,
                exit_code=result.returncode,
                execution_time=execution_time,
                raw_command=raw_command,
                sanitized_command=sanitized_command,
                metadata=parsed_data
            )

        except subprocess.TimeoutExpired:
            execution_time = (datetime.now() - start_time).total_seconds()
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.TIMEOUT,
                output="",
                error=f"Command timed out after {timeout} seconds",
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILURE,
                output="",
                error=f"Execution error: {str(e)}",
                execution_time=execution_time
            )

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """
        Validate parameters against tool schema
        Override for custom validation logic

        Returns:
            (is_valid, error_message)
        """
        # Base implementation - override for specific validation
        return True, ""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}')>"
