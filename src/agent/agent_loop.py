"""
VenomX Agent Loop
Orchestrates LLM reasoning and tool execution for penetration testing
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

from .function_calling import FunctionCallHandler, FunctionCall, FunctionResponse


class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"
    REASONING = "reasoning"
    TOOL_EXECUTION = "tool_execution"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class AgentMessage:
    """Single message in agent conversation"""
    role: str  # "user", "assistant", "system", "tool"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentContext:
    """
    Agent execution context
    Maintains conversation history and state
    """
    messages: List[AgentMessage] = field(default_factory=list)
    state: AgentState = AgentState.IDLE
    max_iterations: int = 10  # Prevent infinite loops
    current_iteration: int = 0
    target_network: Optional[str] = None
    excluded_ips: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None):
        """Add message to context"""
        msg = AgentMessage(
            role=role,
            content=content,
            metadata=metadata or {}
        )
        self.messages.append(msg)

    def get_conversation_history(self) -> List[Dict[str, str]]:
        """Get conversation in LLM-compatible format"""
        return [
            {"role": msg.role, "content": msg.content}
            for msg in self.messages
        ]

    def should_continue(self) -> bool:
        """Check if agent should continue execution"""
        return (
            self.current_iteration < self.max_iterations
            and self.state not in [AgentState.COMPLETE, AgentState.ERROR]
        )


class VenomXAgent:
    """
    VenomX Pentesting Agent

    Implements the agent loop:
    1. Receive user instruction
    2. LLM reasons about task
    3. LLM decides on tool to use (function calling)
    4. Execute tool
    5. LLM analyzes results
    6. Repeat or respond to user
    """

    SYSTEM_PROMPT = """You are VenomX, an AI-powered penetration testing assistant.

You help security professionals conduct authorized penetration tests in isolated lab environments.

CRITICAL RULES:
1. Only scan/attack systems in the designated network range
2. Always respect IP exclusion lists
3. Request human approval before executing restricted tools (hydra, sqlmap, metasploit)
4. Provide clear explanations for your decisions
5. Suggest next steps based on findings

WORKFLOW:
1. Understand the user's goal
2. Plan your approach (reconnaissance → enumeration → vulnerability analysis → exploitation)
3. Use tools methodically and analyze results
4. Provide clear reports of findings
5. Suggest remediation strategies

AVAILABLE TOOLS:
- nmap: Network scanning, port enumeration, service detection
- nikto: Web server vulnerability scanning
- gobuster: Directory/file brute-forcing
- hydra: Authentication brute-forcing (REQUIRES APPROVAL)
- sqlmap: SQL injection testing (REQUIRES APPROVAL)
- searchsploit: Search exploit database
- metasploit: Exploit framework (REQUIRES APPROVAL)

Remember: This is for authorized testing in a controlled environment only."""

    def __init__(
        self,
        llm_client: Any,  # LLM client (Ollama, OpenAI, Anthropic, etc.)
        approval_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
        verbose: bool = True
    ):
        """
        Args:
            llm_client: LLM client for making inference calls
            approval_callback: Function for human-in-the-loop approval
            verbose: Enable verbose logging
        """
        self.llm_client = llm_client
        self.function_handler = FunctionCallHandler(
            approval_callback=approval_callback,
            verbose=verbose
        )
        self.verbose = verbose
        self.context = AgentContext()

        # Initialize context with system prompt
        self.context.add_message("system", self.SYSTEM_PROMPT)

    def run(self, user_input: str, **kwargs) -> str:
        """
        Execute agent loop with user input

        Args:
            user_input: User's instruction/query
            **kwargs: Additional context (target_network, excluded_ips, etc.)

        Returns:
            Agent's final response
        """
        # Update context with user input
        self.context.add_message("user", user_input)

        # Set target network and exclusions if provided
        if "target_network" in kwargs:
            self.context.target_network = kwargs["target_network"]
        if "excluded_ips" in kwargs:
            self.context.excluded_ips = kwargs["excluded_ips"]

        # Main agent loop
        while self.context.should_continue():
            self.context.current_iteration += 1
            self.context.state = AgentState.REASONING

            if self.verbose:
                print(f"\n[Agent] Iteration {self.context.current_iteration}/{self.context.max_iterations}")

            # Get LLM response
            try:
                llm_response = self._call_llm()

                # Check if LLM wants to call a tool
                function_call = self.function_handler.parse_llm_function_call(llm_response)

                if function_call:
                    # Execute tool
                    self.context.state = AgentState.TOOL_EXECUTION
                    if self.verbose:
                        print(f"[Agent] Calling tool: {function_call.name}")

                    response = self.function_handler.execute_function_call(function_call)

                    # Add tool result to context
                    tool_message = self.function_handler.format_function_response_for_llm(response)
                    self.context.add_message(
                        role=tool_message["role"],
                        content=tool_message["content"],
                        metadata={"tool_name": function_call.name}
                    )

                    # Continue loop to let LLM analyze results
                    continue

                else:
                    # No function call - LLM is responding to user
                    assistant_response = self._extract_text_response(llm_response)
                    self.context.add_message("assistant", assistant_response)

                    # Check if task is complete
                    if self._is_task_complete(assistant_response):
                        self.context.state = AgentState.COMPLETE
                        return assistant_response
                    else:
                        # LLM provided response but may need more interaction
                        return assistant_response

            except Exception as e:
                self.context.state = AgentState.ERROR
                error_msg = f"Error in agent loop: {str(e)}"
                if self.verbose:
                    print(f"[ERROR] {error_msg}")
                return error_msg

        # Max iterations reached
        if self.context.current_iteration >= self.context.max_iterations:
            return "Maximum iterations reached. Task may be incomplete. Please review findings and continue manually if needed."

        return "Agent loop exited unexpectedly."

    def _call_llm(self) -> Dict[str, Any]:
        """
        Call LLM with current context

        Returns:
            LLM response (format depends on client)
        """
        # Get conversation history
        messages = self.context.get_conversation_history()

        # Get tool schemas for function calling
        tools = self.function_handler.get_tool_schemas_for_llm()

        # Call LLM (implementation depends on client)
        # This is a placeholder - actual implementation depends on LLM client
        response = self.llm_client.chat(
            messages=messages,
            tools=tools,
            temperature=0.7
        )

        return response

    def _extract_text_response(self, llm_response: Dict[str, Any]) -> str:
        """Extract text content from LLM response"""
        # Handle different LLM response formats
        if isinstance(llm_response, str):
            return llm_response

        # OpenAI format
        if "choices" in llm_response:
            return llm_response["choices"][0]["message"]["content"]

        # Claude format
        if "content" in llm_response:
            content = llm_response["content"]
            if isinstance(content, list):
                # Extract text blocks
                return "\n".join([
                    block.get("text", "")
                    for block in content
                    if block.get("type") == "text"
                ])
            return str(content)

        # Fallback
        return str(llm_response)

    def _is_task_complete(self, response: str) -> bool:
        """
        Determine if agent has completed the task

        Uses heuristics to detect completion
        """
        completion_indicators = [
            "task complete",
            "scan complete",
            "findings summary",
            "recommendations:",
            "no further action",
            "have completed"
        ]

        response_lower = response.lower()
        return any(indicator in response_lower for indicator in completion_indicators)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from execution"""
        findings = []
        for response in self.function_handler.execution_history:
            if response.raw_result and response.raw_result.metadata:
                findings.append({
                    "tool": response.name,
                    "timestamp": response.raw_result.timestamp.isoformat(),
                    "data": response.raw_result.metadata
                })
        return findings

    def reset(self):
        """Reset agent to initial state"""
        self.context = AgentContext()
        self.context.add_message("system", self.SYSTEM_PROMPT)
        self.function_handler.clear_history()


# Example LLM client adapter (for Ollama)
class OllamaClient:
    """Simple Ollama client adapter"""

    def __init__(self, model: str = "llama3.3:70b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def chat(self, messages: List[Dict[str, str]], tools: List[Dict], temperature: float = 0.7) -> Dict[str, Any]:
        """
        Call Ollama chat API

        Note: This is a simplified implementation
        Full implementation would use requests library and handle tool calling properly
        """
        import requests

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "temperature": temperature,
            "stream": False
        }

        response = requests.post(f"{self.base_url}/api/chat", json=payload)
        return response.json()
