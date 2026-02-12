"""
LLM Function Calling Module
Handles conversion between LLM function calls and tool executions
"""

from typing import Dict, Any, List, Optional, Callable
import json
from dataclasses import dataclass, asdict

from ..schemas.tool_schemas import get_all_schemas, get_tool_schema, is_restricted, is_loud
from ..tools import ToolFactory, ToolResult
from ..parsers.output_parser import OutputParser


@dataclass
class FunctionCall:
    """Represents an LLM function call"""
    name: str  # Tool name
    arguments: Dict[str, Any]  # Tool parameters
    call_id: Optional[str] = None  # Optional ID for tracking


@dataclass
class FunctionResponse:
    """Response from function execution"""
    call_id: Optional[str]
    name: str
    result: str  # Formatted result for LLM
    success: bool
    raw_result: Optional[ToolResult] = None


class FunctionCallHandler:
    """
    Handles LLM function calling for tool execution

    Workflow:
    1. LLM decides to call a tool (returns function call)
    2. Handler validates and executes the tool
    3. Handler formats result for LLM
    4. LLM receives result and continues reasoning
    """

    def __init__(
        self,
        approval_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
        verbose: bool = False
    ):
        """
        Args:
            approval_callback: Function to get human approval for restricted tools
                              Should return True if approved, False otherwise
            verbose: Enable verbose logging
        """
        self.tool_factory = ToolFactory()
        self.output_parser = OutputParser()
        self.approval_callback = approval_callback
        self.verbose = verbose

        # Track execution history
        self.execution_history: List[FunctionResponse] = []

    def get_tool_schemas_for_llm(self) -> List[Dict[str, Any]]:
        """
        Get all tool schemas formatted for LLM function calling

        Returns:
            List of tool schemas in LLM-compatible format
        """
        return get_all_schemas()

    def parse_llm_function_call(self, llm_response: Dict[str, Any]) -> Optional[FunctionCall]:
        """
        Parse function call from LLM response

        Supports two formats:
        1. OpenAI-style: {"function_call": {"name": "...", "arguments": "..."}}
        2. Anthropic/Claude-style: {"tool_use": {"name": "...", "input": {...}}}

        Args:
            llm_response: Raw LLM response containing function call

        Returns:
            FunctionCall object or None if no function call present
        """
        # OpenAI format
        if "function_call" in llm_response:
            fc = llm_response["function_call"]
            name = fc.get("name")
            arguments = fc.get("arguments")

            # Arguments might be JSON string
            if isinstance(arguments, str):
                arguments = json.loads(arguments)

            return FunctionCall(
                name=name,
                arguments=arguments,
                call_id=llm_response.get("id")
            )

        # Claude/Anthropic format
        elif "tool_use" in llm_response:
            tool_use = llm_response["tool_use"]
            return FunctionCall(
                name=tool_use.get("name"),
                arguments=tool_use.get("input", {}),
                call_id=tool_use.get("id")
            )

        # Llama 3.3 format (JSON mode)
        elif "name" in llm_response and "arguments" in llm_response:
            return FunctionCall(
                name=llm_response["name"],
                arguments=llm_response["arguments"]
            )

        return None

    def execute_function_call(self, function_call: FunctionCall) -> FunctionResponse:
        """
        Execute a function call from the LLM

        Args:
            function_call: Parsed function call

        Returns:
            FunctionResponse with execution results
        """
        tool_name = function_call.name
        arguments = function_call.arguments

        if self.verbose:
            print(f"[FunctionCall] Executing {tool_name} with args: {arguments}")

        # Check if tool exists
        tool = self.tool_factory.get_tool(tool_name)
        if not tool:
            error_msg = f"Error: Tool '{tool_name}' not found. Available tools: {self.tool_factory.list_tools()}"
            return FunctionResponse(
                call_id=function_call.call_id,
                name=tool_name,
                result=error_msg,
                success=False
            )

        # Check if tool requires approval
        if is_restricted(tool_name):
            if self.approval_callback:
                approved = self.approval_callback(tool_name, arguments)
                if not approved:
                    return FunctionResponse(
                        call_id=function_call.call_id,
                        name=tool_name,
                        result=f"Execution denied. Tool '{tool_name}' requires human approval.",
                        success=False
                    )
            else:
                # No approval callback - deny by default
                return FunctionResponse(
                    call_id=function_call.call_id,
                    name=tool_name,
                    result=f"Execution denied. Tool '{tool_name}' requires human approval but no approval mechanism configured.",
                    success=False
                )

        # Warn if tool is loud
        if is_loud(tool_name) and self.verbose:
            print(f"[WARNING] Tool '{tool_name}' is loud and will generate significant network traffic")

        # Execute tool
        try:
            result: ToolResult = tool.execute(**arguments)

            # Parse output
            parsed = self.output_parser.parse(
                tool_name=tool_name,
                raw_output=result.output,
                metadata=result.metadata
            )

            # Format for LLM
            formatted_result = self.output_parser.format_for_llm(parsed)

            # Create response
            response = FunctionResponse(
                call_id=function_call.call_id,
                name=tool_name,
                result=formatted_result,
                success=result.is_success(),
                raw_result=result
            )

            # Track execution
            self.execution_history.append(response)

            return response

        except Exception as e:
            error_msg = f"Error executing {tool_name}: {str(e)}"
            if self.verbose:
                print(f"[ERROR] {error_msg}")

            return FunctionResponse(
                call_id=function_call.call_id,
                name=tool_name,
                result=error_msg,
                success=False
            )

    def format_function_response_for_llm(self, response: FunctionResponse) -> Dict[str, Any]:
        """
        Format function response for LLM consumption

        Returns:
            Dictionary in LLM-expected format
        """
        return {
            "role": "tool" if response.call_id else "function",
            "name": response.name,
            "content": response.result,
            "tool_call_id": response.call_id
        }

    def clear_history(self):
        """Clear execution history"""
        self.execution_history.clear()

    def get_execution_summary(self) -> str:
        """Get summary of all executions in this session"""
        if not self.execution_history:
            return "No tools executed yet."

        summary_lines = ["=== Execution History ===\n"]
        for i, resp in enumerate(self.execution_history, 1):
            status = "✓" if resp.success else "✗"
            summary_lines.append(f"{i}. {status} {resp.name}")

        return "\n".join(summary_lines)


# Example approval callback (interactive)
def interactive_approval(tool_name: str, arguments: Dict[str, Any]) -> bool:
    """
    Interactive approval for restricted tools

    Args:
        tool_name: Name of the tool
        arguments: Tool arguments

    Returns:
        True if approved, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"APPROVAL REQUIRED: {tool_name}")
    print(f"{'='*60}")
    print(f"Arguments: {json.dumps(arguments, indent=2)}")
    print(f"{'='*60}")

    while True:
        response = input("Approve execution? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("Please enter 'yes' or 'no'")