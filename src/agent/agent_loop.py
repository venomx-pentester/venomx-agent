"""
VenomX Agent Loop
Orchestrates LLM reasoning and tool execution for penetration testing
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ..graph.attack_path import AttackPathFinder
from ..graph.finding_graph import FindingGraph
from ..security.prompt_guard import CanaryViolation, PromptGuard
from ..utils.session import Session, new_session
from .credential_store import CredentialStore
from .function_calling import FunctionCallHandler


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
    max_iterations: int = 20  # Prevent infinite loops
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

    SYSTEM_PROMPT = """You are VenomX, an autonomous penetration testing agent.
Execute the given objective by calling tools in sequence. Do NOT describe what you plan to do — call the tool.

WORKFLOW: reconnaissance → enumeration → vuln analysis → exploitation → summarize

TOOLS (use EXACT enum values — wrong values are rejected):
nmap: target*(IP/CIDR), scan_type*(ping_sweep|port_scan|service_scan|os_detection|aggressive|stealth), ports, timing(0-5)
nikto: target*(URL/IP), port(80), ssl(false), tuning(all|interesting|misconfig|info_disclosure|injection|xss)
gobuster: target*(URL), wordlist(common|medium|large|api|admin), extensions(["php","html"]), threads(1-50)
hydra[APPROVAL]: target*, service*(ssh|ftp|http-get|http-post|rdp|mysql|postgres), username, username_list(common|top100|default), password_list(common|rockyou-100|default|weak), port, threads(1-16)
sqlmap[APPROVAL]: target*(URL?param), method(GET|POST), data, level(1-5), risk(1-3), enumerate([dbs,tables,columns,users,passwords,current-user])
searchsploit: query*(e.g. "OpenSSH 7.4"), strict(false), platform(linux|windows|multiple|php|hardware)
metasploit[APPROVAL]: exploit*(module path), target*(IP), lhost*(attacker IP), port, payload, lport(4444)
(* = required)

RULES:
- One tool call per response
- HTTP/HTTPS port found → run nikto then gobuster
- SSH/FTP/RDP found → run hydra
- Service version found → run searchsploit
- If [TOOL FAILED]: fix the parameter and retry
- Only write a text summary when ALL relevant tools have been called

TOOL CALL FORMAT — your entire response must be ONLY this JSON:
{"name": "<tool>", "arguments": {<params>}}

FINAL SUMMARY FORMAT (max 150 words):
Findings: <severities + services>
Exploits: <CVEs/searchsploit hits or "none">
Recommended next steps: <1-3 actions>"""

    def __init__(
        self,
        llm_client: Any,  # LLM client (Ollama, OpenAI, Anthropic, etc.)
        approval_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
        verbose: bool = True,
        session: Optional[Session] = None,
        scope_cidrs: Optional[List[str]] = None,
        disable_canary: bool = False,
    ):
        """
        Args:
            llm_client:        LLM client for making inference calls
            approval_callback: Function for human-in-the-loop approval
            verbose:           Enable verbose logging
            session:           Session object for persistence.
                               If None, a new in-memory-only session is created.
            scope_cidrs:       CIDR blocks declaring the allowed target scope.
                               Passed to PromptGuard for Layer 3 validation.
            disable_canary:    If True, skip canary injection and validation.
                               Use only in dev/test with models that don't support
                               canary echo (e.g. qwen2.5:3b). Default False.
        """
        self.llm_client = llm_client
        self.verbose = verbose

        # Session: single source of truth for all file paths
        self.session = session or new_session()

        # Security: PromptGuard with audit log and scope enforcement
        self.prompt_guard = PromptGuard(
            audit_log_path=self.session.audit_log_path,
            scope_cidrs=scope_cidrs or [],
            scope_ips=list(self.session.target_network.split(",")) if self.session.target_network else [],
            disable_canary=disable_canary,
        )

        # Stateful memory modules
        self.credential_store = CredentialStore(
            session_id=self.session.session_id,
            persist_path=self.session.credentials_path,
        )
        self.graph = FindingGraph(
            session_id=self.session.session_id,
            wal_path=self.session.wal_path,
            json_path=self.session.graph_json_path,
        )
        self.path_finder = AttackPathFinder(self.graph)

        self.function_handler = FunctionCallHandler(
            approval_callback=approval_callback,
            verbose=verbose,
            prompt_guard=self.prompt_guard,
        )
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

            # Inject stateful context into system message for this iteration:
            #   - Graph summary (all discovered hosts, services, vulns)
            #   - Attack path summary (complete and partial chains)
            #   - Credential summary (all known creds, validated first)
            self._inject_iteration_context()

            # Get LLM response
            try:
                # Layer 2: Generate per-iteration canary AFTER tool output is
                # collected, BEFORE the LLM call. The canary is injected into
                # the system role only - never in tool output context.
                current_system = self.context.messages[0].content
                system_with_canary, canary = self.prompt_guard.inject_canary(
                    current_system, self.context.current_iteration
                )
                # Temporarily override system message for this LLM call
                self.context.messages[0].content = system_with_canary

                llm_response = self._call_llm()

                # Restore original system message (canary is per-iteration only)
                self.context.messages[0].content = current_system

                response_text = self._extract_text_response(llm_response)

                # Check if LLM wants to call a tool (before canary validation,
                # because tool call responses carry no text to embed a canary in)
                function_call = self.function_handler.parse_llm_function_call(llm_response)

                # Layer 2: Validate canary on TEXT responses only.
                # Tool call responses are structured JSON - the model has no place
                # to echo a canary token. Scope validation (Layer 3) covers tool calls.
                if not function_call:
                    try:
                        self.prompt_guard.validate_canary(response_text, canary)
                    except CanaryViolation as e:
                        self.context.state = AgentState.ERROR
                        return f"[SECURITY HALT] {str(e)}"

                if function_call:
                    # Execute tool
                    self.context.state = AgentState.TOOL_EXECUTION
                    if self.verbose:
                        print(f"[Agent] Calling tool: {function_call.name}")

                    response = self.function_handler.execute_function_call(function_call)

                    # Feed results into the graph (replaces ephemeral ParsedOutput)
                    if response.success and response.raw_result:
                        self._ingest_tool_result(function_call.name, response.raw_result.metadata)

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
                    # No function call - LLM produced a text response.
                    assistant_response = response_text
                    self.context.add_message("assistant", assistant_response)

                    # Only exit when the model signals it is truly done.
                    # If the response is intermediate planning text ("I found X,
                    # next I'll run Y"), add it to context and keep looping so
                    # the model can act on its own plan. Returning unconditionally
                    # here caused the agent to halt after the first tool call
                    # even when the model had more investigation to do.
                    if self._is_task_complete(assistant_response):
                        self.context.state = AgentState.COMPLETE
                        self._close_session()
                        return assistant_response
                    # Not a final summary — continue the loop
                    continue

            except CanaryViolation:
                # Already handled above, but catch here as a safety net
                self.context.state = AgentState.ERROR
                return "[SECURITY HALT] Canary validation failed. See audit.log."
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
        # Get conversation history with sliding window.
        # The AGENT STATE section in messages[0] already provides a structured
        # summary of all findings (graph + attack paths + credentials), so older
        # raw tool result messages are redundant once the state is injected.
        # Keeping only the last 4 tool results caps total input to ~600-700 tokens
        # which safely fits in the model's 4096-token architectural limit.
        messages = self._windowed_history(max_tool_messages=4)

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

    def _windowed_history(self, max_tool_messages: int = 4) -> List[Dict[str, str]]:
        """
        Return conversation history capped to the last max_tool_messages tool result
        messages to prevent context growth from overflowing the model's token limit.

        The graph state is already injected into messages[0] (the system prompt)
        on every iteration, so older raw tool result messages are redundant and
        only consume tokens.

        Structure returned:
            messages[0] - system prompt (with AGENT STATE injected)
            messages[1] - original user request
            messages[-max_tool_messages:] - most recent tool results
        """
        messages = self.context.get_conversation_history()
        if len(messages) <= 2:
            return messages
        system_msg = messages[0]
        user_msg = messages[1]
        history = messages[2:]
        if len(history) > max_tool_messages:
            history = history[-max_tool_messages:]
        return [system_msg, user_msg] + history

    def _extract_text_response(self, llm_response: Dict[str, Any]) -> str:
        """Extract text content from LLM response"""
        # Handle different LLM response formats
        if isinstance(llm_response, str):
            return llm_response

        # OpenAI format
        if "choices" in llm_response:
            message = (llm_response["choices"][0].get("message") or {})
            content = message.get("content") or ""
            # gpt-oss-20b sometimes outputs to "reasoning" instead of "content"
            # (content=null). Fall back so canary validation and tool parsing work.
            if not content:
                content = message.get("reasoning") or ""
            return content

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
            "have completed",
            # Matches the OUTPUT FORMAT prompt: "Recommended next steps:" section
            # and the model's markdown variant "next steps" heading, which only
            # appear in a final summary — not in intermediate planning text.
            "recommended next steps:",
            "next steps\n",
            "**next steps**",
        ]

        response_lower = response.lower()
        return any(indicator in response_lower for indicator in completion_indicators)

    def _inject_iteration_context(self) -> None:
        """
        Inject graph summary, attack path summary, and credential summary into
        a fresh context message at the start of each iteration.

        This replaces the pattern of the LLM re-deriving correlations from raw
        tool outputs scattered across the context window.
        """
        sections = []

        graph_summary = self.graph.summary_for_llm()
        if graph_summary:
            sections.append(graph_summary)

        path_summary = self.path_finder.summary_for_llm()
        if path_summary:
            sections.append(path_summary)

        cred_summary = self.credential_store.summary_for_llm()
        if cred_summary:
            sections.append(cred_summary)

        if sections:
            combined = "\n\n".join(sections)
            state_section = f"\n\n[AGENT STATE - Iteration {self.context.current_iteration}]\n{combined}"
            # Update messages[0] (the system prompt) in place instead of
            # appending a new "system" message.  Llama-3's chat template only
            # allows a system message at position 0; injecting system messages
            # mid-conversation causes a tokenizer error in vLLM
            # ("Unexpected token 13 while expecting start token 200006").
            # Rebuilding from SYSTEM_PROMPT also overwrites any previous state
            # injection, so state never accumulates across iterations.
            self.context.messages[0].content = self.SYSTEM_PROMPT + state_section

    def _ingest_tool_result(self, tool_name: str, metadata: dict) -> None:
        """
        Route a successful tool result into the appropriate graph ingestion method.
        This is the integration point that makes the graph stateful across iterations.

        Args:
            tool_name: Name of the tool that ran
            metadata:  Parsed metadata from the tool's parse_output()
        """
        if not metadata:
            return

        try:
            if tool_name == "nmap":
                created = self.graph.add_nmap_result(metadata)
                if self.verbose and created:
                    print(f"[Graph] nmap: added {len(created)} node(s)")

            elif tool_name == "searchsploit":
                created = self.graph.add_searchsploit_result(metadata)
                if self.verbose and created:
                    print(f"[Graph] searchsploit: added {len(created)} node(s)")

            elif tool_name == "hydra":
                added = self.credential_store.add_from_hydra_output(metadata)
                if self.verbose and added:
                    print(f"[CredentialStore] hydra: added {added} credential(s)")

            elif tool_name == "nikto":
                findings = metadata.get("findings", [])
                host = metadata.get("host", "")
                port = int(metadata.get("port", 80))
                if findings and host:
                    created = self.graph.add_nikto_result(findings, host, port)
                    if self.verbose and created:
                        print(f"[Graph] nikto: added {len(created)} vulnerability node(s)")

        except Exception as e:
            if self.verbose:
                print(f"[Graph] Failed to ingest {tool_name} result: {e}")

    def _close_session(self) -> None:
        """
        Checkpoint the graph on session close.
        graph.json is materialized here - guaranteeing Nick and Jordan's
        consumers have a current snapshot at the end of every session.
        """
        self.graph.checkpoint()
        if self.verbose:
            print(f"[Session] Closed. Graph checkpoint written. Session: {self.session.summary()}")

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


# LLM client adapter for vLLM (OpenAI-compatible API)
class VLLMClient:
    """
    vLLM client adapter

    vLLM serves an OpenAI-compatible API at /v1/chat/completions,
    so we use the standard OpenAI request format.

    vLLM advantages over Ollama:
    - PagedAttention for efficient memory management
    - Continuous batching for higher throughput
    - Better performance for large models (70B+)
    - Native support for tool/function calling
    """

    def __init__(
        self,
        model: str = "meta-llama/Llama-3.3-70B-Instruct",
        base_url: str = "http://localhost:8000",
        api_key: str = "EMPTY",  # vLLM doesn't require a real key by default
        use_tools_api: bool = False,  # Set True only for models with native tool_calls support.
                                      # gpt-oss-20b outputs tool args as JSON in content and
                                      # does NOT use tool_calls, so keep False.  Sending tools
                                      # causes vLLM to embed all schemas into the system message
                                      # via the Llama-3 tool-use chat template, which inflates the
                                      # system message and triggers tokenizer errors when the
                                      # AGENT STATE section is also injected.
        verbose: bool = False,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.use_tools_api = use_tools_api
        self.verbose = verbose

    def chat(self, messages: List[Dict[str, str]], tools: List[Dict], temperature: float = 0.7) -> Dict[str, Any]:
        """
        Call vLLM OpenAI-compatible chat completions API

        Args:
            messages: Conversation history
            tools: Tool schemas for function calling (only used when use_tools_api=True)
            temperature: Sampling temperature

        Returns:
            Response in OpenAI format (choices[0].message)
        """
        import requests

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            # Cap at 2048: the model's actual architectural limit is 4096 tokens
            # (max_position_embeddings), regardless of what the vLLM server reports
            # as max_model_len.  Once prompt_tokens + max_tokens > 4096, vLLM
            # overflows the KV cache and raises a misleading tokenizer error.
            # 2048 leaves ample room for a growing conversation (up to ~10 iterations
            # of tool results ≈ 1000-1500 prompt tokens) while fitting tool-call JSON
            # and final summaries comfortably.
            "max_tokens": 2048,
        }

        # Only include tools if the model supports native tool_calls.
        # gpt-oss-20b ignores tool_calls and outputs JSON in content instead;
        # sending tools triggers vLLM's Llama-3 tool template which embeds all
        # schemas into the system message and causes tokenizer errors.
        if self.use_tools_api:
            openai_tools = self._format_tools_for_openai(tools)
            if openai_tools:
                payload["tools"] = openai_tools
                payload["tool_choice"] = "auto"
        else:
            openai_tools = []

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        if self.verbose:
            roles = [m.get("role") for m in messages]
            print(f"[vLLM] Sending {len(messages)} messages, roles={roles}, "
                  f"tools={len(openai_tools)}, "
                  f"sys_len={len(messages[0].get('content','') if messages else '')}")

        response = requests.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=120,  # 2 minute timeout for large model inference
        )

        if not response.ok:
            print(f"[vLLM] Error body: {response.text[:500]}")
            response.raise_for_status()

        result = response.json()

        if "choices" not in result:
            raise RuntimeError(f"vLLM API error: {result}")

        # Extract the message from OpenAI format
        message = result["choices"][0]["message"]

        # If there's a native tool_call response AND we sent tools= to the API,
        # reformat it for our function calling handler.
        # Guard with use_tools_api: gpt-oss-20b outputs JSON in content and
        # does NOT use tool_calls.  If we process tool_calls unconditionally,
        # a spurious native response would set call_id on the FunctionCall,
        # causing format_function_response_for_llm to return role:"tool", which
        # vLLM then rejects on the next request with:
        # "unexpected tokens remaining in message header: Some('to=tool')"
        if self.use_tools_api and message.get("tool_calls"):
            tool_call = message["tool_calls"][0]
            return {
                "choices": result["choices"],
                "function_call": {
                    "name": tool_call["function"]["name"],
                    "arguments": tool_call["function"]["arguments"],
                },
                "id": tool_call.get("id"),
            }

        return result

    def _format_tools_for_openai(self, tools: List[Dict]) -> List[Dict]:
        """
        Convert our tool schemas to OpenAI function calling format

        Our format:
            {"name": "nmap", "description": "...", "parameters": {...}}

        OpenAI format:
            {"type": "function", "function": {"name": "nmap", "description": "...", "parameters": {...}}}
        """
        openai_tools = []
        for tool in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                }
            })
        return openai_tools
