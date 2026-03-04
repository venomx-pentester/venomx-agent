"""Tests for FunctionCallHandler (JSON function calling)."""

from src.agent import FunctionCallHandler


def test_handler_provides_seven_schemas():
    handler = FunctionCallHandler()
    assert len(handler.get_tool_schemas_for_llm()) == 7


def test_parse_openai_format():
    handler = FunctionCallHandler()
    response = {
        "function_call": {
            "name": "nmap",
            "arguments": '{"target": "192.168.1.50", "scan_type": "ping_scan"}',
        },
        "id": "call_123",
    }
    fc = handler.parse_llm_function_call(response)
    assert fc is not None
    assert fc.name == "nmap"
    assert fc.arguments["target"] == "192.168.1.50"


def test_parse_claude_format():
    handler = FunctionCallHandler()
    response = {
        "tool_use": {
            "name": "searchsploit",
            "input": {"query": "Apache 2.4.49"},
            "id": "tool_use_123",
        }
    }
    fc = handler.parse_llm_function_call(response)
    assert fc is not None
    assert fc.name == "searchsploit"
    assert fc.arguments["query"] == "Apache 2.4.49"


def test_parse_llama_format():
    handler = FunctionCallHandler()
    response = {"name": "nmap", "arguments": {"target": "192.168.1.50"}}
    fc = handler.parse_llm_function_call(response)
    assert fc is not None
    assert fc.name == "nmap"


def test_no_function_call_returns_none():
    handler = FunctionCallHandler()
    assert handler.parse_llm_function_call({"content": "Analyzing results..."}) is None
    assert handler.parse_llm_function_call({"choices": [{"message": {"content": "hi"}}]}) is None
