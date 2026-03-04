"""Tests for tool wrappers and ToolFactory."""

from src.tools import ToolFactory, ToolStatus


def test_factory_lists_registered_tools():
    tools = ToolFactory.list_tools()
    assert "nmap" in tools
    assert "searchsploit" in tools


def test_get_nmap_tool():
    tool = ToolFactory.get_tool("nmap")
    assert tool is not None
    assert tool.name == "nmap"


def test_unknown_tool_returns_none():
    assert ToolFactory.get_tool("nonexistent") is None


def test_tool_has_required_methods():
    tool = ToolFactory.get_tool("nmap")
    assert hasattr(tool, "execute")
    assert hasattr(tool, "build_command")
    assert hasattr(tool, "parse_output")
    assert hasattr(tool, "validate_params")


def test_nmap_build_command():
    tool = ToolFactory.get_tool("nmap")
    cmd = tool.build_command(target="127.0.0.1", scan_type="ping_scan")
    assert "nmap" in cmd
    assert "127.0.0.1" in cmd


def test_tool_status_enum():
    assert ToolStatus.SUCCESS
    assert ToolStatus.FAILURE
    assert ToolStatus.TIMEOUT
