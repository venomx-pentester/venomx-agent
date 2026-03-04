"""Tests for tool schemas."""

from src.schemas import get_all_schemas, get_tool_schema, is_restricted, is_loud


def test_all_schemas_count():
    assert len(get_all_schemas()) == 7


def test_schema_has_required_fields():
    schema = get_tool_schema("nmap")
    assert "name" in schema
    assert "description" in schema
    assert "parameters" in schema


def test_restricted_tools():
    assert is_restricted("hydra")
    assert is_restricted("sqlmap")
    assert is_restricted("metasploit")


def test_non_restricted_tools():
    assert not is_restricted("nmap")
    assert not is_restricted("searchsploit")
    assert not is_restricted("nikto")


def test_loud_tools():
    assert is_loud("hydra")
    assert is_loud("nikto")
    assert is_loud("gobuster")


def test_non_loud_tools():
    assert not is_loud("nmap")
    assert not is_loud("searchsploit")
