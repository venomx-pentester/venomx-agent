"""Tests for CommandSanitizer and OutputParser."""

import pytest
from src.parsers import CommandSanitizer, OutputParser

_NMAP_RAW = "Nmap scan report for 192.168.1.50\nPORT   STATE SERVICE\n22/tcp open  ssh"
_NMAP_META = {
    "hosts": [{"ip": "192.168.1.50", "hostname": ""}],
    "open_ports": [
        {"host": "192.168.1.50", "port": 22, "protocol": "tcp",
         "service": "ssh", "product": "", "version": ""},
    ],
}


# ---------------------------------------------------------------------------
# CommandSanitizer
# ---------------------------------------------------------------------------

def test_allows_private_ip():
    s = CommandSanitizer()
    is_safe, _, _ = s.sanitize("nmap -sn 192.168.1.0/24", tool_name="nmap")
    assert is_safe


def test_blocks_external_ip():
    s = CommandSanitizer()
    is_safe, _, reason = s.sanitize("nmap -sn 8.8.8.8", tool_name="nmap")
    assert not is_safe
    assert "8.8.8.8" in reason


def test_blocks_command_injection_semicolon():
    s = CommandSanitizer()
    is_safe, _, reason = s.sanitize("nmap 192.168.1.1; rm -rf /", tool_name="nmap")
    assert not is_safe
    assert "metacharacter" in reason.lower()


def test_blocks_command_injection_pipe():
    s = CommandSanitizer()
    is_safe, _, _ = s.sanitize("nmap 192.168.1.1 | cat /etc/passwd", tool_name="nmap")
    assert not is_safe


# ---------------------------------------------------------------------------
# OutputParser
# ---------------------------------------------------------------------------

def test_parser_returns_structured_output():
    parser = OutputParser()
    parsed = parser.parse(tool_name="nmap", raw_output=_NMAP_RAW, metadata=_NMAP_META)
    assert parsed.tool_name == "nmap"
    assert len(parsed.findings) >= 1
    assert parsed.severity in ("critical", "high", "medium", "low", "info")


def test_format_for_llm_returns_string():
    parser = OutputParser()
    parsed = parser.parse(tool_name="nmap", raw_output=_NMAP_RAW, metadata=_NMAP_META)
    formatted = parser.format_for_llm(parsed)
    assert isinstance(formatted, str)
    assert len(formatted) > 0
