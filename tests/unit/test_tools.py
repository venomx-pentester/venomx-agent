"""Tests for tool wrappers and ToolFactory."""

import pytest

from src.tools import ToolFactory, ToolStatus


# ---------------------------------------------------------------------------
# ToolFactory
# ---------------------------------------------------------------------------

def test_factory_lists_all_registered_tools():
    tools = ToolFactory.list_tools()
    for expected in ["nmap", "nikto", "gobuster", "hydra", "sqlmap", "searchsploit", "metasploit"]:
        assert expected in tools


def test_get_known_tool_returns_instance():
    for name in ["nmap", "nikto", "gobuster", "hydra", "sqlmap", "searchsploit", "metasploit"]:
        tool = ToolFactory.get_tool(name)
        assert tool is not None, f"Expected tool '{name}' to be registered"
        assert tool.name == name


def test_unknown_tool_returns_none():
    assert ToolFactory.get_tool("nonexistent") is None


def test_all_tools_have_required_methods():
    for name in ToolFactory.list_tools():
        tool = ToolFactory.get_tool(name)
        assert hasattr(tool, "execute")
        assert hasattr(tool, "build_command")
        assert hasattr(tool, "parse_output")
        assert hasattr(tool, "validate_params")


def test_tool_status_enum():
    assert ToolStatus.SUCCESS
    assert ToolStatus.FAILURE
    assert ToolStatus.TIMEOUT


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def test_nmap_build_command_includes_target_and_flags():
    tool = ToolFactory.get_tool("nmap")
    cmd = tool.build_command(target="192.168.1.1", scan_type="port_scan")
    assert "nmap" in cmd
    assert "192.168.1.1" in cmd
    assert "-sS" in cmd  # port_scan maps to -sS

def test_nmap_build_command_service_scan():
    tool = ToolFactory.get_tool("nmap")
    cmd = tool.build_command(target="10.0.0.1", scan_type="service_scan")
    assert "-sV" in cmd

def test_nmap_build_command_custom_ports():
    tool = ToolFactory.get_tool("nmap")
    cmd = tool.build_command(target="10.0.0.1", scan_type="port_scan", ports="22,80,443")
    assert "-p 22,80,443" in cmd

def test_nmap_validate_params_valid():
    tool = ToolFactory.get_tool("nmap")
    ok, _ = tool.validate_params(target="10.0.0.1", scan_type="aggressive")
    assert ok

def test_nmap_validate_params_missing_target():
    tool = ToolFactory.get_tool("nmap")
    ok, msg = tool.validate_params(scan_type="port_scan")
    assert not ok
    assert "target" in msg.lower()

def test_nmap_validate_params_invalid_scan_type():
    tool = ToolFactory.get_tool("nmap")
    ok, msg = tool.validate_params(target="10.0.0.1", scan_type="full_scan")
    assert not ok
    assert "scan_type" in msg.lower()

def test_nmap_parse_output_empty():
    tool = ToolFactory.get_tool("nmap")
    result = tool.parse_output("")
    assert result["hosts"] == []
    assert result["open_ports"] == []


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------

def test_nikto_build_command_includes_host_and_port():
    tool = ToolFactory.get_tool("nikto")
    cmd = tool.build_command(target="192.168.1.50", port=8080)
    assert "nikto" in cmd
    assert "192.168.1.50" in cmd
    assert "8080" in cmd

def test_nikto_build_command_ssl_flag():
    tool = ToolFactory.get_tool("nikto")
    cmd = tool.build_command(target="10.0.0.1", ssl=True)
    assert "-ssl" in cmd

def test_nikto_build_command_tuning():
    tool = ToolFactory.get_tool("nikto")
    cmd = tool.build_command(target="10.0.0.1", tuning="xss")
    assert "-Tuning" in cmd
    assert "4" in cmd  # xss maps to tuning code "4"

def test_nikto_validate_params_valid():
    tool = ToolFactory.get_tool("nikto")
    ok, _ = tool.validate_params(target="http://10.0.0.1")
    assert ok

def test_nikto_validate_params_missing_target():
    tool = ToolFactory.get_tool("nikto")
    ok, msg = tool.validate_params()
    assert not ok

def test_nikto_validate_params_invalid_tuning():
    tool = ToolFactory.get_tool("nikto")
    ok, msg = tool.validate_params(target="10.0.0.1", tuning="sqli")
    assert not ok
    assert "tuning" in msg.lower()

def test_nikto_parse_output_extracts_findings():
    tool = ToolFactory.get_tool("nikto")
    raw = (
        "+ Target Port:          80\n"
        "+ OSVDB-3092: /admin/: This might be interesting...\n"
        "+ /config.php: PHP configuration file\n"
        "+ CVE-2021-41773: Apache path traversal vulnerability\n"
    )
    result = tool.parse_output(raw)
    assert result["port"] == 80
    assert result["finding_count"] >= 2


# ---------------------------------------------------------------------------
# gobuster
# ---------------------------------------------------------------------------

def test_gobuster_build_command_includes_target_and_wordlist():
    tool = ToolFactory.get_tool("gobuster")
    cmd = tool.build_command(target="http://10.0.0.1", wordlist="common")
    assert "gobuster" in cmd
    assert "http://10.0.0.1" in cmd
    assert "common.txt" in cmd

def test_gobuster_build_command_extensions():
    tool = ToolFactory.get_tool("gobuster")
    cmd = tool.build_command(target="http://10.0.0.1", extensions=["php", "bak"])
    assert "-x" in cmd
    assert "php" in cmd

def test_gobuster_validate_params_valid():
    tool = ToolFactory.get_tool("gobuster")
    ok, _ = tool.validate_params(target="http://10.0.0.1", wordlist="medium")
    assert ok

def test_gobuster_validate_params_missing_target():
    tool = ToolFactory.get_tool("gobuster")
    ok, _ = tool.validate_params(wordlist="common")
    assert not ok

def test_gobuster_validate_params_invalid_wordlist():
    tool = ToolFactory.get_tool("gobuster")
    ok, msg = tool.validate_params(target="http://10.0.0.1", wordlist="huge")
    assert not ok
    assert "wordlist" in msg.lower()

def test_gobuster_parse_output_extracts_paths():
    tool = ToolFactory.get_tool("gobuster")
    raw = (
        "/admin (Status: 200) [Size: 1234]\n"
        "/login.php (Status: 301) [Size: 0]\n"
        "/config.bak (Status: 403) [Size: 512]\n"
    )
    result = tool.parse_output(raw)
    assert result["path_count"] == 3
    paths = [p["path"] for p in result["paths"]]
    assert "/admin" in paths
    assert "/login.php" in paths


# ---------------------------------------------------------------------------
# hydra
# ---------------------------------------------------------------------------

def test_hydra_build_command_single_username():
    tool = ToolFactory.get_tool("hydra")
    cmd = tool.build_command(target="10.0.0.1", service="ssh", username="root", password_list="common")
    assert "hydra" in cmd
    assert "-l root" in cmd
    assert "ssh" in cmd

def test_hydra_build_command_username_list():
    tool = ToolFactory.get_tool("hydra")
    cmd = tool.build_command(target="10.0.0.1", service="ftp", username_list="common", password_list="common")
    assert "-L" in cmd

def test_hydra_build_command_stop_on_success():
    tool = ToolFactory.get_tool("hydra")
    cmd = tool.build_command(target="10.0.0.1", service="ssh", username="admin",
                             password_list="common", stop_on_success=True)
    assert "-f" in cmd

def test_hydra_validate_params_valid():
    tool = ToolFactory.get_tool("hydra")
    ok, _ = tool.validate_params(target="10.0.0.1", service="ssh")
    assert ok

def test_hydra_validate_params_invalid_service():
    tool = ToolFactory.get_tool("hydra")
    ok, msg = tool.validate_params(target="10.0.0.1", service="telnet")
    assert not ok
    assert "service" in msg.lower()

def test_hydra_validate_params_invalid_password_list():
    tool = ToolFactory.get_tool("hydra")
    ok, msg = tool.validate_params(target="10.0.0.1", service="ssh",
                                   password_list="/usr/share/wordlists/rockyou.txt")
    assert not ok
    assert "password_list" in msg.lower()

def test_hydra_validate_params_invalid_username_list():
    tool = ToolFactory.get_tool("hydra")
    ok, msg = tool.validate_params(target="10.0.0.1", service="ssh",
                                   username_list="root,admin,user")
    assert not ok
    assert "username_list" in msg.lower()

def test_hydra_parse_output_extracts_credentials():
    tool = ToolFactory.get_tool("hydra")
    raw = (
        "[22][ssh] host: 10.0.0.1   login: admin   password: password123\n"
        "1 valid password found.\n"
    )
    result = tool.parse_output(raw)
    assert result["credential_count"] == 1
    assert result["credentials"][0]["login"] == "admin"
    assert result["credentials"][0]["password"] == "password123"


# ---------------------------------------------------------------------------
# sqlmap
# ---------------------------------------------------------------------------

def test_sqlmap_build_command_basic():
    tool = ToolFactory.get_tool("sqlmap")
    cmd = tool.build_command(target="http://10.0.0.1/page.php?id=1")
    assert "sqlmap" in cmd
    assert "http://10.0.0.1/page.php?id=1" in cmd
    assert "--batch" in cmd

def test_sqlmap_build_command_enumerate():
    tool = ToolFactory.get_tool("sqlmap")
    cmd = tool.build_command(target="http://10.0.0.1/page.php?id=1",
                             enumerate=["dbs", "users"])
    assert "--dbs" in cmd
    assert "--users" in cmd

def test_sqlmap_validate_params_valid():
    tool = ToolFactory.get_tool("sqlmap")
    ok, _ = tool.validate_params(target="http://10.0.0.1/page.php?id=1")
    assert ok

def test_sqlmap_validate_params_missing_target():
    tool = ToolFactory.get_tool("sqlmap")
    ok, _ = tool.validate_params()
    assert not ok

def test_sqlmap_validate_params_invalid_level():
    tool = ToolFactory.get_tool("sqlmap")
    ok, msg = tool.validate_params(target="http://10.0.0.1/page.php?id=1", level=6)
    assert not ok
    assert "level" in msg.lower()

def test_sqlmap_parse_output_injectable():
    tool = ToolFactory.get_tool("sqlmap")
    raw = (
        "[INFO] GET parameter 'id' appears to be injectable\n"
        "[INFO] available databases [2]:\n"
        "[*] information_schema\n"
        "[*] webapp_db\n"
    )
    result = tool.parse_output(raw)
    assert result["injectable"]
    assert "information_schema" in result["databases"]
    assert "webapp_db" in result["databases"]


# ---------------------------------------------------------------------------
# searchsploit
# ---------------------------------------------------------------------------

def test_searchsploit_build_command():
    tool = ToolFactory.get_tool("searchsploit")
    cmd = tool.build_command(query="vsftpd 2.3.4")
    assert "searchsploit" in cmd
    assert "vsftpd 2.3.4" in cmd
    assert "--json" in cmd

def test_searchsploit_build_command_strict():
    tool = ToolFactory.get_tool("searchsploit")
    cmd = tool.build_command(query="Apache 2.4.49", strict=True)
    assert "--strict" in cmd

def test_searchsploit_validate_params_valid():
    tool = ToolFactory.get_tool("searchsploit")
    ok, _ = tool.validate_params(query="OpenSSH 7.4")
    assert ok

def test_searchsploit_validate_params_query_too_short():
    tool = ToolFactory.get_tool("searchsploit")
    ok, msg = tool.validate_params(query="ab")
    assert not ok

def test_searchsploit_parse_output_json():
    import json
    tool = ToolFactory.get_tool("searchsploit")
    data = {
        "RESULTS_EXPLOIT": [
            {"Title": "vsftpd 2.3.4 - Backdoor", "Path": "/usr/share/exploitdb/exploits/unix/remote/17491.rb",
             "Platform": "Unix", "Type": "remote", "Date_Published": "2011-07-03"},
        ]
    }
    result = tool.parse_output(json.dumps(data))
    assert result["count"] == 1
    assert result["exploits"][0]["title"] == "vsftpd 2.3.4 - Backdoor"


# ---------------------------------------------------------------------------
# metasploit
# ---------------------------------------------------------------------------

def test_metasploit_build_command_includes_module_and_target():
    tool = ToolFactory.get_tool("metasploit")
    cmd = tool.build_command(
        exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        target="10.0.0.1",
        lhost="192.168.1.100",
    )
    assert "msfconsole" in cmd
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in cmd
    assert "10.0.0.1" in cmd
    assert "192.168.1.100" in cmd

def test_metasploit_build_command_custom_payload_and_lport():
    tool = ToolFactory.get_tool("metasploit")
    cmd = tool.build_command(
        exploit="exploit/multi/handler",
        target="10.0.0.1",
        lhost="192.168.1.100",
        payload="cmd/unix/reverse",
        lport=5555,
    )
    assert "cmd/unix/reverse" in cmd
    assert "5555" in cmd

def test_metasploit_validate_params_valid():
    tool = ToolFactory.get_tool("metasploit")
    ok, _ = tool.validate_params(
        exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        target="10.0.0.1",
        lhost="192.168.1.100",
    )
    assert ok

def test_metasploit_validate_params_missing_lhost():
    tool = ToolFactory.get_tool("metasploit")
    ok, msg = tool.validate_params(
        exploit="exploit/unix/ftp/vsftpd_234_backdoor",
        target="10.0.0.1",
    )
    assert not ok
    assert "lhost" in msg.lower()

def test_metasploit_parse_output_session_opened():
    tool = ToolFactory.get_tool("metasploit")
    raw = (
        "[*] Started reverse TCP handler on 192.168.1.100:4444\n"
        "[*] Command shell session 1 opened (192.168.1.100:4444 -> 10.0.0.1:59823)\n"
    )
    result = tool.parse_output(raw)
    assert result["session_opened"]
    assert result["session_id"] == 1
    assert result["session_type"] == "shell"
