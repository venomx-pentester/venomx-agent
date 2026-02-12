"""
Tool Schemas for VenomX Agent
Defines JSON schemas for LLM function calling with security tools
"""

from typing import TypedDict, Literal, Optional
from enum import Enum


class ToolSchema(TypedDict):
    """Base schema for all tools"""
    name: str
    description: str
    parameters: dict


# ============================================================================
# NMAP Tool Schema
# ============================================================================

NMAP_SCHEMA: ToolSchema = {
    "name": "nmap",
    "description": """
    Network scanning tool for host discovery, port scanning, service/version detection,
    and OS fingerprinting. Use for initial reconnaissance and enumeration.

    Common use cases:
    - Host discovery: Find active devices on network
    - Port scanning: Identify open ports and services
    - Service detection: Determine software versions
    - OS fingerprinting: Identify operating systems
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address, hostname, or CIDR range (e.g., '192.168.1.1', '192.168.1.0/24')"
            },
            "scan_type": {
                "type": "string",
                "enum": ["ping_sweep", "port_scan", "service_scan", "os_detection", "aggressive", "stealth"],
                "description": "Type of scan to perform. ping_sweep=host discovery, port_scan=basic port check, service_scan=version detection, os_detection=OS fingerprinting, aggressive=comprehensive scan, stealth=SYN scan"
            },
            "ports": {
                "type": "string",
                "description": "Port specification (e.g., '80,443', '1-1000', 'top-100'). Leave empty for default ports based on scan_type",
                "default": ""
            },
            "timing": {
                "type": "integer",
                "enum": [0, 1, 2, 3, 4, 5],
                "description": "Timing template: 0=paranoid (slowest, stealthiest), 3=normal, 5=insane (fastest, loudest)",
                "default": 3
            },
            "exclude": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of IP addresses to exclude from scanning (safety measure)",
                "default": []
            }
        },
        "required": ["target", "scan_type"]
    }
}


# ============================================================================
# NIKTO Tool Schema
# ============================================================================

NIKTO_SCHEMA: ToolSchema = {
    "name": "nikto",
    "description": """
    Web server vulnerability scanner that checks for dangerous files, outdated
    server software, and common misconfigurations.

    Use after discovering web servers (port 80/443/8080) with nmap.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or IP address (e.g., 'http://192.168.1.50', 'https://target.local')"
            },
            "port": {
                "type": "integer",
                "description": "Port to scan (default: 80 for http, 443 for https)",
                "default": 80
            },
            "ssl": {
                "type": "boolean",
                "description": "Use HTTPS instead of HTTP",
                "default": False
            },
            "tuning": {
                "type": "string",
                "enum": ["all", "interesting", "misconfig", "info_disclosure", "injection", "xss"],
                "description": "Focus scan on specific vulnerability types",
                "default": "all"
            }
        },
        "required": ["target"]
    }
}


# ============================================================================
# GOBUSTER Tool Schema
# ============================================================================

GOBUSTER_SCHEMA: ToolSchema = {
    "name": "gobuster",
    "description": """
    Directory and file brute-forcing tool for discovering hidden web paths,
    backup files, admin panels, and exposed directories.

    Use after identifying web servers to enumerate web application structure.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL to scan (e.g., 'http://192.168.1.50')"
            },
            "wordlist": {
                "type": "string",
                "enum": ["common", "medium", "large", "api", "admin"],
                "description": "Wordlist size/type: common=2.3k words (fast), medium=20k, large=220k (slow), api=API endpoints, admin=admin panels",
                "default": "common"
            },
            "extensions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "File extensions to check (e.g., ['php', 'html', 'txt', 'bak'])",
                "default": ["php", "html", "txt"]
            },
            "status_codes": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "HTTP status codes to report (200=found, 301=redirect, 403=forbidden)",
                "default": [200, 301, 302, 401, 403]
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads (higher=faster but noisier)",
                "default": 10,
                "minimum": 1,
                "maximum": 50
            }
        },
        "required": ["target"]
    }
}


# ============================================================================
# HYDRA Tool Schema
# ============================================================================

HYDRA_SCHEMA: ToolSchema = {
    "name": "hydra",
    "description": """
    Fast network authentication brute-forcing tool supporting SSH, FTP, HTTP,
    RDP, and other protocols.

    ⚠️ LOUD TOOL - Generates significant traffic and logs. Use carefully.
    Only use after identifying authentication services with weak credentials.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address or hostname"
            },
            "service": {
                "type": "string",
                "enum": ["ssh", "ftp", "http-get", "http-post", "rdp", "mysql", "postgres"],
                "description": "Service/protocol to attack"
            },
            "username": {
                "type": "string",
                "description": "Single username to test (or leave empty to use username list)",
                "default": ""
            },
            "username_list": {
                "type": "string",
                "enum": ["common", "top100", "default"],
                "description": "Predefined username list to use if username not specified",
                "default": "common"
            },
            "password_list": {
                "type": "string",
                "enum": ["common", "rockyou-100", "default", "weak"],
                "description": "Password wordlist: common=500 most common, rockyou-100=top 100 from rockyou.txt, default=service defaults, weak=weak passwords",
                "default": "common"
            },
            "port": {
                "type": "integer",
                "description": "Target port (uses service default if not specified)",
                "default": 0
            },
            "threads": {
                "type": "integer",
                "description": "Number of parallel tasks (default: 4, max: 16 for safety)",
                "default": 4,
                "maximum": 16
            },
            "stop_on_success": {
                "type": "boolean",
                "description": "Stop after finding first valid credential",
                "default": True
            }
        },
        "required": ["target", "service"]
    }
}


# ============================================================================
# SQLMAP Tool Schema
# ============================================================================

SQLMAP_SCHEMA: ToolSchema = {
    "name": "sqlmap",
    "description": """
    Automated SQL injection detection and exploitation tool.

    ⚠️ POTENTIALLY DESTRUCTIVE - Can modify database contents.
    Requires human approval before execution.

    Use after identifying web applications with user input fields.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL with vulnerable parameter (e.g., 'http://target/page.php?id=1')"
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST"],
                "description": "HTTP method",
                "default": "GET"
            },
            "data": {
                "type": "string",
                "description": "POST data if method=POST (e.g., 'username=admin&password=test')",
                "default": ""
            },
            "level": {
                "type": "integer",
                "enum": [1, 2, 3, 4, 5],
                "description": "Test level: 1=basic tests, 5=extensive tests (slower)",
                "default": 1
            },
            "risk": {
                "type": "integer",
                "enum": [1, 2, 3],
                "description": "Risk level: 1=safe tests only, 3=potentially harmful tests",
                "default": 1
            },
            "technique": {
                "type": "string",
                "enum": ["BEUSTQ", "B", "E", "U", "S", "T", "Q"],
                "description": "SQL injection techniques: B=Boolean-based, E=Error-based, U=Union, S=Stacked, T=Time-based, Q=Inline queries",
                "default": "BEUSTQ"
            },
            "enumerate": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["dbs", "tables", "columns", "users", "passwords", "current-user"]
                },
                "description": "What to enumerate if injection is found",
                "default": ["current-user", "dbs"]
            }
        },
        "required": ["target"]
    }
}


# ============================================================================
# SEARCHSPLOIT Tool Schema
# ============================================================================

SEARCHSPLOIT_SCHEMA: ToolSchema = {
    "name": "searchsploit",
    "description": """
    Search the local Exploit-DB database for known exploits matching software
    versions discovered during reconnaissance.

    Safe tool - only searches database, doesn't execute anything.
    Use after service version detection to find relevant exploits.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search term (e.g., 'Apache 2.4.49', 'vsftpd 2.3.4', 'Windows 7')"
            },
            "strict": {
                "type": "boolean",
                "description": "Strict search (exact match) vs fuzzy search",
                "default": False
            },
            "exclude": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Terms to exclude from results (e.g., ['dos', 'outdated'])",
                "default": []
            },
            "platform": {
                "type": "string",
                "enum": ["", "linux", "windows", "multiple", "php", "hardware"],
                "description": "Filter by platform",
                "default": ""
            }
        },
        "required": ["query"]
    }
}


# ============================================================================
# METASPLOIT Tool Schema
# ============================================================================

METASPLOIT_SCHEMA: ToolSchema = {
    "name": "metasploit",
    "description": """
    Exploit framework for validating vulnerabilities and gaining access.

    ⚠️ REQUIRES HUMAN APPROVAL - Actively exploits vulnerabilities.

    Use only after confirming vulnerability exists and getting user permission.
    """.strip(),
    "parameters": {
        "type": "object",
        "properties": {
            "exploit": {
                "type": "string",
                "description": "Exploit module path (e.g., 'exploit/unix/ftp/vsftpd_234_backdoor')"
            },
            "target": {
                "type": "string",
                "description": "Target IP address"
            },
            "port": {
                "type": "integer",
                "description": "Target port"
            },
            "payload": {
                "type": "string",
                "description": "Payload to use (e.g., 'cmd/unix/reverse', 'generic/shell_reverse_tcp')",
                "default": "generic/shell_reverse_tcp"
            },
            "lhost": {
                "type": "string",
                "description": "Local host IP for reverse connections (attacker IP)"
            },
            "lport": {
                "type": "integer",
                "description": "Local port for reverse connections",
                "default": 4444
            },
            "options": {
                "type": "object",
                "description": "Additional exploit-specific options as key-value pairs",
                "default": {}
            }
        },
        "required": ["exploit", "target", "lhost"]
    }
}


# ============================================================================
# Tool Registry
# ============================================================================

ALL_TOOL_SCHEMAS = {
    "nmap": NMAP_SCHEMA,
    "nikto": NIKTO_SCHEMA,
    "gobuster": GOBUSTER_SCHEMA,
    "hydra": HYDRA_SCHEMA,
    "sqlmap": SQLMAP_SCHEMA,
    "searchsploit": SEARCHSPLOIT_SCHEMA,
    "metasploit": METASPLOIT_SCHEMA,
}

# Tools that require human approval before execution
RESTRICTED_TOOLS = {"hydra", "sqlmap", "metasploit"}

# Tools that are considered "loud" and generate significant network traffic
LOUD_TOOLS = {"hydra", "nikto", "gobuster"}


def get_tool_schema(tool_name: str) -> Optional[ToolSchema]:
    """Get schema for a specific tool"""
    return ALL_TOOL_SCHEMAS.get(tool_name)


def get_all_schemas() -> list[ToolSchema]:
    """Get all tool schemas for LLM function calling"""
    return list(ALL_TOOL_SCHEMAS.values())


def is_restricted(tool_name: str) -> bool:
    """Check if tool requires human approval"""
    return tool_name in RESTRICTED_TOOLS


def is_loud(tool_name: str) -> bool:
    """Check if tool generates significant traffic"""
    return tool_name in LOUD_TOOLS
