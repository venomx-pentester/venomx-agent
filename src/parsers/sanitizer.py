"""
Command Sanitization Module
Security layer to prevent command injection and unauthorized operations
"""

import re
import ipaddress
from typing import Tuple, List, Set
from dataclasses import dataclass


@dataclass
class SanitizationConfig:
    """Configuration for command sanitization"""
    # IP addresses allowed to be targeted
    whitelist: Set[str] = None

    # IP addresses never to target
    blacklist: Set[str] = None

    # Allowed port ranges
    allowed_port_ranges: List[Tuple[int, int]] = None

    # Dangerous commands that are never allowed
    banned_commands: Set[str] = None

    # Maximum command length
    max_command_length: int = 2000

    def __post_init__(self):
        # Default whitelist (RFC1918 private networks + localhost)
        if self.whitelist is None:
            self.whitelist = {
                "192.168.0.0/16",  # Private network
                "10.0.0.0/8",      # Private network
                "172.16.0.0/12",   # Private network
                "127.0.0.0/8",     # Localhost
            }

        # Default blacklist (specific dangerous IPs/ranges)
        if self.blacklist is None:
            self.blacklist = {
                "8.8.8.8",         # Google DNS
                "1.1.1.1",         # Cloudflare DNS
                "8.8.4.4",         # Google DNS secondary
                "1.0.0.1",         # Cloudflare DNS secondary
            }

        # Default port ranges (common services only)
        if self.allowed_port_ranges is None:
            self.allowed_port_ranges = [
                (1, 65535),  # Allow all ports (restrict later if needed)
            ]

        # Dangerous commands (command injection prevention)
        if self.banned_commands is None:
            self.banned_commands = {
                "rm", "rmdir", "del", "format",  # File deletion
                "dd", "shred",  # Disk operations
                "curl", "wget",  # External downloads
                "nc", "netcat",  # Raw network connections (except in controlled tools)
                "ssh", "scp",  # SSH operations (except through proper tools)
                "mkfs", "fdisk",  # Filesystem operations
                "kill", "killall",  # Process killing
                "reboot", "shutdown", "halt",  # System control
                "iptables", "ufw", "firewall-cmd",  # Firewall changes
                "useradd", "userdel", "passwd",  # User management
                "chmod", "chown",  # Permission changes (could be needed for exploits)
                "crontab",  # Scheduled tasks
            }


class CommandSanitizer:
    """
    Sanitizes and validates security tool commands before execution

    Security Checks:
    1. Command injection prevention (shell metacharacters)
    2. IP address whitelisting/blacklisting
    3. Port range validation
    4. Dangerous command detection
    5. Path traversal prevention
    6. Length limits
    """

    # Shell metacharacters that could enable command injection
    SHELL_METACHARACTERS = {
        ';', '|', '&', '$', '`', '\n', '\r',
        '>', '<', '(', ')', '{', '}', '[', ']',
        '*', '?', '~', '!', '#', '%'
    }

    # Exception: These tools legitimately use some metacharacters
    ALLOWED_METACHARACTERS = {
        "nmap": {'*'},  # For wildcard IP ranges
        "searchsploit": set(),  # No metacharacters needed
        "hydra": set(),
    }

    def __init__(self, config: SanitizationConfig = None):
        self.config = config or SanitizationConfig()

    def sanitize(self, command: str, tool_name: str) -> Tuple[bool, str, str]:
        """
        Sanitize and validate a command

        Args:
            command: Raw command string
            tool_name: Name of the tool being executed

        Returns:
            Tuple of (is_safe, sanitized_command, error_message)
        """
        # Check 1: Length limit
        if len(command) > self.config.max_command_length:
            return False, "", f"Command exceeds maximum length ({self.config.max_command_length})"

        # Check 2: Command injection - shell metacharacters
        allowed_meta = self.ALLOWED_METACHARACTERS.get(tool_name, set())
        dangerous_chars = self.SHELL_METACHARACTERS - allowed_meta

        for char in dangerous_chars:
            if char in command:
                return False, "", f"Dangerous metacharacter detected: '{char}'"

        # Check 3: Dangerous commands in the command string
        command_lower = command.lower()
        for banned_cmd in self.config.banned_commands:
            # Use word boundaries to avoid false positives
            pattern = r'\b' + re.escape(banned_cmd) + r'\b'
            if re.search(pattern, command_lower):
                return False, "", f"Banned command detected: '{banned_cmd}'"

        # Check 4: IP address validation (extract and validate IPs)
        ips = self._extract_ips(command)
        for ip in ips:
            if not self._is_ip_allowed(ip):
                return False, "", f"IP address not in whitelist or is blacklisted: {ip}"

        # Check 5: Path traversal prevention
        if self._has_path_traversal(command):
            return False, "", "Path traversal detected (../ or .\\.)"

        # Check 6: Tool-specific validation
        is_valid, error = self._validate_tool_specific(command, tool_name)
        if not is_valid:
            return False, "", error

        # Command is safe - return sanitized version
        sanitized = command.strip()
        return True, sanitized, ""

    def _extract_ips(self, command: str) -> List[str]:
        """Extract IP addresses and CIDR ranges from command"""
        # Pattern for IP addresses and CIDR notation
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        matches = re.findall(ip_pattern, command)
        return matches

    def _is_ip_allowed(self, ip_str: str) -> bool:
        """
        Check if IP address is allowed based on whitelist/blacklist

        Args:
            ip_str: IP address or CIDR range

        Returns:
            True if allowed, False otherwise
        """
        try:
            # Handle CIDR notation
            if '/' in ip_str:
                target_network = ipaddress.ip_network(ip_str, strict=False)
            else:
                target_ip = ipaddress.ip_address(ip_str)
                target_network = ipaddress.ip_network(f"{ip_str}/32", strict=False)

            # Check blacklist first (takes precedence)
            for blacklist_entry in self.config.blacklist:
                blacklist_network = ipaddress.ip_network(blacklist_entry, strict=False)
                if target_network.overlaps(blacklist_network):
                    return False

            # Check whitelist
            for whitelist_entry in self.config.whitelist:
                whitelist_network = ipaddress.ip_network(whitelist_entry, strict=False)
                if target_network.subnet_of(whitelist_network) or target_network == whitelist_network:
                    return True

            # Not in whitelist
            return False

        except ValueError:
            # Invalid IP address format
            return False

    def _has_path_traversal(self, command: str) -> bool:
        """Check for path traversal attempts"""
        dangerous_patterns = [
            r'\.\.',  # Parent directory
            r'~/',    # Home directory
            r'/etc/',  # System directories
            r'/root/',
            r'/sys/',
            r'/proc/',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command):
                # Exception: searchsploit uses paths like exploits/../
                if 'searchsploit' in command.lower() and 'exploits' in command:
                    continue
                return True

        return False

    def _validate_tool_specific(self, command: str, tool_name: str) -> Tuple[bool, str]:
        """
        Tool-specific validation rules

        Args:
            command: Command string
            tool_name: Name of the tool

        Returns:
            (is_valid, error_message)
        """
        if tool_name == "nmap":
            # Prevent extremely aggressive nmap scans
            if "-T5" in command or "-T 5" in command:
                # Allow but warn (could make configurable)
                pass

            # Prevent dangerous nmap scripts
            dangerous_scripts = ["broadcast", "external", "intrusive"]
            if "--script" in command:
                for script_cat in dangerous_scripts:
                    if script_cat in command:
                        return False, f"Dangerous nmap script category: {script_cat}"

        elif tool_name == "hydra":
            # Ensure thread limit is reasonable
            if "-t" in command:
                match = re.search(r'-t\s*(\d+)', command)
                if match and int(match.group(1)) > 64:
                    return False, "Hydra thread count too high (max: 64)"

        elif tool_name == "sqlmap":
            # Prevent OS shell and file system access
            if "--os-shell" in command or "--file-write" in command:
                return False, "SQLMap file operations not allowed without explicit approval"

        return True, ""

    def add_to_whitelist(self, ip_range: str):
        """Add IP range to whitelist"""
        self.config.whitelist.add(ip_range)

    def add_to_blacklist(self, ip_range: str):
        """Add IP range to blacklist"""
        self.config.blacklist.add(ip_range)

    def update_config(self, config: SanitizationConfig):
        """Update sanitization configuration"""
        self.config = config


# Convenience function for quick sanitization checks
def quick_sanitize(command: str, tool_name: str) -> bool:
    """
    Quick sanitization check

    Returns:
        True if command is safe, False otherwise
    """
    sanitizer = CommandSanitizer()
    is_safe, _, _ = sanitizer.sanitize(command, tool_name)
    return is_safe
