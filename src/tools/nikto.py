"""
Nikto Tool Wrapper
Web server vulnerability scanner
"""

from .base import BaseTool


class NiktoTool(BaseTool):
    """
    Nikto web server vulnerability scanner wrapper

    Supports:
    - Common web misconfigurations
    - Outdated server software detection
    - Dangerous file discovery
    - XSS / injection indicators
    """

    # Schema tuning values to nikto -Tuning codes
    TUNING_MAP = {
        "all": "",             # No -Tuning flag = scan everything
        "interesting": "1",   # Interesting files / seen in logs
        "misconfig": "2",      # Misconfiguration / default files
        "info_disclosure": "3",  # Information disclosure
        "injection": "9",      # SQL injection
        "xss": "4",            # XSS / script / HTML injection
    }

    def __init__(self):
        super().__init__(
            name="nikto",
            command="nikto",
            default_timeout=300,
            requires_approval=False,
            is_loud=True
        )

    def build_command(self, **kwargs) -> str:
        """
        Build nikto command from parameters

        Args:
            target: Target URL or IP address
            port:   Port to scan (default 80)
            ssl:    Use HTTPS (default False)
            tuning: Scan focus — "all", "interesting", "misconfig",
                    "info_disclosure", "injection", "xss"
        """
        target = kwargs.get("target", "")
        port = kwargs.get("port", 80)
        ssl = kwargs.get("ssl", False)
        tuning = kwargs.get("tuning", "all")

        cmd_parts = ["nikto", "-nointeractive"]

        # Host
        cmd_parts += ["-h", target]

        # Port
        cmd_parts += ["-p", str(port)]

        # SSL
        if ssl:
            cmd_parts.append("-ssl")

        # Tuning filter
        tuning_code = self.TUNING_MAP.get(tuning, "")
        if tuning_code:
            cmd_parts += ["-Tuning", tuning_code]

        # Plain text output (parseable)
        cmd_parts += ["-Format", "txt"]

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse nikto text output into structured data

        Returns:
            dict with:
                - host: Scanned host
                - port: Scanned port
                - findings: List of finding dicts
                - finding_count: Total findings
        """
        parsed = {
            "host": "",
            "port": 0,
            "findings": [],
            "finding_count": 0,
        }

        if not output:
            return parsed

        for line in output.splitlines():
            line = line.strip()

            # Target info line
            if line.startswith("+ Target IP:") or line.startswith("+ Target Hostname:"):
                pass  # informational, skip
            elif line.startswith("+ Target Port:"):
                try:
                    parsed["port"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass

            # Finding lines start with "+ "
            elif line.startswith("+ ") and not line.startswith("+ Target") \
                    and not line.startswith("+ Start Time") \
                    and not line.startswith("+ End Time") \
                    and not line.startswith("+ Server:") \
                    and "item(s) reported" not in line:

                description = line[2:].strip()

                # Classify severity from keywords
                severity = "info"
                desc_lower = description.lower()
                if any(k in desc_lower for k in ["osvdb", "cve-", "remote code", "rce", "shell"]):
                    severity = "high"
                elif any(k in desc_lower for k in ["sql injection", "xss", "file inclusion",
                                                     "directory traversal", "sensitive"]):
                    severity = "medium"
                elif any(k in desc_lower for k in ["default", "misconfigured",
                                                     "information disclosure", "version"]):
                    severity = "low"

                parsed["findings"].append({
                    "description": description,
                    "severity": severity,
                    "raw": line,
                })

        parsed["finding_count"] = len(parsed["findings"])
        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate nikto parameters"""
        if not kwargs.get("target"):
            return False, "Target is required"

        tuning = kwargs.get("tuning", "all")
        if tuning not in self.TUNING_MAP:
            return False, f"Invalid tuning. Must be one of: {list(self.TUNING_MAP.keys())}"

        port = kwargs.get("port", 80)
        if not (1 <= int(port) <= 65535):
            return False, "Port must be between 1 and 65535"

        return True, ""
