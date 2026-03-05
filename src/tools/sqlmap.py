"""
SQLMap Tool Wrapper
Automated SQL injection detection and exploitation
"""

from .base import BaseTool


class SQLMapTool(BaseTool):
    """
    SQLMap wrapper for SQL injection testing

    Supports:
    - Injection detection across multiple techniques
    - Database / table / column enumeration
    - GET and POST parameter testing
    - Configurable aggressiveness (level/risk)
    """

    # Enumeration flags for the --<flag> argument
    ENUMERATE_FLAGS = {
        "dbs":          "--dbs",
        "tables":       "--tables",
        "columns":      "--columns",
        "users":        "--users",
        "passwords":    "--passwords",
        "current-user": "--current-user",
    }

    def __init__(self):
        super().__init__(
            name="sqlmap",
            command="sqlmap",
            default_timeout=300,
            requires_approval=True,   # Can modify database contents
            is_loud=False
        )

    def build_command(self, **kwargs) -> str:
        """
        Build sqlmap command from parameters

        Args:
            target:     Target URL with parameter (e.g. "http://target/page.php?id=1")
            method:     HTTP method — "GET" or "POST" (default "GET")
            data:       POST body data (e.g. "username=admin&password=test")
            level:      Test level 1-5 (default 1 = basic)
            risk:       Risk level 1-3 (default 1 = safe only)
            technique:  Injection techniques string (default "BEUSTQ" = all)
            enumerate:  List of things to enumerate if injection found
                        (e.g. ["current-user", "dbs"])
        """
        target = kwargs.get("target", "")
        method = kwargs.get("method", "GET").upper()
        data = kwargs.get("data", "")
        level = kwargs.get("level", 1)
        risk = kwargs.get("risk", 1)
        technique = kwargs.get("technique", "BEUSTQ")
        enumerate_list = kwargs.get("enumerate", ["current-user", "dbs"])

        cmd_parts = [
            "sqlmap",
            "-u", target,
            "--method", method,
            f"--level={level}",
            f"--risk={risk}",
            f"--technique={technique}",
            "--batch",      # Non-interactive: always use default answers
            "--no-logging", # Suppress log file creation
        ]

        # POST data
        if data and method == "POST":
            cmd_parts += ["--data", data]

        # Enumeration flags
        for item in enumerate_list:
            flag = self.ENUMERATE_FLAGS.get(item)
            if flag:
                cmd_parts.append(flag)

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse sqlmap output into structured data

        Returns:
            dict with:
                - injectable: Whether injection was found
                - injection_points: List of vulnerable parameters
                - databases: Enumerated databases
                - users: Enumerated DB users
                - current_user: Current DB user
                - tables: Enumerated tables
        """
        parsed = {
            "injectable": False,
            "injection_points": [],
            "databases": [],
            "users": [],
            "current_user": "",
            "tables": [],
        }

        if not output:
            return parsed

        lines = output.splitlines()
        current_section = None

        for line in lines:
            line_stripped = line.strip()

            # Injection found indicator
            if "is vulnerable" in line_stripped or "appears to be injectable" in line_stripped:
                parsed["injectable"] = True

            # Injection point
            if "Parameter:" in line_stripped and "appears to be" in line_stripped:
                try:
                    param = line_stripped.split("Parameter:")[1].split("appears")[0].strip()
                    parsed["injection_points"].append(param)
                except IndexError:
                    pass

            # Section headers
            if "available databases" in line_stripped.lower():
                current_section = "databases"
            elif "database users" in line_stripped.lower():
                current_section = "users"
            elif "tables" in line_stripped.lower() and "entries" not in line_stripped.lower():
                current_section = "tables"
            elif "current user" in line_stripped.lower():
                current_section = "current_user"

            # Data lines (prefixed with [*] or indented)
            elif current_section and line_stripped.startswith("[*]"):
                value = line_stripped.lstrip("[*]").strip()
                if current_section == "databases":
                    parsed["databases"].append(value)
                elif current_section == "users":
                    parsed["users"].append(value)
                elif current_section == "tables":
                    parsed["tables"].append(value)
                elif current_section == "current_user":
                    parsed["current_user"] = value
                    current_section = None  # Reset after single value

        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate sqlmap parameters"""
        if not kwargs.get("target"):
            return False, "Target URL is required"

        level = kwargs.get("level", 1)
        if not (1 <= int(level) <= 5):
            return False, "Level must be between 1 and 5"

        risk = kwargs.get("risk", 1)
        if not (1 <= int(risk) <= 3):
            return False, "Risk must be between 1 and 3"

        method = kwargs.get("method", "GET").upper()
        if method not in {"GET", "POST"}:
            return False, "Method must be GET or POST"

        return True, ""
