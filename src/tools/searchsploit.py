"""
Searchsploit Tool Wrapper
Search local Exploit-DB database for known exploits
"""

from .base import BaseTool
import re
import json


class SearchsploitTool(BaseTool):
    """
    Searchsploit wrapper for querying local Exploit-DB

    Safe tool - only searches database, no network activity
    """

    def __init__(self):
        super().__init__(
            name="searchsploit",
            command="searchsploit",
            default_timeout=30,
            requires_approval=False,  # Safe, read-only
            is_loud=False
        )

    def build_command(self, **kwargs) -> str:
        """
        Build searchsploit command

        Args:
            query: Search term (software name/version)
            strict: Strict vs fuzzy search
            exclude: Terms to exclude from results
            platform: Platform filter (linux, windows, etc.)
        """
        query = kwargs.get("query")
        strict = kwargs.get("strict", False)
        exclude = kwargs.get("exclude", [])
        platform = kwargs.get("platform", "")

        cmd_parts = ["searchsploit"]

        # Add strict flag
        if strict:
            cmd_parts.append("--strict")

        # Add platform filter
        if platform:
            cmd_parts.append(f"--platform {platform}")

        # Add exclusions
        for exclude_term in exclude:
            cmd_parts.append(f"--exclude '{exclude_term}'")

        # JSON output for easier parsing
        cmd_parts.append("--json")

        # Add query (must be last)
        cmd_parts.append(f"'{query}'")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse searchsploit JSON output

        Returns:
            dict with:
                - exploits: List of matching exploits
                - count: Number of results
                - query: Original search query
        """
        parsed = {
            "exploits": [],
            "count": 0,
            "query": ""
        }

        try:
            # Searchsploit outputs JSON with --json flag
            data = json.loads(output)

            if "RESULTS_EXPLOIT" in data:
                exploits = data["RESULTS_EXPLOIT"]
                parsed["count"] = len(exploits)

                for exploit in exploits:
                    parsed["exploits"].append({
                        "title": exploit.get("Title", ""),
                        "path": exploit.get("Path", ""),
                        "platform": exploit.get("Platform", ""),
                        "type": exploit.get("Type", ""),
                        "date": exploit.get("Date_Published", "")
                    })

        except json.JSONDecodeError:
            # Fallback to text parsing
            parsed = self._parse_text_output(output)

        return parsed

    def _parse_text_output(self, output: str) -> dict:
        """
        Fallback text parsing if JSON fails
        """
        parsed = {
            "exploits": [],
            "count": 0,
            "raw_text": output
        }

        # Extract exploit entries (simplified pattern)
        # Format: Title | Path
        lines = output.split('\n')
        for line in lines:
            if '|' in line and 'exploits/' in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    parsed["exploits"].append({
                        "title": parts[0].strip(),
                        "path": parts[1].strip()
                    })

        parsed["count"] = len(parsed["exploits"])
        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate searchsploit parameters"""
        query = kwargs.get("query")
        if not query:
            return False, "Query is required"

        if len(query) < 3:
            return False, "Query must be at least 3 characters"

        return True, ""