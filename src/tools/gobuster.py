"""
Gobuster Tool Wrapper
Directory and file brute-forcing for web servers
"""

from .base import BaseTool


class GobusterTool(BaseTool):
    """
    Gobuster directory/file brute-forcer wrapper

    Supports:
    - Directory enumeration
    - File extension brute-forcing
    - Custom status code filtering
    - Threaded parallel requests
    """

    # Logical wordlist names to filesystem paths (standard Kali/Debian installs)
    WORDLISTS = {
        "common":  "/usr/share/wordlists/dirb/common.txt",
        "medium":  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "large":   "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        "api":     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "admin":   "/usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt",
    }

    def __init__(self):
        super().__init__(
            name="gobuster",
            command="gobuster",
            default_timeout=300,
            requires_approval=False,
            is_loud=True
        )

    def build_command(self, **kwargs) -> str:
        """
        Build gobuster command from parameters

        Args:
            target:       Base URL to scan (e.g. "http://192.168.1.50")
            wordlist:     Logical wordlist name — "common", "medium", "large", "api", "admin"
            extensions:   List of file extensions (e.g. ["php", "html", "txt"])
            status_codes: HTTP status codes to report (e.g. [200, 301, 403])
            threads:      Concurrent request threads (1-50)
        """
        target = kwargs.get("target", "")
        wordlist_key = kwargs.get("wordlist", "common")
        extensions = kwargs.get("extensions", ["php", "html", "txt"])
        status_codes = kwargs.get("status_codes", [200, 301, 302, 401, 403])
        threads = kwargs.get("threads", 10)

        wordlist_path = self.WORDLISTS.get(wordlist_key, self.WORDLISTS["common"])

        cmd_parts = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist_path,
            "-t", str(threads),
            "-q",           # Quiet: only print results
            "--no-error",   # Don't print errors for each request
        ]

        if extensions:
            cmd_parts += ["-x", ",".join(extensions)]

        if status_codes:
            cmd_parts += ["-s", ",".join(str(c) for c in status_codes)]

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse gobuster output into structured data

        Returns:
            dict with:
                - paths: List of discovered paths with status codes
                - path_count: Total paths found
        """
        parsed = {
            "paths": [],
            "path_count": 0,
        }

        if not output:
            return parsed

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Gobuster quiet output format: "/path (Status: 200) [Size: 1234]"
            if line.startswith("/") or "(Status:" in line:
                path = ""
                status = 0
                size = 0

                # Extract path
                parts = line.split()
                if parts:
                    path = parts[0]

                # Extract status code
                if "(Status:" in line:
                    try:
                        status_part = line.split("(Status:")[1]
                        status = int(status_part.split(")")[0].strip())
                    except (IndexError, ValueError):
                        pass

                # Extract size
                if "[Size:" in line:
                    try:
                        size_part = line.split("[Size:")[1]
                        size = int(size_part.split("]")[0].strip())
                    except (IndexError, ValueError):
                        pass

                if path:
                    parsed["paths"].append({
                        "path": path,
                        "status": status,
                        "size": size,
                    })

        parsed["path_count"] = len(parsed["paths"])
        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate gobuster parameters"""
        if not kwargs.get("target"):
            return False, "Target URL is required"

        wordlist = kwargs.get("wordlist", "common")
        if wordlist not in self.WORDLISTS:
            return False, f"Invalid wordlist. Must be one of: {list(self.WORDLISTS.keys())}"

        threads = kwargs.get("threads", 10)
        if not (1 <= int(threads) <= 50):
            return False, "Threads must be between 1 and 50"

        return True, ""
