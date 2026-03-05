"""
Hydra Tool Wrapper
Network authentication brute-forcing
"""

from .base import BaseTool


class HydraTool(BaseTool):
    """
    Hydra network authentication brute-forcer wrapper

    Supports:
    - SSH, FTP, HTTP, RDP, MySQL, PostgreSQL
    - Custom username / username list
    - Predefined password wordlists
    - Parallel task control
    """

    # Password wordlist logical names to filesystem paths
    PASSWORD_LISTS = {
        "common":      "/usr/share/wordlists/fasttrack.txt",
        "rockyou-100": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
        "default":     "/usr/share/seclists/Passwords/Default-Credentials/default-passwords-for-services-shortened.txt",
        "weak":        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-500.txt",
    }

    # Username list logical names to filesystem paths
    USERNAME_LISTS = {
        "common":  "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "top100":  "/usr/share/seclists/Usernames/Names/names.txt",
        "default": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    }

    def __init__(self):
        super().__init__(
            name="hydra",
            command="hydra",
            default_timeout=300,
            requires_approval=True,   # Loud + disruptive: require approval
            is_loud=True
        )

    def build_command(self, **kwargs) -> str:
        """
        Build hydra command from parameters

        Args:
            target:          Target IP or hostname
            service:         Protocol — "ssh", "ftp", "http-get", "http-post",
                             "rdp", "mysql", "postgres"
            username:        Single username to test (takes precedence over username_list)
            username_list:   Logical username list name — "common", "top100", "default"
            password_list:   Logical password list name — "common", "rockyou-100", "default", "weak"
            port:            Target port (0 = service default)
            threads:         Parallel tasks (default 4, max 16)
            stop_on_success: Stop after first valid credential (default True)
        """
        target = kwargs.get("target", "")
        service = kwargs.get("service", "ssh")
        username = kwargs.get("username", "")
        username_list_key = kwargs.get("username_list", "common")
        password_list_key = kwargs.get("password_list", "common")
        port = kwargs.get("port", 0)
        threads = min(int(kwargs.get("threads", 4)), 16)
        stop_on_success = kwargs.get("stop_on_success", True)

        password_path = self.PASSWORD_LISTS.get(password_list_key, self.PASSWORD_LISTS["common"])

        cmd_parts = ["hydra"]

        # Username: single value takes precedence over list
        if username:
            cmd_parts += ["-l", username]
        else:
            user_path = self.USERNAME_LISTS.get(username_list_key, self.USERNAME_LISTS["common"])
            cmd_parts += ["-L", user_path]

        # Password list
        cmd_parts += ["-P", password_path]

        # Optional port override
        if port and int(port) > 0:
            cmd_parts += ["-s", str(port)]

        # Threads
        cmd_parts += ["-t", str(threads)]

        # Stop on first success
        if stop_on_success:
            cmd_parts.append("-f")

        # Disable verbose output noise; -I skips restore file prompt
        cmd_parts += ["-V", "-I"]

        # Target and service
        cmd_parts += [target, service]

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse hydra output for successful credentials

        Returns:
            dict with:
                - credentials: List of {"host", "port", "service", "login", "password"}
                - credential_count: Number of valid creds found
                - attack_complete: Whether the full wordlist was exhausted
        """
        parsed = {
            "credentials": [],
            "credential_count": 0,
            "attack_complete": False,
        }

        if not output:
            return parsed

        for line in output.splitlines():
            line = line.strip()

            # Hydra success line format:
            # "[port][service] host: 192.168.1.50   login: admin   password: secret"
            if "login:" in line and "password:" in line and "host:" in line:
                cred = {"host": "", "port": 0, "service": "", "login": "", "password": ""}

                # Extract bracketed [port][service] prefix
                if line.startswith("["):
                    try:
                        port_part = line.split("]")[0].lstrip("[")
                        service_part = line.split("]")[1].lstrip("[")
                        cred["port"] = int(port_part)
                        cred["service"] = service_part
                    except (IndexError, ValueError):
                        pass

                # Extract host
                if "host:" in line:
                    try:
                        cred["host"] = line.split("host:")[1].split()[0].strip()
                    except IndexError:
                        pass

                # Extract login
                if "login:" in line:
                    try:
                        cred["login"] = line.split("login:")[1].split()[0].strip()
                    except IndexError:
                        pass

                # Extract password
                if "password:" in line:
                    try:
                        cred["password"] = line.split("password:")[1].strip()
                    except IndexError:
                        pass

                parsed["credentials"].append(cred)

            # Completion indicator
            elif "1 valid password found" in line or "valid passwords found" in line:
                parsed["attack_complete"] = True

        parsed["credential_count"] = len(parsed["credentials"])
        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate hydra parameters"""
        if not kwargs.get("target"):
            return False, "Target is required"

        service = kwargs.get("service")
        valid_services = {"ssh", "ftp", "http-get", "http-post", "rdp", "mysql", "postgres"}
        if not service or service not in valid_services:
            return False, f"Invalid service. Must be one of: {sorted(valid_services)}"

        username_list = kwargs.get("username_list")
        if username_list and username_list not in self.USERNAME_LISTS:
            return False, f"Invalid username_list '{username_list}'. Must be one of: {list(self.USERNAME_LISTS.keys())}"

        password_list = kwargs.get("password_list")
        if password_list and password_list not in self.PASSWORD_LISTS:
            return False, f"Invalid password_list '{password_list}'. Must be one of: {list(self.PASSWORD_LISTS.keys())}"

        threads = kwargs.get("threads", 4)
        if not (1 <= int(threads) <= 16):
            return False, "Threads must be between 1 and 16"

        return True, ""
