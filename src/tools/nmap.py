"""
Nmap Tool Wrapper
Network scanning and service detection
"""

from .base import BaseTool
import re
import json


class NmapTool(BaseTool):
    """
    Nmap network scanner wrapper

    Supports:
    - Host discovery (ping sweeps)
    - Port scanning
    - Service/version detection
    - OS fingerprinting
    - Stealth and aggressive scans
    """

    # Scan type to nmap flags mapping
    SCAN_TYPES = {
        "ping_sweep": "-sn",  # Ping scan only, no port scan
        "port_scan": "-sS",   # SYN scan (requires root)
        "service_scan": "-sV",  # Service version detection
        "os_detection": "-O",  # OS fingerprinting
        "aggressive": "-A",   # Aggressive (OS, version, scripts, traceroute)
        "stealth": "-sS -T2",  # Stealth SYN scan, slow timing
    }

    def __init__(self):
        super().__init__(
            name="nmap",
            command="nmap",
            default_timeout=600,  # 10 minutes for large scans
            requires_approval=False,
            is_loud=False  # Can be loud depending on scan type
        )

    def build_command(self, **kwargs) -> str:
        """
        Build nmap command from parameters

        Args:
            target: IP address or CIDR range
            scan_type: Type of scan to perform
            ports: Port specification (optional)
            timing: Timing template 0-5
            exclude: List of IPs to exclude
        """
        target = kwargs.get("target")
        scan_type = kwargs.get("scan_type", "port_scan")
        ports = kwargs.get("ports", "")
        timing = kwargs.get("timing", 3)
        exclude = kwargs.get("exclude", [])

        # Base command
        cmd_parts = ["nmap"]

        # Add scan type flags
        scan_flags = self.SCAN_TYPES.get(scan_type, "-sS")
        cmd_parts.append(scan_flags)

        # Add timing
        cmd_parts.append(f"-T{timing}")

        # Add port specification if provided
        if ports:
            cmd_parts.append(f"-p {ports}")

        # Add exclusions (safety feature)
        if exclude:
            exclude_list = ",".join(exclude)
            cmd_parts.append(f"--exclude {exclude_list}")

        # Output in XML for better parsing
        cmd_parts.append("-oX -")  # Output XML to stdout

        # Disable DNS resolution for speed
        cmd_parts.append("-n")

        # Add target
        cmd_parts.append(target)

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> dict:
        """
        Parse nmap XML output into structured data

        Returns:
            dict with:
                - hosts: List of discovered hosts
                - open_ports: List of open ports with services
                - os_matches: OS detection results
                - scan_stats: Scan statistics
        """
        parsed = {
            "hosts": [],
            "open_ports": [],
            "os_matches": [],
            "scan_stats": {}
        }

        if not output or "<nmaprun" not in output:
            # Fallback to text parsing if XML not available
            return self._parse_text_output(output)

        try:
            # Parse XML (simplified - full implementation would use xml.etree)
            # Extract hosts
            host_pattern = r'<host.*?</host>'
            hosts = re.findall(host_pattern, output, re.DOTALL)

            for host in hosts:
                # Extract IP address
                ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', host)
                if not ip_match:
                    continue
                ip = ip_match.group(1)

                # Extract hostname if available
                hostname_match = re.search(r'<hostname name="([^"]+)"', host)
                hostname = hostname_match.group(1) if hostname_match else ""

                # Extract open ports
                port_pattern = r'<port protocol="([^"]+)" portid="(\d+)">.*?<state state="open".*?<service name="([^"]+)".*?(?:product="([^"]+)")?.*?(?:version="([^"]+)")?'
                ports = re.findall(port_pattern, host, re.DOTALL)

                host_data = {
                    "ip": ip,
                    "hostname": hostname,
                    "ports": []
                }

                for protocol, port, service, product, version in ports:
                    port_data = {
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "product": product or "",
                        "version": version or ""
                    }
                    host_data["ports"].append(port_data)
                    parsed["open_ports"].append({
                        "host": ip,
                        **port_data
                    })

                # Extract OS detection if available
                os_pattern = r'<osmatch name="([^"]+)" accuracy="(\d+)"'
                os_matches = re.findall(os_pattern, host)
                if os_matches:
                    parsed["os_matches"].extend([
                        {"os": name, "accuracy": int(acc), "host": ip}
                        for name, acc in os_matches
                    ])

                parsed["hosts"].append(host_data)

            # Extract scan stats
            stats_match = re.search(r'<runstats>.*?<finished time="(\d+)".*?timestr="([^"]+)".*?<hosts up="(\d+)" down="(\d+)" total="(\d+)"', output, re.DOTALL)
            if stats_match:
                parsed["scan_stats"] = {
                    "timestamp": int(stats_match.group(1)),
                    "timestr": stats_match.group(2),
                    "hosts_up": int(stats_match.group(3)),
                    "hosts_down": int(stats_match.group(4)),
                    "hosts_total": int(stats_match.group(5))
                }

        except Exception as e:
            parsed["parse_error"] = str(e)

        return parsed

    def _parse_text_output(self, output: str) -> dict:
        """
        Fallback text parsing for when XML isn't available
        """
        parsed = {
            "hosts": [],
            "open_ports": [],
            "raw_text": output
        }

        # Extract IP addresses
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ips = re.findall(ip_pattern, output)

        # Extract port information
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        ports = re.findall(port_pattern, output)

        for port, protocol, service in ports:
            parsed["open_ports"].append({
                "port": int(port),
                "protocol": protocol,
                "service": service
            })

        return parsed

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """Validate nmap parameters"""
        target = kwargs.get("target")
        if not target:
            return False, "Target is required"

        scan_type = kwargs.get("scan_type")
        if scan_type and scan_type not in self.SCAN_TYPES:
            return False, f"Invalid scan_type. Must be one of: {list(self.SCAN_TYPES.keys())}"

        timing = kwargs.get("timing", 3)
        if not (0 <= timing <= 5):
            return False, "Timing must be between 0 and 5"

        return True, ""