"""
Output Parser Module
Parses and structures tool outputs for LLM consumption
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import re
import json


@dataclass
class ParsedOutput:
    """Structured output from parsing"""
    tool_name: str
    summary: str  # Human-readable summary for LLM
    structured_data: Dict[str, Any]  # Structured data for programmatic use
    findings: List[Dict[str, Any]]  # Key findings (vulnerabilities, open ports, etc.)
    severity: str  # overall, medium, low, info
    recommendations: List[str]  # Suggested next steps


class OutputParser:
    """
    Parses tool outputs and structures them for LLM reasoning

    Responsibilities:
    - Extract key information from raw tool output
    - Classify findings by severity
    - Generate human-readable summaries
    - Suggest next steps based on findings
    """

    def parse(self, tool_name: str, raw_output: str, metadata: Dict[str, Any] = None) -> ParsedOutput:
        """
        Parse tool output based on tool type

        Args:
            tool_name: Name of the tool that generated output
            raw_output: Raw command output
            metadata: Additional metadata from tool execution

        Returns:
            ParsedOutput with structured information
        """
        metadata = metadata or {}

        # Route to tool-specific parser
        parser_method = getattr(self, f"_parse_{tool_name}", None)
        if parser_method:
            return parser_method(raw_output, metadata)
        else:
            # Generic fallback parser
            return self._parse_generic(tool_name, raw_output, metadata)

    def _parse_nmap(self, raw_output: str, metadata: Dict[str, Any]) -> ParsedOutput:
        """Parse nmap scan results"""
        findings = []
        recommendations = []

        # Extract data from metadata (already parsed by NmapTool)
        hosts = metadata.get("hosts", [])
        open_ports = metadata.get("open_ports", [])
        os_matches = metadata.get("os_matches", [])

        # Analyze findings
        for port_info in open_ports:
            host = port_info.get("host")
            port = port_info.get("port")
            service = port_info.get("service")
            product = port_info.get("product", "")
            version = port_info.get("version", "")

            severity = self._assess_port_severity(port, service)

            finding = {
                "type": "open_port",
                "host": host,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "severity": severity,
                "description": f"Port {port}/{service} open on {host}" + (f" ({product} {version})" if product else "")
            }
            findings.append(finding)

            # Generate recommendations
            if service in ["ssh", "ftp", "telnet", "rdp"]:
                recommendations.append(f"Test {service} on {host}:{port} for weak credentials using hydra")

            if service in ["http", "https", "http-proxy"]:
                recommendations.append(f"Scan web server on {host}:{port} with nikto and gobuster")

            if version and service:
                recommendations.append(f"Search for exploits: '{service} {version}' using searchsploit")

        # Generate summary
        num_hosts = len(hosts)
        num_ports = len(open_ports)
        summary = f"Scan complete. Found {num_hosts} host(s) with {num_ports} open port(s)."

        if os_matches:
            top_os = os_matches[0]
            summary += f" Likely OS: {top_os['os']} ({top_os['accuracy']}% confidence)."

        # Determine overall severity
        severities = [f["severity"] for f in findings]
        overall_severity = self._calculate_overall_severity(severities)

        return ParsedOutput(
            tool_name="nmap",
            summary=summary,
            structured_data=metadata,
            findings=findings,
            severity=overall_severity,
            recommendations=recommendations
        )

    def _parse_searchsploit(self, raw_output: str, metadata: Dict[str, Any]) -> ParsedOutput:
        """Parse searchsploit results"""
        findings = []
        recommendations = []

        exploits = metadata.get("exploits", [])
        count = metadata.get("count", 0)

        for exploit in exploits:
            title = exploit.get("title", "")
            path = exploit.get("path", "")
            platform = exploit.get("platform", "")
            exploit_type = exploit.get("type", "")

            # Assess severity based on exploit type
            severity = "critical" if "remote" in exploit_type.lower() else "high"

            finding = {
                "type": "exploit_available",
                "title": title,
                "path": path,
                "platform": platform,
                "exploit_type": exploit_type,
                "severity": severity,
                "description": f"Exploit found: {title}"
            }
            findings.append(finding)

        # Generate summary
        if count == 0:
            summary = "No exploits found in Exploit-DB."
            overall_severity = "info"
        else:
            summary = f"Found {count} exploit(s) in Exploit-DB."
            overall_severity = "high"  # If exploits exist, it's concerning

            # Recommendations
            recommendations.append("Review exploit code to understand attack vectors")
            recommendations.append("Test if target is vulnerable using Metasploit or manual exploitation")
            recommendations.append("Check CVE database for more details on these vulnerabilities")

        return ParsedOutput(
            tool_name="searchsploit",
            summary=summary,
            structured_data=metadata,
            findings=findings,
            severity=overall_severity,
            recommendations=recommendations
        )

    def _parse_nikto(self, raw_output: str, metadata: Dict[str, Any]) -> ParsedOutput:
        """Parse nikto web scan results"""
        findings = []
        recommendations = []

        # Nikto output parsing (text-based)
        lines = raw_output.split('\n')

        for line in lines:
            # Look for vulnerability indicators
            if '+ OSVDB-' in line or '+ CVE-' in line:
                severity = "medium"  # Default for nikto findings

                # Extract vulnerability details
                finding = {
                    "type": "web_vulnerability",
                    "severity": severity,
                    "description": line.strip(),
                    "raw": line
                }
                findings.append(finding)

        # Summary
        vuln_count = len(findings)
        summary = f"Web scan complete. Found {vuln_count} potential issue(s)."

        if vuln_count > 0:
            recommendations.append("Manually verify findings to eliminate false positives")
            recommendations.append("Test for SQL injection using sqlmap on identified forms")
            recommendations.append("Run gobuster to discover hidden directories")

        overall_severity = "medium" if vuln_count > 0 else "info"

        return ParsedOutput(
            tool_name="nikto",
            summary=summary,
            structured_data={"findings_count": vuln_count},
            findings=findings,
            severity=overall_severity,
            recommendations=recommendations
        )

    def _parse_generic(self, tool_name: str, raw_output: str, metadata: Dict[str, Any]) -> ParsedOutput:
        """Generic parser for tools without specific parsers"""
        # Try to extract useful information generically
        findings = []

        # Look for common indicators
        if "error" in raw_output.lower() or "failed" in raw_output.lower():
            severity = "info"
            summary = f"{tool_name} completed with errors. Review output for details."
        else:
            severity = "info"
            summary = f"{tool_name} completed successfully."

        return ParsedOutput(
            tool_name=tool_name,
            summary=summary,
            structured_data=metadata,
            findings=findings,
            severity=severity,
            recommendations=[]
        )

    def _assess_port_severity(self, port: int, service: str) -> str:
        """Assess security severity of an open port"""
        # Critical ports
        if port in [21, 23, 445, 3389, 3306, 5432, 5900]:  # FTP, Telnet, SMB, RDP, MySQL, PostgreSQL, VNC
            return "high"

        # Medium risk ports
        if port in [22, 25, 53, 80, 443, 8080, 8443]:  # SSH, SMTP, DNS, HTTP/HTTPS
            return "medium"

        # Everything else
        return "low"

    def _calculate_overall_severity(self, severities: List[str]) -> str:
        """Calculate overall severity from list of individual severities"""
        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        elif "low" in severities:
            return "low"
        else:
            return "info"

    def format_for_llm(self, parsed: ParsedOutput) -> str:
        """
        Format parsed output for LLM consumption

        Returns:
            Well-structured text summary for LLM reasoning
        """
        output_lines = []

        # Header
        output_lines.append(f"=== {parsed.tool_name.upper()} Results ===\n")

        # Summary
        output_lines.append(f"Summary: {parsed.summary}")
        output_lines.append(f"Severity: {parsed.severity.upper()}\n")

        # Findings
        if parsed.findings:
            output_lines.append(f"Findings ({len(parsed.findings)}):")
            for i, finding in enumerate(parsed.findings, 1):
                desc = finding.get("description", "")
                sev = finding.get("severity", "info")
                output_lines.append(f"  {i}. [{sev.upper()}] {desc}")
            output_lines.append("")

        # Recommendations
        if parsed.recommendations:
            output_lines.append("Recommended Next Steps:")
            for i, rec in enumerate(parsed.recommendations, 1):
                output_lines.append(f"  {i}. {rec}")
            output_lines.append("")

        return "\n".join(output_lines)
