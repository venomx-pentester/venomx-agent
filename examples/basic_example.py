"""
Basic Example: VenomX Agent Usage
Demonstrates core functionality without requiring full LLM integration
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tools import ToolFactory, ToolStatus
from src.parsers import CommandSanitizer, OutputParser
from src.schemas import get_all_schemas, is_restricted


def demo_tool_execution():
    """Demonstrate tool execution"""
    print("="*60)
    print("DEMO 1: Tool Execution")
    print("="*60)

    # Get nmap tool
    nmap = ToolFactory.get_tool("nmap")
    print(f"✓ Loaded tool: {nmap.name}")

    # Execute a simple scan
    print("\nExecuting: nmap ping sweep on localhost")
    result = nmap.execute(
        target="127.0.0.1",
        scan_type="ping_sweep",
        timing=3
    )

    print(f"Status: {result.status.value}")
    print(f"Exit Code: {result.exit_code}")
    print(f"Execution Time: {result.execution_time:.2f}s")
    print(f"\nOutput (first 500 chars):\n{result.output[:500]}")

    if result.metadata:
        print(f"\nParsed Metadata:")
        print(f"  Hosts: {len(result.metadata.get('hosts', []))}")
        print(f"  Open Ports: {len(result.metadata.get('open_ports', []))}")


def demo_command_sanitization():
    """Demonstrate command sanitization"""
    print("\n" + "="*60)
    print("DEMO 2: Command Sanitization")
    print("="*60)

    sanitizer = CommandSanitizer()

    test_cases = [
        ("nmap -sS 192.168.1.50", "nmap", "Valid private IP"),
        ("nmap -sS 8.8.8.8", "nmap", "Blacklisted IP (Google DNS)"),
        ("nmap -sS 192.168.1.1; rm -rf /", "nmap", "Command injection attempt"),
        ("searchsploit apache 2.4", "searchsploit", "Safe searchsploit query"),
    ]

    for command, tool, description in test_cases:
        is_safe, sanitized, reason = sanitizer.sanitize(command, tool)
        status = "✓ SAFE" if is_safe else "✗ BLOCKED"
        print(f"\n{status}: {description}")
        print(f"  Command: {command}")
        if not is_safe:
            print(f"  Reason: {reason}")


def demo_output_parsing():
    """Demonstrate output parsing"""
    print("\n" + "="*60)
    print("DEMO 3: Output Parsing")
    print("="*60)

    parser = OutputParser()

    # Simulate nmap scan result
    mock_metadata = {
        "hosts": [{"ip": "192.168.1.50", "hostname": "target.local", "ports": []}],
        "open_ports": [
            {"host": "192.168.1.50", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4"},
            {"host": "192.168.1.50", "port": 80, "service": "http", "product": "Apache", "version": "2.4.6"},
            {"host": "192.168.1.50", "port": 3306, "service": "mysql", "product": "MySQL", "version": "5.5.62"},
        ],
        "os_matches": [{"os": "Linux 3.X", "accuracy": 95, "host": "192.168.1.50"}]
    }

    parsed = parser.parse("nmap", "", mock_metadata)

    print(f"\nSummary: {parsed.summary}")
    print(f"Severity: {parsed.severity.upper()}")
    print(f"\nFindings ({len(parsed.findings)}):")
    for i, finding in enumerate(parsed.findings[:5], 1):  # Show first 5
        print(f"  {i}. [{finding['severity'].upper()}] {finding['description']}")

    print(f"\nRecommendations ({len(parsed.recommendations)}):")
    for i, rec in enumerate(parsed.recommendations[:3], 1):  # Show first 3
        print(f"  {i}. {rec}")

    print(f"\nFormatted for LLM:")
    print(parser.format_for_llm(parsed))


def demo_tool_schemas():
    """Demonstrate tool schemas"""
    print("\n" + "="*60)
    print("DEMO 4: Tool Schemas for LLM")
    print("="*60)

    schemas = get_all_schemas()

    print(f"Total tools available: {len(schemas)}")
    print("\nTools:")
    for schema in schemas:
        name = schema["name"]
        restricted = "🔒 REQUIRES APPROVAL" if is_restricted(name) else "✓ Auto-approved"
        print(f"  - {name}: {restricted}")

    print("\nExample Schema (nmap):")
    nmap_schema = [s for s in schemas if s["name"] == "nmap"][0]
    print(f"  Description: {nmap_schema['description'][:100]}...")
    print(f"  Parameters: {list(nmap_schema['parameters']['properties'].keys())}")


def demo_tool_factory():
    """Demonstrate tool factory"""
    print("\n" + "="*60)
    print("DEMO 5: Tool Factory")
    print("="*60)

    available_tools = ToolFactory.list_tools()
    print(f"Available tools: {', '.join(available_tools)}")

    # Test tool loading
    for tool_name in available_tools:
        tool = ToolFactory.get_tool(tool_name)
        print(f"  ✓ {tool_name}: {tool.__class__.__name__}")


def main():
    """Run all demos"""
    print("\n" + "="*70)
    print("VenomX Agent - Component Demos")
    print("="*70)

    try:
        demo_tool_factory()
        demo_tool_schemas()
        demo_command_sanitization()
        demo_output_parsing()

        # Only run actual tool execution if tools are installed
        print("\n" + "="*60)
        print("DEMO: Live Tool Execution")
        print("="*60)

        try:
            demo_tool_execution()
        except FileNotFoundError:
            print("⚠ Nmap not installed. Skipping live execution demo.")
            print("  Install with: sudo apt-get install nmap (Linux)")
            print("              : brew install nmap (macOS)")

        print("\n" + "="*70)
        print("✓ All demos completed successfully!")
        print("="*70)

    except Exception as e:
        print(f"\n✗ Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
