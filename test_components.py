"""
Quick component verification test
Run this to make sure everything works before committing
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported"""
    print("="*60)
    print("TEST 1: Imports")
    print("="*60)

    try:
        from src.schemas import get_all_schemas, is_restricted
        print("[OK] Schemas module imported")

        from src.tools import ToolFactory, ToolStatus
        print("[OK] Tools module imported")

        from src.parsers import CommandSanitizer, OutputParser
        print("[OK] Parsers module imported")

        from src.agent import FunctionCallHandler
        print("[OK] Agent module imported")

        return True
    except Exception as e:
        print(f"[FAIL] Import failed: {e}")
        return False

def test_schemas():
    """Test tool schemas"""
    print("\n" + "="*60)
    print("TEST 2: Tool Schemas")
    print("="*60)

    try:
        from src.schemas import get_all_schemas, is_restricted, is_loud

        schemas = get_all_schemas()
        print(f"[OK] Found {len(schemas)} tool schemas")

        # Verify structure
        first_schema = schemas[0]
        assert "name" in first_schema
        assert "description" in first_schema
        assert "parameters" in first_schema
        print(f"[OK] Schema structure valid (tested {first_schema['name']})")

        # Test helper functions
        assert is_restricted("hydra") == True
        assert is_restricted("nmap") == False
        print("[OK] is_restricted() works")

        assert is_loud("hydra") == True
        print("[OK] is_loud() works")

        return True
    except Exception as e:
        print(f"[FAIL] Schema test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_tools():
    """Test tool factory and wrappers"""
    print("\n" + "="*60)
    print("TEST 3: Tool Wrappers")
    print("="*60)

    try:
        from src.tools import ToolFactory

        # Test factory
        tools = ToolFactory.list_tools()
        print(f"[OK] Tool factory has {len(tools)} tools: {', '.join(tools)}")

        # Test getting a tool
        nmap = ToolFactory.get_tool("nmap")
        assert nmap is not None
        print(f"[OK] Can retrieve nmap tool: {nmap.name}")

        # Test tool attributes
        assert hasattr(nmap, 'build_command')
        assert hasattr(nmap, 'parse_output')
        assert hasattr(nmap, 'execute')
        print("[OK] Tool has required methods")

        # Test command building (without executing)
        cmd = nmap.build_command(target="127.0.0.1", scan_type="ping_sweep")
        assert "nmap" in cmd
        assert "127.0.0.1" in cmd
        print(f"[OK] Can build command: {cmd[:50]}...")

        return True
    except Exception as e:
        print(f"[FAIL] Tool test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_sanitizer():
    """Test command sanitization"""
    print("\n" + "="*60)
    print("TEST 4: Command Sanitization")
    print("="*60)

    try:
        from src.parsers import CommandSanitizer

        sanitizer = CommandSanitizer()

        # Test valid command
        is_safe, cmd, reason = sanitizer.sanitize("nmap -sS 192.168.1.50", "nmap")
        assert is_safe == True
        print("[OK] Allows valid private IP scan")

        # Test blocked external IP
        is_safe, cmd, reason = sanitizer.sanitize("nmap -sS 8.8.8.8", "nmap")
        assert is_safe == False
        print(f"[OK] Blocks external IP: {reason}")

        # Test command injection
        is_safe, cmd, reason = sanitizer.sanitize("nmap 127.0.0.1; rm -rf /", "nmap")
        assert is_safe == False
        print(f"[OK] Blocks command injection: {reason}")

        return True
    except Exception as e:
        print(f"[FAIL] Sanitizer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_parser():
    """Test output parser"""
    print("\n" + "="*60)
    print("TEST 5: Output Parser")
    print("="*60)

    try:
        from src.parsers import OutputParser

        parser = OutputParser()

        # Test with mock nmap data
        mock_data = {
            "hosts": [{"ip": "192.168.1.50", "hostname": "", "ports": []}],
            "open_ports": [
                {"host": "192.168.1.50", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4"},
            ]
        }

        parsed = parser.parse("nmap", "", mock_data)

        assert parsed.tool_name == "nmap"
        assert len(parsed.findings) > 0
        assert parsed.severity in ["critical", "high", "medium", "low", "info"]
        print(f"[OK] Parser creates structured output")
        print(f"  - Summary: {parsed.summary}")
        print(f"  - Severity: {parsed.severity}")
        print(f"  - Findings: {len(parsed.findings)}")

        # Test LLM formatting
        llm_text = parser.format_for_llm(parsed)
        assert "NMAP Results" in llm_text
        print("[OK] Can format for LLM")

        return True
    except Exception as e:
        print(f"[FAIL] Parser test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_function_calling():
    """Test function calling handler"""
    print("\n" + "="*60)
    print("TEST 6: Function Calling")
    print("="*60)

    try:
        from src.agent import FunctionCallHandler

        handler = FunctionCallHandler(verbose=False)

        # Test getting schemas
        schemas = handler.get_tool_schemas_for_llm()
        assert len(schemas) > 0
        print(f"[OK] Handler provides {len(schemas)} schemas to LLM")

        # Test parsing function call (OpenAI format)
        mock_llm_response = {
            "function_call": {
                "name": "nmap",
                "arguments": '{"target": "127.0.0.1", "scan_type": "ping_sweep"}'
            }
        }

        function_call = handler.parse_llm_function_call(mock_llm_response)
        assert function_call is not None
        assert function_call.name == "nmap"
        print(f"[OK] Can parse LLM function call: {function_call.name}")

        return True
    except Exception as e:
        print(f"[FAIL] Function calling test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("VENOMX AGENT - COMPONENT VERIFICATION")
    print("="*70)

    tests = [
        ("Imports", test_imports),
        ("Schemas", test_schemas),
        ("Tools", test_tools),
        ("Sanitizer", test_sanitizer),
        ("Parser", test_parser),
        ("Function Calling", test_function_calling),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[FAIL] {name} test crashed: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[OK] PASS" if result else "[FAIL] FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n*** ALL TESTS PASSED! Ready to commit. ***")
        return True
    else:
        print(f"\n*** WARNING: {total - passed} test(s) failed. Review errors above. ***")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
