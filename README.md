# VenomX Agent - AI-Powered Penetration Testing

**Vulnerability Exploitation via Neural Operative Model**

This repository contains the **Agent & Tools** component of the VenomX capstone project - an AI-powered penetration testing assistant that leverages local LLMs for autonomous security testing.

## 🎯 What's Implemented

### ✅ Completed Tasks

#### Phase 2

- [x] **Task #245**: Command Sanitization - Security layer preventing command injection, IP whitelisting, dangerous command detection
- [x] **Task #243**: Output Parsing - Structured parsing of tool outputs with severity assessment and recommendations
- [x] **Task #173**: Tool Schemas - JSON schemas for 7 security tools (nmap, nikto, gobuster, hydra, sqlmap, searchsploit, metasploit)
- [x] **Task #174**: Basic Agent Loop - Core orchestration loop (Reason → Tool Call → Analyze → Repeat)
- [x] **Task #171**: JSON Function Calling - LLM-to-tool bridge supporting multiple LLM formats (OpenAI, Claude, Llama)
- [x] **Task #172**: Tool Wrappers - Python wrappers for tool execution with error handling

## 📁 Project Structure

```
venomx-agent/
├── src/
│   ├── agent/              # Agent loop and function calling
│   │   ├── agent_loop.py   # Main agent orchestration
│   │   └── function_calling.py  # LLM function call handler
│   ├── tools/              # Security tool wrappers
│   │   ├── base.py         # Base tool class
│   │   ├── nmap.py         # Nmap wrapper
│   │   └── searchsploit.py # Searchsploit wrapper
│   ├── schemas/            # Tool schemas for LLM
│   │   └── tool_schemas.py # JSON schemas for all tools
│   ├── parsers/            # Output parsing and sanitization
│   │   ├── output_parser.py  # Parse tool outputs
│   │   └── sanitizer.py      # Command sanitization
│   └── utils/              # Utilities (TODO)
├── tests/                  # Unit and integration tests (TODO)
├── config/                 # Configuration files (TODO)
├── docs/                   # Documentation
└── README.md
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd venomx-agent

# Install dependencies (requirements.txt TODO)
pip install -r requirements.txt

# Ensure security tools are installed
# Ubuntu/Debian:
sudo apt-get install nmap nikto gobuster hydra sqlmap exploitdb

# macOS:
brew install nmap nikto gobuster hydra sqlmap exploitdb
```

### Basic Usage

```python
from src.agent import VenomXAgent, OllamaClient, interactive_approval

# Initialize LLM client (Ollama with Llama 3.3 70B)
llm = OllamaClient(model="llama3.3:70b")

# Create agent with human approval for restricted tools
agent = VenomXAgent(
    llm_client=llm,
    approval_callback=interactive_approval,
    verbose=True
)

# Run a pentesting task
response = agent.run(
    "Scan 192.168.1.0/24 for devices and identify open ports",
    target_network="192.168.1.0/24",
    excluded_ips=["192.168.1.1"]  # Exclude router
)

print(response)

# Get detailed findings
findings = agent.get_findings()
for finding in findings:
    print(f"{finding['tool']}: {finding['data']}")
```

## 🔧 Component Details

### 1. Tool Schemas (`src/schemas/tool_schemas.py`)

Defines JSON schemas for LLM function calling. Each tool has:

- **Name**: Tool identifier
- **Description**: What the tool does and when to use it
- **Parameters**: Required and optional parameters with types and validation

Example:

```python
from src.schemas import get_all_schemas, is_restricted

# Get all schemas for LLM
schemas = get_all_schemas()

# Check if tool requires approval
if is_restricted("hydra"):
    print("This tool requires human approval")
```

### 2. Tool Wrappers (`src/tools/`)

Implements tool execution with:

- **Command building** from parameters
- **Output parsing** into structured data
- **Error handling** and timeouts
- **Safety checks** via command sanitization

Example:

```python
from src.tools import ToolFactory

# Get tool instance
nmap = ToolFactory.get_tool("nmap")

# Execute scan
result = nmap.execute(
    target="192.168.1.50",
    scan_type="service_scan",
    ports="1-1000",
    timing=3
)

print(f"Status: {result.status}")
print(f"Output: {result.output}")
print(f"Parsed data: {result.metadata}")
```

### 3. Command Sanitization (`src/parsers/sanitizer.py`)

Security layer that prevents:

- **Command injection** (shell metacharacters)
- **Unauthorized scanning** (IP whitelisting/blacklisting)
- **Dangerous operations** (rm, dd, etc.)
- **Path traversal** (../, etc.)

Example:

```python
from src.parsers import CommandSanitizer

sanitizer = CommandSanitizer()

# Sanitize command
is_safe, sanitized, reason = sanitizer.sanitize(
    "nmap -sS 192.168.1.50",
    tool_name="nmap"
)

if is_safe:
    print(f"Safe to execute: {sanitized}")
else:
    print(f"Blocked: {reason}")
```

### 4. Output Parsing (`src/parsers/output_parser.py`)

Parses raw tool output into structured findings:

- **Severity assessment** (critical, high, medium, low, info)
- **Extracted findings** (open ports, vulnerabilities, exploits)
- **Recommendations** (suggested next steps)
- **LLM-friendly summaries**

Example:

```python
from src.parsers import OutputParser

parser = OutputParser()

# Parse nmap output
parsed = parser.parse(
    tool_name="nmap",
    raw_output=nmap_output,
    metadata={"hosts": [...], "open_ports": [...]}
)

print(parsed.summary)
print(f"Severity: {parsed.severity}")
for finding in parsed.findings:
    print(f"- {finding['description']}")
```

### 5. Function Calling (`src/agent/function_calling.py`)

Bridges LLM function calls to tool execution:

- Parses LLM function calls (OpenAI, Claude, Llama formats)
- Executes tools with approval checks
- Formats results for LLM consumption
- Tracks execution history

Example:

```python
from src.agent import FunctionCallHandler, interactive_approval

handler = FunctionCallHandler(
    approval_callback=interactive_approval,
    verbose=True
)

# Parse LLM response
function_call = handler.parse_llm_function_call(llm_response)

# Execute
response = handler.execute_function_call(function_call)

print(response.result)  # Formatted for LLM
```

### 6. Agent Loop (`src/agent/agent_loop.py`)

Main orchestration loop:

1. **Reasoning**: LLM analyzes task and decides on approach
2. **Tool Calling**: LLM calls appropriate tool
3. **Execution**: Tool runs with safety checks
4. **Analysis**: LLM processes results
5. **Repeat**: Continue until task complete or max iterations

## 🔒 Security Features

### IP Whitelisting

Only private networks allowed by default:

- `192.168.0.0/16`
- `10.0.0.0/8`
- `172.16.0.0/12`
- `127.0.0.0/8`

### Human-in-the-Loop

Restricted tools require approval:

- `hydra` (brute-forcing)
- `sqlmap` (SQL injection)
- `metasploit` (exploitation)

### Audit Logging

All tool executions are tracked:

- Command executed
- Timestamp
- Results
- Execution time

### Command Sanitization

Prevents:

- Command injection
- Unauthorized external scanning
- File deletion
- System modification

## 📝 Next Steps (TODO)

### Phase 1 Tasks

- [ ] **Task #162**: Download and explore data sources (CVE, ExploitDB)
- [ ] Implement remaining tool wrappers (nikto, gobuster, hydra, sqlmap, metasploit)
- [ ] Add comprehensive unit tests
- [ ] Integrate with RAG system (Coleman's component)
- [ ] Connect to OpenWebUI (Jordan's component)

### Phase 3 Tasks

- [ ] **Task #247**: Implement comprehensive logging system
- [ ] **Task #244**: Add validation logic for multi-step attack chains
- [ ] Performance optimization
- [ ] Error recovery and retry logic

## 🤝 Integration Points

This component integrates with:

1. **RAG System** (Coleman) - Query CVE/exploit databases for vulnerability information
2. **OpenWebUI Frontend** (Jordan) - Display real-time execution status and results
3. **Infrastructure** (Nick) - Deploy in isolated lab environment with vulnerable VMs

## 📊 Testing

```bash
# Run unit tests (TODO)
pytest tests/unit/

# Run integration tests (TODO)
pytest tests/integration/

# Test specific component
pytest tests/unit/test_sanitizer.py -v
```

## 🐛 Known Issues

- [ ] Ollama client is simplified - needs full implementation
- [ ] Missing tool wrappers for nikto, gobuster, hydra, sqlmap, metasploit
- [ ] No integration tests yet
- [ ] LLM response parsing needs testing with different model formats

## 🙏 Acknowledgments

Built as part of the VenomX capstone project by:

- **Khalid** - Agent & Tools Lead
- **Coleman** - RAG & Knowledge Lead
- **Jordan** - UI & Experience Lead
- **Nick** - Integration & Infrastructure Lead

---

**⚠️ IMPORTANT**: This tool is for authorized penetration testing in controlled environments only. Unauthorized use is illegal and unethical.
