# VenomX Agent - Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Step 1: Verify Python
```bash
python --version  # Should be 3.9+
```

### Step 2: Install Dependencies
```bash
cd venomx-agent
pip install -r requirements.txt
```

### Step 3: Run the Demo
```bash
python examples/basic_example.py
```

**Expected Output:**
```
======================================================================
VenomX Agent - Component Demos
======================================================================

============================================================
DEMO 5: Tool Factory
============================================================
Available tools: nmap, searchsploit
  ✓ nmap: NmapTool
  ✓ searchsploit: SearchsploitTool

============================================================
DEMO 4: Tool Schemas for LLM
============================================================
Total tools available: 7
...
```

---

## 📋 What the Demo Shows

1. **Tool Factory** - Loading security tools
2. **Tool Schemas** - JSON schemas for LLM function calling
3. **Command Sanitization** - Security checks in action
4. **Output Parsing** - Structured vulnerability analysis
5. **Live Execution** - Real nmap scan (if installed)

---

## 🔧 Optional: Install Security Tools

To run live tool executions:

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y nmap nikto gobuster hydra sqlmap exploitdb
```

### macOS
```bash
brew install nmap nikto gobuster hydra sqlmap exploitdb
```

### Windows (WSL)
```bash
# Use WSL and follow Linux instructions
```

---

## 🧪 Quick Component Tests

### Test Sanitizer
```python
from src.parsers import CommandSanitizer

sanitizer = CommandSanitizer()
is_safe, cmd, reason = sanitizer.sanitize("nmap -sS 192.168.1.50", "nmap")
print(f"Safe: {is_safe}")  # Should be True
```

### Test Tool Execution
```python
from src.tools import ToolFactory

nmap = ToolFactory.get_tool("nmap")
result = nmap.execute(target="127.0.0.1", scan_type="ping_sweep")
print(result.status)  # Should be SUCCESS or FAILURE (depending on nmap install)
```

### Test Output Parsing
```python
from src.parsers import OutputParser

parser = OutputParser()
# Use mock data from basic_example.py
```

---

## 🎯 Next: Try the Agent Loop

Once you have Ollama running with Llama 3.3 70B:

```python
from src.agent import VenomXAgent, OllamaClient, interactive_approval

# Initialize LLM
llm = OllamaClient(model="llama3.3:70b")

# Create agent
agent = VenomXAgent(
    llm_client=llm,
    approval_callback=interactive_approval,
    verbose=True
)

# Run a task
response = agent.run(
    "Scan 192.168.1.0/24 for devices and open ports",
    target_network="192.168.1.0/24"
)

print(response)
```

---

## 📚 Documentation

- **README.md** - Full component documentation
- **KHALID_TASKS_COMPLETED.md** - What's been built
- **examples/basic_example.py** - Working code examples

---

## 🆘 Troubleshooting

### Import Errors
```bash
# Make sure you're in the venomx-agent directory
cd venomx-agent
# Run from project root
python examples/basic_example.py
```

### "nmap not found"
```bash
# Install nmap or skip live execution demo
# The sanitization and parsing demos will still work
```

### Permission Errors
```bash
# Some nmap scans require sudo
# The demo uses safe scans that don't need root
```

---

## ✅ Success Indicators

You're ready to move forward if:
- [ ] Demo runs without errors
- [ ] All 5 demos complete successfully
- [ ] You understand the component architecture
- [ ] You can modify and run the examples

---

**Ready to build! 🎉**
