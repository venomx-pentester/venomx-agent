# VenomX Agent

AI-powered penetration testing agent. Part of the VenomX capstone project.

Connects to a local LLM (vLLM in production, Ollama in dev), reasons about a target network, calls security tools, and accumulates findings into a persistent graph across iterations.

## Project Structure

```
venomx-agent/
├── src/
│   ├── agent/          # Agent loop, function calling, credential store
│   ├── graph/          # Finding graph (WAL-backed) + attack path classifier
│   ├── security/       # PromptGuard — 3-layer injection defense
│   ├── tools/          # nmap, searchsploit wrappers + base class
│   ├── schemas/        # JSON schemas for 7 tools
│   ├── parsers/        # Tool output parsing + command sanitization
│   └── utils/          # Session management
├── tests/
│   ├── unit/           # 89 tests, no external dependencies
│   └── integration/    # Agent loop tests against live LLM
├── scripts/
│   ├── hooks/pre-push  # Runs lint + unit tests before every push
│   └── setup.ps1       # Windows dev setup
└── data/sessions/      # Per-session state (WAL, graph, creds, audit log)
```

## Dev Setup

One-time after cloning. Installs the pre-push hook.

**Windows:**

```powershell
.\scripts\setup.ps1
```

**Linux/Mac:**

```bash
make install-hooks
```

## Basic Usage

```python
from src.agent import VenomXAgent, VLLMClient, interactive_approval
from src.utils import new_session

session = new_session(target_network="192.168.1.0/24")
llm = VLLMClient(model="openai/gpt-oss-20b", base_url="http://localhost:8000")

agent = VenomXAgent(
    llm_client=llm,
    approval_callback=interactive_approval,
    session=session,
    scope_cidrs=["192.168.1.0/24"],
)

response = agent.run("Scan 192.168.1.0/24 and find exploitable vulnerabilities.")
```

## Testing

**Unit tests** (no LLM required):

```bash
pytest tests/unit/ -v
```

**Integration tests** (requires Ollama dev stack):

```bash
docker compose -f ../venomx-docker/docker-compose.dev.yml up -d
docker exec venomx-ollama-dev ollama pull qwen2.5:3b
pytest tests/integration/ -v -s
```

Against the production vLLM stack (run from the GPU server):

```bash
LLM_BASE_URL=http://localhost:8000 LLM_MODEL=openai/gpt-oss-20b DISABLE_CANARY=0 \
  pytest tests/integration/ -v -s
```

`DISABLE_CANARY` defaults to `1` — small models don't echo the canary token reliably. Set to `0` only against the production model.

## Security Model

- **Command sanitization** — 6-layer check before any subprocess call
- **Prompt injection defense** — pattern stripping, per-iteration canary tokens, and scope validation on every tool call
- **Human-in-the-loop** — `hydra`, `sqlmap`, and `metasploit` require explicit approval before execution
- **Audit log** — all security events written as JSON lines to `audit.log` in the session directory

---

For authorized penetration testing in controlled environments only.
