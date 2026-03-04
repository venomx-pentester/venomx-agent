.PHONY: install-hooks lint test check

# Point git at scripts/hooks/ directly — run this once after cloning.
# All hooks in scripts/hooks/ are picked up automatically; no file copying needed.
install-hooks:
	git config core.hooksPath scripts/hooks
	@echo "Git hooks configured (core.hooksPath = scripts/hooks)."
	@echo "Dependencies: pip install pytest ruff"

# Run linter only
lint:
	python -m ruff check src/

# Run unit tests only
test:
	python -m pytest tests/unit/ -v

# Run both (same as the pre-push hook)
check: lint test
