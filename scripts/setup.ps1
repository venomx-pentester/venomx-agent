# Run once after cloning: .\scripts\setup.ps1
# Configures git hooks and installs dev dependencies.

Write-Host "Configuring git hooks..."
git config core.hooksPath scripts/hooks

Write-Host "Installing dev dependencies..."
pip install pytest ruff -q

Write-Host "Done. Lint + tests will run on every 'git push'."
