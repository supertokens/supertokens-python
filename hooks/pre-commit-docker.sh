#!/bin/bash
# Git pre-commit hook with three-tier fallback:
#   1. Local pre-commit (if installed)
#   2. Docker container (if running)
#   3. Error with instructions

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# 1. Try local pre-commit
if command -v pre-commit &>/dev/null; then
    exec pre-commit run --config "$REPO_ROOT/.pre-commit-config.yaml"
fi

# 2. Try Docker container
if docker compose ps --status running mcp 2>/dev/null | grep -q mcp; then
    exec docker compose exec -T -w /workspace mcp pre-commit run --config /workspace/.pre-commit-config.yaml
fi

# 3. Error with instructions
echo "ERROR: Cannot run pre-commit hooks." >&2
echo "" >&2
echo "Either:" >&2
echo "  1. Install pre-commit locally: pip install pre-commit && pre-commit install" >&2
echo "  2. Start the MCP Docker container: docker compose up -d mcp" >&2
exit 1
