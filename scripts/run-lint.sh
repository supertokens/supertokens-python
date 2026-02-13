#!/usr/bin/env bash
# Automated lint runner with log streaming.
# Starts linting via the MCP API, streams container logs, polls until completion.
set -euo pipefail

source "$(dirname "$0")/../mcp.env" 2>/dev/null || true
MCP_URL="${MCP_URL:-http://localhost:${MCP_PORT:-3001}}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
CLIENT="node $(dirname "$0")/mcp-client.mjs"

usage() {
  cat <<EOF
Usage: ./scripts/run-lint.sh [options]

Options:
  --tool <name>       all, ruff, or pyright (default: all)
  --fix               Auto-fix lint issues (ruff only)
  --no-logs           Don't stream container logs

Environment:
  MCP_URL             Base URL (default: http://localhost:3001)
  POLL_INTERVAL       Seconds between status checks (default: 5)
EOF
}

# Parse args
TOOL="all"
FIX=false
STREAM_LOGS=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool)     TOOL="$2"; shift 2 ;;
    --fix)      FIX=true; shift ;;
    --no-logs)  STREAM_LOGS=false; shift ;;
    --help|-h)  usage; exit 0 ;;
    *)          echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Check health
echo "Checking MCP server health..."
HEALTH=$(curl -sf "${MCP_URL}/health" 2>/dev/null || echo "")
if [ -z "$HEALTH" ]; then
  echo "ERROR: MCP server not reachable at ${MCP_URL}"
  echo "Run './manage.sh up' first."
  exit 1
fi
echo "MCP server is healthy."

# Start lint
FIX_FLAG=""
if [ "$FIX" = true ]; then
  FIX_FLAG="--fix"
fi

echo ""
echo "> Starting lint (${TOOL}${FIX:+, fix})..."
RESULT=$($CLIENT lint --tool "$TOOL" $FIX_FLAG)
echo "$RESULT"

# Extract task ID from "Task ID: xxx" line
TASK_ID=$(echo "$RESULT" | grep -o 'Task ID: [^ ]*' | head -1 | sed 's/Task ID: //')
if [ -z "$TASK_ID" ]; then
  echo "ERROR: Could not extract task ID from response"
  exit 1
fi

# Stream logs in background
LOG_PID=""
if [ "$STREAM_LOGS" = true ]; then
  echo ""
  echo "> Streaming MCP container logs..."
  docker compose logs -n 10 -f mcp &
  LOG_PID=$!
fi

# Poll for completion
echo ""
while true; do
  sleep "$POLL_INTERVAL"

  STATUS_RESULT=$($CLIENT status "$TASK_ID" 2>/dev/null || echo "poll failed")

  # Check if task is still running
  if echo "$STATUS_RESULT" | grep -q "still running"; then
    echo "[$(date '+%H:%M:%S')] Still running..."
    continue
  fi

  # Task is done — stop log streaming
  if [ -n "$LOG_PID" ]; then
    kill "$LOG_PID" 2>/dev/null || true
    wait "$LOG_PID" 2>/dev/null || true
  fi

  echo ""
  echo "$STATUS_RESULT"

  # Exit with appropriate code
  if echo "$STATUS_RESULT" | grep -q "LINT CHECKS FAILED"; then
    exit 1
  fi
  exit 0
done
