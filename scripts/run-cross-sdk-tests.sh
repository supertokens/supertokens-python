#!/usr/bin/env bash
# Automated cross-SDK test runner with log streaming.
# Starts Mocha tests via the MCP API, streams container logs, polls until completion.
set -euo pipefail

source "$(dirname "$0")/../mcp.env" 2>/dev/null || true
MCP_URL="${MCP_URL:-http://localhost:${MCP_PORT:-3001}}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
CLIENT="node $(dirname "$0")/mcp-client.mjs"

usage() {
  cat <<EOF
Usage: ./scripts/run-cross-sdk-tests.sh [options]

Options:
  --grep <expr>       Mocha --grep filter expression
  --timeout <ms>      Mocha per-test timeout in ms
  --no-parallel       Disable parallel test execution
  --jobs <n>          Number of parallel workers (default: Mocha default)
  --no-logs           Don't stream container logs

Environment:
  MCP_URL             Base URL (default: http://localhost:3001)
  POLL_INTERVAL       Seconds between status checks (default: 5)
EOF
}

# Parse args
GREP=""
TIMEOUT=""
PARALLEL=""
JOBS=""
STREAM_LOGS=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --grep)         GREP="$2"; shift 2 ;;
    --timeout)      TIMEOUT="$2"; shift 2 ;;
    --no-parallel)  PARALLEL="false"; shift ;;
    --jobs)         JOBS="$2"; shift 2 ;;
    --no-logs)      STREAM_LOGS=false; shift ;;
    --help|-h)      usage; exit 0 ;;
    *)              echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Check health
echo "Checking MCP server health..."
HEALTH=$(curl -sf "${MCP_URL}/health" 2>/dev/null || echo "")
if [ -z "$HEALTH" ]; then
  echo "ERROR: MCP server not reachable at ${MCP_URL}"
  echo "Run 'docker compose up --wait' first."
  exit 1
fi
echo "MCP server is healthy."

# Build command args
CMD_ARGS=""
if [ -n "$GREP" ]; then
  CMD_ARGS="${CMD_ARGS} --grep ${GREP}"
fi
if [ -n "$TIMEOUT" ]; then
  CMD_ARGS="${CMD_ARGS} --timeout ${TIMEOUT}"
fi
if [ -n "$PARALLEL" ]; then
  CMD_ARGS="${CMD_ARGS} --parallel ${PARALLEL}"
fi
if [ -n "$JOBS" ]; then
  CMD_ARGS="${CMD_ARGS} --jobs ${JOBS}"
fi

# Start cross-SDK tests
echo ""
echo "> Starting cross-SDK tests..."
# shellcheck disable=SC2086
RESULT=$($CLIENT cross-sdk-test $CMD_ARGS)
echo "$RESULT"

# Extract task ID from "Task ID: xxx" line
TASK_ID=$(echo "$RESULT" | grep -o 'Task ID: [^ ]*' | head -1 | sed 's/Task ID: //')
if [ -z "$TASK_ID" ]; then
  echo "ERROR: Could not extract task ID from response"
  exit 1
fi

# Helper: kill a process and all its children
kill_tree() {
  local pid="$1"
  pkill -P "$pid" 2>/dev/null || true
  kill "$pid" 2>/dev/null || true
}

# Stream logs in background
LOG_PID=""
if [ "$STREAM_LOGS" = true ]; then
  echo ""
  echo "> Streaming MCP container logs..."
  docker compose logs -n 10 -f mcp &
  LOG_PID=$!
fi

# Ensure log streaming is cleaned up on exit/interrupt
trap '[ -n "$LOG_PID" ] && kill_tree "$LOG_PID"' EXIT INT TERM

# Poll for completion
echo ""
while true; do
  sleep "$POLL_INTERVAL"

  STATUS_RESULT=$($CLIENT status "$TASK_ID" 2>/dev/null) || true

  # Retry on empty response (connection failure)
  if [ -z "$STATUS_RESULT" ]; then
    echo "[$(date '+%H:%M:%S')] Poll failed, retrying..."
    continue
  fi

  # Check if task is still running
  if echo "$STATUS_RESULT" | grep -q "still running"; then
    echo "[$(date '+%H:%M:%S')] Still running..."
    continue
  fi

  # Task is done — stop log streaming (kill child processes first, then parent)
  if [ -n "$LOG_PID" ]; then
    kill_tree "$LOG_PID"
  fi

  echo ""
  echo "$STATUS_RESULT"

  # Exit with appropriate code
  if echo "$STATUS_RESULT" | grep -q "CROSS-SDK TESTS FAILED"; then
    exit 1
  fi
  exit 0
done
