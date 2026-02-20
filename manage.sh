#!/usr/bin/env bash
# Convenience wrapper for MCP build tools Docker environment.
set -euo pipefail

COMPOSE_FILE="compose.mcp.yml"
source "$(dirname "$0")/mcp.env" 2>/dev/null || true
MCP_PORT="${MCP_PORT:-3001}"

usage() {
  cat <<EOF
Usage: ./manage.sh <command>

Commands:
  build     Build the MCP container image
  up        Start all services (core + oauth + mcp)
  down      Stop all services
  reset     Stop all services and remove volumes
  status    Show service status and connection info
  logs      Tail logs (optionally for a specific service)

Examples:
  ./manage.sh build
  ./manage.sh up
  ./manage.sh status
  ./manage.sh logs mcp
EOF
}

cmd_build() {
  echo "Building MCP container..."
  docker compose -f "$COMPOSE_FILE" build mcp
}

cmd_up() {
  echo "Starting services..."
  docker compose -f "$COMPOSE_FILE" up -d
  echo ""
  echo "Waiting for services to be healthy..."
  docker compose -f "$COMPOSE_FILE" up --wait
  echo ""
  cmd_status
}

cmd_down() {
  echo "Stopping services..."
  docker compose -f "$COMPOSE_FILE" down
}

cmd_reset() {
  echo "Stopping services and removing volumes..."
  docker compose -f "$COMPOSE_FILE" down -v
}

cmd_status() {
  docker compose -f "$COMPOSE_FILE" ps
  echo ""
  echo "=== Connection Info ==="
  echo "  SuperTokens Core:  http://localhost:${SUPERTOKENS_CORE_PORT:-3567}"
  echo "  MCP Server:        http://localhost:${MCP_PORT}"
  echo "  MCP Health:        http://localhost:${MCP_PORT}/health"
  echo "  MCP SSE:           http://localhost:${MCP_PORT}/sse"
  echo "  MCP API (tools):   http://localhost:${MCP_PORT}/api/tools"
}

cmd_logs() {
  local service="${1:-}"
  if [ -n "$service" ]; then
    docker compose -f "$COMPOSE_FILE" logs -f "$service"
  else
    docker compose -f "$COMPOSE_FILE" logs -f
  fi
}

case "${1:-}" in
  build)  cmd_build ;;
  up)     cmd_up ;;
  down)   cmd_down ;;
  reset)  cmd_reset ;;
  status) cmd_status ;;
  logs)   cmd_logs "${2:-}" ;;
  *)      usage; exit 1 ;;
esac
