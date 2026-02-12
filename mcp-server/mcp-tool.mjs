#!/usr/bin/env node

// Stdio MCP server that proxies to the Docker container's stateless HTTP API.
// Configure in Claude Code's MCP settings to use the build tools directly.
//
// Usage in .claude/settings.json or .mcp.json:
// {
//   "mcpServers": {
//     "python-build-tools": {
//       "command": "node",
//       "args": ["mcp-server/mcp-tool.mjs"],
//       "env": { "MCP_URL": "http://localhost:3001" }
//     }
//   }
// }

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import http from "node:http";

const API_BASE = process.env.MCP_URL || "http://localhost:3001";

function httpPost(path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    const payload = JSON.stringify(body);

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try { resolve(JSON.parse(data)); } catch { resolve(data); }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.setTimeout(0);
    req.write(payload);
    req.end();
  });
}

async function callRemoteTool(name, args) {
  try {
    const result = await httpPost("/api/call", { tool: name, arguments: args });
    // The remote API already returns { content: [{ type: "text", text }] }
    if (result?.content) return result;
    // Fallback: wrap plain text
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error calling ${name}: ${err.message}` }],
      isError: true,
    };
  }
}

const server = new McpServer({
  name: "python-build-tools",
  version: "1.0.0",
});

// --- test ---
server.tool(
  "test",
  "Run pytest tests in the Docker container. Returns a task ID — use task_status to poll for results.",
  {
    filter: z.string().optional().describe("pytest -k expression to filter tests by name"),
    path: z.string().optional().describe("Test file or directory path (default: ./tests/)"),
    markers: z.string().optional().describe("pytest -m expression to filter by markers"),
    maxFail: z.number().optional().describe("Stop after N failures (pytest --maxfail)"),
  },
  async (params) => callRemoteTool("test", params)
);

// --- lint ---
server.tool(
  "lint",
  "Run linting tools (ruff and/or pyright) in the Docker container. Returns a task ID.",
  {
    tool: z.enum(["all", "ruff", "pyright"]).optional().default("all")
      .describe("Which linter to run: all, ruff, or pyright"),
    fix: z.boolean().optional().default(false)
      .describe("Auto-fix lint issues (ruff only)"),
  },
  async (params) => callRemoteTool("lint", params)
);

// --- task_status ---
server.tool(
  "task_status",
  "Check the status of a running or completed task. Returns results when done.",
  {
    taskId: z.string().describe("The task ID returned by test or lint"),
  },
  async (params) => callRemoteTool("task_status", params)
);

// --- task_cancel ---
server.tool(
  "task_cancel",
  "Cancel a running task.",
  {
    taskId: z.string().describe("The task ID to cancel"),
  },
  async (params) => callRemoteTool("task_cancel", params)
);

// --- task_list ---
server.tool(
  "task_list",
  "List all tasks (running and recent completed).",
  {},
  async () => callRemoteTool("task_list", {})
);

// --- test_results ---
server.tool(
  "test_results",
  "Browse archived test results with optional filters. Use test_output to get detailed output for specific tests.",
  {
    runId: z.string().optional().describe("Test run ID (default: latest run). Use test_runs to list available runs."),
    filter: z.enum(["all", "failed", "passed", "skipped"]).optional().default("all")
      .describe("Filter results by status"),
    className: z.string().optional().describe("Filter by test file/class name (substring match)"),
  },
  async (params) => callRemoteTool("test_results", params)
);

// --- test_output ---
server.tool(
  "test_output",
  "Get detailed stdout/stderr/traceback for a specific test. Use test_results first to find the testId.",
  {
    testId: z.string().describe("Full test ID (e.g. tests/test_session.py::test_create_session)"),
    runId: z.string().optional().describe("Test run ID (default: latest run)"),
  },
  async (params) => callRemoteTool("test_output", params)
);

// --- test_runs ---
server.tool(
  "test_runs",
  "List archived test runs. Use the runId with test_results or test_output to access specific runs.",
  {},
  async () => callRemoteTool("test_runs", {})
);

// --- Start ---
const transport = new StdioServerTransport();
await server.connect(transport);
