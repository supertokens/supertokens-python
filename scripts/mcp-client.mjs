#!/usr/bin/env node

// HTTP client for the MCP build tools stateless API.
// Usage: node scripts/mcp-client.mjs <command> [options]

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

function getDefaultPort() {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const content = readFileSync(resolve(__dirname, "../mcp.env"), "utf8");
    const match = content.match(/^MCP_PORT=(\d+)/m);
    if (match) return match[1];
  } catch {}
  return "3001";
}

const BASE_URL = process.env.MCP_URL
  || `http://localhost:${process.env.MCP_PORT || getDefaultPort()}`;

function usage() {
  console.log(`
Usage: node scripts/mcp-client.mjs <command> [options]

Commands:
  test [options]        Run pytest tests
    --filter <expr>     pytest -k expression
    --path <path>       Test file or directory
    --markers <expr>    pytest -m expression
    --max-fail <n>      Stop after N failures

  lint [options]        Run linting
    --tool <name>       all, ruff, or pyright (default: all)
    --fix               Auto-fix lint issues (ruff only)

  cross-sdk-test [options]  Run cross-SDK Mocha tests
    --grep <expr>       Mocha --grep filter
    --timeout <ms>      Mocha per-test timeout in ms

  status <taskId>       Check task status
  cancel <taskId>       Cancel a running task
  list                  List all tasks

  results [options]     Browse test results
    --run <runId>       Test run ID (default: latest)
    --filter <status>   all, failed, passed, skipped
    --class <name>      Filter by class name

  output <testId>       Get per-test output
    --run <runId>       Test run ID (default: latest)

  runs                  List archived test runs

Environment:
  MCP_URL              Base URL (default: http://localhost:3001)
`);
}

async function callTool(tool, args = {}) {
  const resp = await fetch(`${BASE_URL}/api/call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, arguments: args }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.error(`Error ${resp.status}: ${text}`);
    process.exit(1);
  }

  const result = await resp.json();

  if (result.isError) {
    if (result.content) {
      for (const item of result.content) {
        if (item.type === "text") console.error(item.text);
      }
    }
    process.exit(1);
  }

  return result;
}

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const val = argv[i + 1];
      if (val && !val.startsWith("--")) {
        result[key] = val;
        i++;
      } else {
        result[key] = true;
      }
    } else if (!result._positional) {
      result._positional = arg;
    }
  }
  return result;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === "help" || command === "--help") {
    usage();
    process.exit(0);
  }

  const opts = parseArgs(rest);

  let result;

  switch (command) {
    case "test":
      result = await callTool("test", {
        filter: opts.filter,
        path: opts.path,
        markers: opts.markers,
        maxFail: opts["max-fail"] ? parseInt(opts["max-fail"], 10) : undefined,
      });
      break;

    case "lint":
      result = await callTool("lint", {
        tool: opts.tool || "all",
        fix: opts.fix === true ? true : undefined,
      });
      break;

    case "cross-sdk-test":
      result = await callTool("cross_sdk_test", {
        grep: opts.grep,
        timeout: opts.timeout ? parseInt(opts.timeout, 10) : undefined,
      });
      break;

    case "status":
      if (!opts._positional && !rest[0]) {
        console.error("Usage: mcp-client.mjs status <taskId>");
        process.exit(1);
      }
      result = await callTool("task_status", {
        taskId: opts._positional || rest[0],
      });
      break;

    case "cancel":
      if (!opts._positional && !rest[0]) {
        console.error("Usage: mcp-client.mjs cancel <taskId>");
        process.exit(1);
      }
      result = await callTool("task_cancel", {
        taskId: opts._positional || rest[0],
      });
      break;

    case "list":
      result = await callTool("task_list");
      break;

    case "results":
      result = await callTool("test_results", {
        runId: opts.run,
        filter: opts.filter || "all",
        className: opts.class,
      });
      break;

    case "output":
      if (!opts._positional && !rest[0]) {
        console.error("Usage: mcp-client.mjs output <testId>");
        process.exit(1);
      }
      result = await callTool("test_output", {
        testId: opts._positional || rest[0],
        runId: opts.run,
      });
      break;

    case "runs":
      result = await callTool("test_runs");
      break;

    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(1);
  }

  // Print result
  if (result?.content) {
    for (const item of result.content) {
      if (item.type === "text") {
        console.log(item.text);
      }
    }
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
