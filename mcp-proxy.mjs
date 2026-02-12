#!/usr/bin/env node

// Stdio-to-HTTP proxy for Claude Desktop / Claude Code.
// Translates MCP stdio transport into HTTP calls against the SSE server.
//
// Claude Desktop config (~/.claude/claude_desktop_config.json):
// {
//   "mcpServers": {
//     "python-build-tools": {
//       "command": "node",
//       "args": ["/path/to/supertokens-python/mcp-proxy.mjs"],
//       "env": { "MCP_URL": "http://localhost:3000" }
//     }
//   }
// }

import { stdin, stdout, stderr } from "process";
import { createInterface } from "readline";

const MCP_URL = process.env.MCP_URL || "http://localhost:3001";
const SSE_URL = `${MCP_URL}/sse`;
const MESSAGES_URL = `${MCP_URL}/messages`;

let sessionId = null;

// ---------------------------------------------------------------------------
// SSE client — connects to the MCP server's /sse endpoint
// ---------------------------------------------------------------------------
async function connectSSE() {
  stderr.write(`[mcp-proxy] Connecting to ${SSE_URL}\n`);

  const resp = await fetch(SSE_URL, {
    headers: { Accept: "text/event-stream" },
  });

  if (!resp.ok) {
    throw new Error(`SSE connection failed: ${resp.status} ${resp.statusText}`);
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  (async () => {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        let eventType = null;
        let data = "";

        for (const line of lines) {
          if (line.startsWith("event:")) {
            eventType = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            data = line.slice(5).trim();
          } else if (line === "") {
            // End of event
            if (eventType === "endpoint") {
              // Extract session ID from the endpoint URL
              const match = data.match(/sessionId=([^&]+)/);
              if (match) {
                sessionId = match[1];
                stderr.write(`[mcp-proxy] Session: ${sessionId}\n`);
              }
            } else if (eventType === "message") {
              // Forward MCP message to stdout
              try {
                const msg = JSON.parse(data);
                stdout.write(JSON.stringify(msg) + "\n");
              } catch {
                stderr.write(`[mcp-proxy] Bad SSE message: ${data}\n`);
              }
            }
            eventType = null;
            data = "";
          }
        }
      }
    } catch (err) {
      stderr.write(`[mcp-proxy] SSE read error: ${err.message}\n`);
      process.exit(1);
    }
  })();

  // Wait for session ID
  for (let i = 0; i < 50; i++) {
    if (sessionId) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("Timed out waiting for SSE session ID");
}

// ---------------------------------------------------------------------------
// Forward stdin (MCP messages) to HTTP POST /messages
// ---------------------------------------------------------------------------
async function forwardStdin() {
  const rl = createInterface({ input: stdin });

  for await (const line of rl) {
    if (!line.trim()) continue;

    try {
      const msg = JSON.parse(line);
      const url = `${MESSAGES_URL}?sessionId=${sessionId}`;

      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(msg),
      });

      if (!resp.ok) {
        stderr.write(
          `[mcp-proxy] POST error: ${resp.status} ${await resp.text()}\n`
        );
      }
    } catch (err) {
      stderr.write(`[mcp-proxy] Forward error: ${err.message}\n`);
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  try {
    await connectSSE();
    stderr.write("[mcp-proxy] Connected, forwarding stdio <-> HTTP\n");
    await forwardStdin();
  } catch (err) {
    stderr.write(`[mcp-proxy] Fatal: ${err.message}\n`);
    process.exit(1);
  }
}

main();
