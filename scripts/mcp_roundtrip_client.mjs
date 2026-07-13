#!/usr/bin/env node
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

function usage() {
  return `Usage:
  node scripts/mcp_roundtrip_client.mjs --package-dir PATH --tool NAME (--args JSON | --args-file PATH) [--expect-not-ok]

Runs a generated FirstCall MCP server from PATH, lists tools, calls one tool,
and exits non-zero unless the call's structuredContent.ok matches the expectation.`;
}

function requiredArg(args, name) {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length) {
    throw new Error(`missing ${name}\n\n${usage()}`);
  }
  return args[index + 1];
}

function optionalArg(args, name) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

async function importFromPackage(packageDir, specifier) {
  const requireFromPackage = createRequire(path.join(packageDir, "package.json"));
  return import(pathToFileURL(requireFromPackage.resolve(specifier)).href);
}

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log(usage());
  process.exit(0);
}

const packageDir = path.resolve(requiredArg(args, "--package-dir"));
const toolName = requiredArg(args, "--tool");
let toolArgs;
try {
  const inlineArgs = optionalArg(args, "--args");
  const argsFile = optionalArg(args, "--args-file");
  if ((inlineArgs === undefined) === (argsFile === undefined)) {
    throw new Error("provide exactly one of --args or --args-file");
  }
  const rawArgs = argsFile === undefined
    ? inlineArgs
    : readFileSync(path.resolve(argsFile), "utf8");
  toolArgs = JSON.parse(rawArgs);
} catch (error) {
  throw new Error(`tool args must be valid JSON: ${error.message}`);
}

const serverPath = path.join(packageDir, "dist", "server.js");
const { Client } = await importFromPackage(packageDir, "@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = await importFromPackage(
  packageDir,
  "@modelcontextprotocol/sdk/client/stdio.js",
);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  cwd: packageDir,
  env: process.env,
});
const client = new Client({
  name: "firstcall-generated-mcp-roundtrip",
  version: "0.1.0",
});

try {
  await client.connect(transport);
  const tools = await client.listTools();
  if (!tools.tools.some((tool) => tool.name === toolName)) {
    throw new Error(`generated MCP tool not found: ${toolName}`);
  }
  const result = await client.callTool({ name: toolName, arguments: toolArgs });
  if (args.includes("--debug-result")) {
    console.error(JSON.stringify(result, null, 2));
  }
  const structured = result.structuredContent ?? {};
  const ok = structured.ok === true;
  const expectedOk = !args.includes("--expect-not-ok");
  const status = structured.status;
  if (ok !== expectedOk) {
    throw new Error(
      `generated MCP tool returned ok=${structured.ok} status=${status}; expected ok=${expectedOk}`,
    );
  }
  console.log(
    JSON.stringify(
      {
        mcp_roundtrip: "passed",
        tool: toolName,
        status,
        ok,
        body_truncated: structured.body_truncated,
        schema_valid: structured.schema_valid,
        validation_errors: structured.validation_errors,
        listed_tools: tools.tools.map((tool) => tool.name),
      },
      null,
      2,
    ),
  );
} finally {
  await client.close();
}
