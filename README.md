# FirstCall

Turn an API request into a tool your AI client can actually call.

Bring a curl command or an OpenAPI operation, verify it against the API, describe
what the tool does, and export a local MCP connection. FirstCall's companion
executable runs the tool directly: no generated code to build and no npm setup.

## Make your first tool

1. Download the [v0.3.0 Apple Silicon Mac archive](https://github.com/rad1092/firstcall-local-api-workbench/releases/tag/v0.3.0), unzip it, and move FirstCall.app to Applications before exporting tools. The companion runtime is included inside the app.
2. Open FirstCall and choose **Create a tool**. Paste a curl command or select OpenAPI. **Try an example** loads a public GitHub repository lookup with sample values; no authentication is needed for that example.
3. Choose **Read request**, review the operation, and enter its inputs. Authentication values stay separate from the tool's ordinary parameters.
4. Choose **Send and verify**. This sends a real request to the selected API. A successful response enables **Continue to MCP tool**.
5. Give the tool a useful name, explain when the AI should use it and what it returns, and describe its inputs. Text, integer, number, and boolean inputs are supported. Write operations require an explicit per-export opt-in.
6. Choose **Export MCP package**. FirstCall creates a new folder, verifies its files and request policy, and shows **Copy connection configuration** and **Open package folder**.
7. Add that server entry to your AI client's local MCP settings. Fill any empty authentication environment values in the client's settings, then restart its MCP connection. Ask the client to call your named tool.

The exported tool returns structured, redacted API response data, status, and
explicit error or size-limit information. Export verification records that the
request worked at that time; every MCP tool call makes a new API request.

## Current release scope

v0.3.0 includes an Apple Silicon macOS app and CLI. The bundle is ad-hoc signed
for integrity and is not Apple notarized. Windows, Linux, and Intel Mac binaries
are not included in this release; older releases remain available. The runtime
allows GET and HEAD by default, requires explicit opt-in for other methods,
uses a 30-second timeout, and limits each response body to 256 KiB. Oversized or
malformed JSON returns an error rather than partial data presented as complete.

## What leaves your computer

Request verification and MCP tool calls connect directly to the API you chose.
FirstCall has no cloud backend. Request history and verified recipes use local
SQLite storage. Exported packages contain environment variable names, not their
credential values. The MCP runtime reads credentials from its own process
environment, so a token entered in the GUI must also be supplied in the client's
local environment when connecting the exported tool.

Keep the package and application at their exported locations. The connection
configuration uses absolute paths; export a new configuration if either moves.
The export preserves existing folders instead of overwriting them.

## What's in the MCP package

- `recipe.yaml`: the request template, input slots, and authentication references
- `tool.json`: the tool's name, purpose, and input schema
- `policy.json`: the allowed endpoint and operation
- `verified.lock.json` and `package.manifest.json`: verification and integrity records
- `client-config.json`: the local MCP server entry with empty credential placeholders
- `README.md`: connection instructions for this tool

The connection runs the installed firstcall-cli with the `serve --package`
command. The native runtime checks the package and its endpoint policy before
accepting tool calls. It does not follow redirects to another endpoint.

## Command line and existing packages

The CLI also supports verification, saved recipes, package inspection, and
import. [CLI usage](docs/cli-lifecycle.md) describes those commands and the native
MCP runtime. Existing TypeScript MCP packages remain available through the
advanced CLI packaging workflow; they are not required for desktop exports.

To build from source, see [Build surfaces](docs/build-surfaces.md). Rust is needed
for source development, not for running a release download. Parser coverage and
limits are documented in [Support boundaries](docs/support-boundaries.md).
