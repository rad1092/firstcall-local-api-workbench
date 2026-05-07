# FirstCall

[![CI](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml)
[![Security audit](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

FirstCall is a native local-first desktop tool for turning pasted `curl` commands, prose API docs, or OpenAPI snippets into one executable HTTP request. It helps fill runtime values, execute the call, classify the outcome, persist redacted attempts locally, and promote successful attempts into reusable recipes.

FirstCall Agent Recipes adds a second surface to that workflow: **Verified API tool recipes for AI agents.** A recipe becomes an agent-usable package only after a real request has succeeded.

## MVP Scope

- Native desktop app built with Rust + `eframe`/`egui`
- Ingest tabs for `curl`, docs prose, and OpenAPI JSON/YAML/fragments
- Deterministic request draft extraction and merge precedence: `curl > OpenAPI > docs`
- Editable request builder for method, base URL, path, headers, query, and body
- Runtime slot filling and auth handling
- Blocking HTTP execution on a background thread
- Deterministic outcome and blocker classification
- Optional JSON Schema validation for JSON responses
- SQLite persistence for attempts, recipes, and settings
- Recipe rerun, curl copy, markdown export, and JSON export
- Verified agent recipe package export from existing recipe JSON

## Build And Run

FirstCall now targets host-native builds on Windows, macOS, and Linux. The repository keeps optional support for `x86_64-pc-windows-gnullvm`, but it no longer forces that target for every machine.

Prerequisites:

- Rust stable
- platform-native build prerequisites for `eframe` on the local OS
- if you explicitly want the `x86_64-pc-windows-gnullvm` target on Windows: `llvm-mingw`

The repository includes:

- `rust-toolchain.toml` for stable + `clippy` + `rustfmt`
- `.cargo/config.toml` with optional linker resolution for `x86_64-pc-windows-gnullvm`

Tool resolution order:

1. `FIRSTCALL_LLVM_MINGW_BIN`
2. Common `winget` install location for `llvm-mingw`
3. `PATH`

If you explicitly build for `x86_64-pc-windows-gnullvm`, one of these must be true:

- `llvm-mingw` is installed in the usual `winget` location
- or its `bin` directory is on `PATH`
- or `FIRSTCALL_LLVM_MINGW_BIN` points to that `bin` directory

Build on the current host OS:

```powershell
cargo build
```

Run:

```powershell
cargo run
```

CLI:

```powershell
cargo run --bin firstcall-cli -- version
```

CLI command overview:

```text
firstcall-cli version
firstcall-cli explain --recipe-json PATH
firstcall-cli package --recipe-json PATH --out DIR
firstcall-cli package --recipe-id ID --out DIR [--data-dir PATH --config-dir PATH]
firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating]
firstcall-cli verify --recipe-json PATH [--allow-mutating] [--dry-run|--preflight] [--json]
firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating]
firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--dry-run|--preflight] [--json]
firstcall-cli validate-package --dir PATH [--json]
firstcall-cli inspect-package --dir PATH [--json]
firstcall-cli import-package --dir PATH [--data-dir PATH --config-dir PATH] [--json]
firstcall-cli recipe-list [--data-dir PATH --config-dir PATH] [--json]
firstcall-cli recipe-show --id ID [--data-dir PATH --config-dir PATH] [--json]
```

Without `--json`, CLI commands keep human-readable output. With `--json`, report-producing commands emit machine-readable JSON for agents, CI, and scripts. JSON output is for safe/static report surfaces and read-only recipe summaries. Actual non-dry-run HTTP `verify --json` is intentionally not supported yet.

Quick local checks:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked
```

For the full CLI lifecycle and release-readiness checklist, see [docs/release-readiness.md](docs/release-readiness.md).

Optional Windows `gnullvm` build:

```powershell
rustup target add x86_64-pc-windows-gnullvm
cargo build --target x86_64-pc-windows-gnullvm
```

## Agent Recipe Export

FirstCall Agent Recipes exports a successful recipe into a portable agent tool package.

**Verified API tool recipes for AI agents.**

The package includes:

- `recipe.yaml`
- `skill.md`
- `policy.json`
- `verified.lock.json`
- `package.manifest.json`
- `mcp-server/` with a TypeScript MCP server template

Raw secrets are never exported. Secret values are represented as environment variable references such as `FIRSTCALL_BEARER_TOKEN` or `FIRSTCALL_API_KEY`. Recipes are exportable only after a successful execution, represented by `last_success_at` and a 2xx `last_success_status` in the exported recipe JSON.

Explain an existing exported recipe JSON:

```powershell
cargo run --bin firstcall-cli -- explain --recipe-json ./recipe.json
```

Package a verified recipe:

```powershell
cargo run --bin firstcall-cli -- package `
  --recipe-json ./recipe.json `
  --out ./dist/my-agent-tool
```

Package a verified recipe from local recipe storage:

```powershell
cargo run --bin firstcall-cli -- package `
  --recipe-id 1 `
  --out ./dist/my-agent-tool
```

```powershell
cargo run --bin firstcall-cli -- package `
  --recipe-id 1 `
  --data-dir ./tmp/firstcall-data `
  --config-dir ./tmp/firstcall-config `
  --out ./dist/my-agent-tool
```

`package --recipe-id` reads the stored recipe payload from local SQLite storage. It does not execute HTTP, does not mutate SQLite, and requires successful local verification metadata before export. It emits the same redacted agent package format as `package --recipe-json`; generated `mcp-server/` files remain template artifacts, not source of truth.

Re-run a recipe locally to refresh verification metadata:

```powershell
$env:FIRSTCALL_BEARER_TOKEN = "..."
cargo run --bin firstcall-cli -- verify `
  --recipe-json ./recipe.json `
  --out ./recipe.verified.json `
  --lock-out ./verified.lock.json
```

`verify` executes the recipe from the local machine. Secrets must come from environment variables, and raw secret values are not written to the updated recipe or lock file. `POST`, `PUT`, `PATCH`, and `DELETE` require `--allow-mutating`.

Check whether a recipe is ready to verify without sending HTTP:

```powershell
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --dry-run
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --dry-run --json
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --preflight
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --preflight --json
```

Verify or preflight a recipe already in local recipe storage:

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1 --dry-run --json
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --dry-run --json
```

`verify --dry-run` and `verify --preflight` are aliases. They perform local static/runtime-input preflight only, do not execute HTTP, and do not write `--out` or `--lock-out` files. Human and JSON reports list required environment variables by name with `set` or `missing` status only, never environment values or raw secrets. Mutating methods still require `--allow-mutating` to be ready for real verification. `verify --recipe-id` reads from local recipe storage and can perform actual local verification; on success it updates local SQLite verification metadata. In this phase, actual `verify --recipe-id` does not support `--json`, `--out`, or `--lock-out`.

`verify --dry-run` checks whether a recipe is ready to execute. `validate-package` checks exported package structure and integrity.

Try the local verified fixture:

```powershell
cargo run --bin firstcall-cli -- explain --recipe-json fixtures/verified-agent-recipe.json
```

```powershell
cargo run --bin firstcall-cli -- package `
  --recipe-json fixtures/verified-agent-recipe.json `
  --out ./dist/sample-agent-tool
```

Expected output tree:

```text
dist/sample-agent-tool/
  recipe.yaml
  verified.lock.json
  skill.md
  policy.json
  package.manifest.json
  mcp-server/
    package.json
    tsconfig.json
    src/server.ts
    README.md
```

This packages an already-verified recipe JSON or stored recipe. It does not execute an HTTP request, mutate SQLite during package export, verify npm or TypeScript compilation, or export raw secrets.

The generated MCP server is a template artifact. It returns `structuredContent` in addition to text content, declares an `outputSchema` for `status`, `ok`, and `body_preview`, and includes advisory tool annotations such as `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`. These annotations are hints only; they are not security controls. Rust tests do not run live HTTP verification, `npm install`, `npm build`, TypeScript compilation, Node, MCP Inspector, or the generated MCP runtime.

## Inspect generated package

Create a local sample package:

```powershell
cargo run --bin firstcall-cli -- package --recipe-json fixtures/verified-agent-recipe.json --out ./dist/sample-agent-tool
```

Inspect these generated files:

- `dist/sample-agent-tool/recipe.yaml`
- `dist/sample-agent-tool/skill.md`
- `dist/sample-agent-tool/policy.json`
- `dist/sample-agent-tool/verified.lock.json`
- `dist/sample-agent-tool/package.manifest.json`
- `dist/sample-agent-tool/mcp-server/src/server.ts`

Run static validation on the generated package:

```powershell
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool
```

```powershell
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --json
```

`package.manifest.json` records SHA-256 hashes for generated package files. `validate-package` checks package structure, schema metadata, lock metadata, policy shape, MCP template markers including `structuredContent`, `outputSchema`, and tool annotations, obvious secret leaks, and manifest hashes when the manifest is present. Missing `package.manifest.json` currently warns instead of failing for backward compatibility.

`validate-package` is static-only: it does not execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, execute the generated MCP server, import recipes, or modify files. The generated files should not export raw secrets.

Inspect import-readiness without importing anything:

```powershell
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool
```

```powershell
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool --json
```

`inspect-package` runs `validate-package` and then checks import-readiness conditions such as manifest presence, recipe/policy agreement, and verified lock metadata. It does not import recipes, modify files, modify app storage, execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, or execute the generated MCP server. Missing `package.manifest.json` blocks inspect-readiness even though `validate-package` still warns for backward compatibility.

Import an inspect-ready package into local FirstCall recipe storage:

```powershell
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool
```

```powershell
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --json
```

For tests or controlled local imports, storage can be overridden explicitly:

```powershell
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config
```

```powershell
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
```

`import-package` runs inspect-readiness first, writes one recipe into the existing local SQLite recipe storage, and marks the imported recipe as needing local re-verification. It does not preserve verified status, import raw secrets, execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, execute generated MCP runtime, or use generated `mcp-server/` files as the source of truth.

## Local recipe storage CLI

List local stored recipes:

```powershell
cargo run --bin firstcall-cli -- recipe-list
```

```powershell
cargo run --bin firstcall-cli -- recipe-list --json
```

Show one local stored recipe:

```powershell
cargo run --bin firstcall-cli -- recipe-show --id 1
```

```powershell
cargo run --bin firstcall-cli -- recipe-show --id 1 --json
```

Controlled storage examples:

```powershell
cargo run --bin firstcall-cli -- recipe-list --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config
```

```powershell
cargo run --bin firstcall-cli -- recipe-show --id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
```

`recipe-list` and `recipe-show` are read-only recipe summary commands over local FirstCall SQLite recipe storage. When overriding storage, `--data-dir` and `--config-dir` must be provided together. Output is intentionally safe: it does not include `RuntimeSlot.current_value`, raw secrets, environment values, resolved secret-bearing URLs, or body contents. URL templates are sanitized. Imported recipes normally show `requires_local_re_verification: true` until verified locally.

## Agent and CI workflow

Agents and CI should parse stdout JSON and treat a non-zero exit status as blocked or failed:

```powershell
cargo run --bin firstcall-cli -- package --recipe-json fixtures/verified-agent-recipe.json --out ./dist/sample-agent-tool
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- recipe-list --json
```

Full local-first lifecycle:

```powershell
cargo run --bin firstcall-cli -- package --recipe-json ./recipe.verified.json --out ./dist/sample-agent-tool
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- recipe-list --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- recipe-show --id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --dry-run --json
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config
cargo run --bin firstcall-cli -- package --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --out ./dist/reverified-agent-tool
cargo run --bin firstcall-cli -- validate-package --dir ./dist/reverified-agent-tool --json
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/reverified-agent-tool --json
```

`import-package` does not preserve verified status, so imported recipes require local re-verification before `package --recipe-id` can export them. `verify --recipe-id --dry-run` does not execute HTTP or update SQLite. Actual `verify --recipe-id` executes local HTTP and updates SQLite verification metadata only on success. `package --recipe-id` does not execute HTTP or mutate SQLite.

For maintainers and agents preparing a handoff or release candidate, use the checklist in [docs/release-readiness.md](docs/release-readiness.md).

## CI

GitHub Actions validates:

- `windows-latest`
- `ubuntu-latest`
- `macos-latest`

Each runner executes:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --locked`
- `cargo build --locked`

## Storage And Secrets

- App data uses `directories::ProjectDirs` with qualifier `dev`, organization `rad1092`, application `FirstCall`
- SQLite database lives under the app data directory
- Recipes and attempts persist only redacted request/response snapshots
- Native keyring is intentionally disabled in this environment; credentials fall back to session-only in-memory storage via `secrecy`
- Raw secrets are never intentionally written to SQLite, exports, or logs

## Known Limitations

- Remote `$ref` fetching is intentionally disabled in v1
- Multipart file uploads are marked unsupported in v1
- Docs parsing is conservative and heuristic-only
- OpenAPI body templating focuses on common object/JSON cases
- Cookie-based auth is reduced to a simple header-oriented fallback in the current MVP
- Recipe export writes into the app export directory instead of opening a save-file dialog

## Architecture Summary

- `src/main.rs`: native entry point
- `src/app.rs`: app state, persistence wiring, execution dispatch
- `src/ui/*`: screens for New Attempt, Attempts, Recipes, Settings
- `src/model/*`: typed domain models
- `src/parse/*`: `curl`, docs, and OpenAPI ingestion
- `src/merge/*`: source precedence and candidate merge rules
- `src/exec/*`: request execution, classification, validation, redaction
- `src/store/*`: SQLite migrations/repos and secret storage abstraction
- `src/bin/firstcall-cli.rs`: CLI surface for verify, package, validate, inspect, import, and recipe storage commands
- `src/export/*`: curl, markdown, and JSON recipe export
- `src/export/agent_*`, `src/export/policy.rs`, `src/export/skill.rs`, `src/export/mcp_ts.rs`: verified agent recipe package export
- `src/export/package_validation.rs`: static generated package validation
- `src/export/package_inspect.rs`: import-readiness inspection
- `src/export/package_import.rs`: inspect-gated package import into local recipe storage
- `fixtures/*`: sample manual test inputs
