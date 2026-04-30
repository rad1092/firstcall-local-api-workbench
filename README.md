# FirstCall

[![CI](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml)

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

Checks:

```powershell
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

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
- `mcp-server/` with a basic TypeScript MCP server template

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
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --preflight
```

`verify --dry-run` and `verify --preflight` are aliases. They perform local static/runtime-input preflight only, do not execute HTTP, and do not write `--out` or `--lock-out` files. The report lists required environment variables by name with `set` or `missing` status only, never secret values. Mutating methods still require `--allow-mutating` to be ready for real verification.

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

This packages an already-verified recipe JSON. It does not execute an HTTP request, does not verify npm or TypeScript compilation, and does not export raw secrets.

The generated MCP server is a template artifact. Rust tests do not run live HTTP verification, `npm install`, `npm build`, or TypeScript compilation.

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

`package.manifest.json` records SHA-256 hashes for generated package files. `validate-package` checks package structure, schema metadata, lock metadata, policy shape, MCP template markers, obvious secret leaks, and manifest hashes when the manifest is present. Missing `package.manifest.json` currently warns instead of failing for backward compatibility.

`validate-package` is static-only: it does not execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, execute the generated MCP server, import recipes, or modify files. The generated files should not export raw secrets.

## CI

GitHub Actions validates:

- `windows-latest`
- `ubuntu-latest`
- `macos-latest`

Each runner executes:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo build`

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
- `src/export/*`: curl, markdown, and JSON recipe export
- `src/export/agent_*`, `src/export/policy.rs`, `src/export/skill.rs`, `src/export/mcp_ts.rs`: verified agent recipe package export
- `fixtures/*`: sample manual test inputs
