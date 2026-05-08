# FirstCall

[![CI](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml)
[![CLI lifecycle](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml)
[![Security audit](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

FirstCall is a Rust 2024 local-first verified API recipe workbench. It turns request sources into `RequestDraft` candidates, requires local verification, and promotes successful requests into reusable recipes that can be exported as redacted agent packages.

FirstCall is not a Postman, Hurl, or Bruno runner. Its source adapters are static intake paths for building verified recipes; imported scripts, tests, runtime hooks, captured responses, and environment files are not executed.

For the current CLI / desktop GUI boundary, see [docs/surfaces.md](docs/surfaces.md). For build-surface notes and optional desktop feature design, see [docs/build-surfaces.md](docs/build-surfaces.md).

## Product Surfaces

FirstCall has two product surfaces built on shared local core logic:

- **FirstCall desktop GUI**: the `egui` / `eframe` human workbench for request source intake, source kind selection, parser notes, candidate review, runtime slot/auth entry, local HTTP execution, attempt review, recipe review, settings, and secret backend status.
- **`firstcall-cli`**: the automation surface for agents, CI, and scripts. It owns verify, package, validate-package, inspect-package, import-package, recipe-list/show, storage-backed verification flows, and JSON reports.

## Desktop GUI Workbench Flow

The desktop GUI supports the interactive recipe-building loop:

1. Paste or select a request source.
2. Analyze sources with a static parser.
3. Review parser notes and `RequestDraft` candidates.
4. Fill required runtime slots and auth values.
5. Run the request locally.
6. Inspect the redacted result and saved attempt.
7. Save a successful execution as a recipe.

Current GUI source kinds are `curl`, docs, OpenAPI, Postman Collection, HAR, `.http` / `.rest`, Hurl, and Bruno/OpenCollection. GraphQL-over-HTTP is detected from JSON request bodies in supported parser paths; it is not a direct GUI input tab.

Auth values entered in the GUI use password-style transient input. Saved auth values are held by the GUI `SecretStore`, are not displayed raw after save, and are not used by CLI verification. Required runtime slots gate execution before HTTP starts. While a request is running, context-changing controls are disabled; attempt persistence uses the run-start source snapshot, and recipe promotion uses the executed successful draft snapshot rather than the mutable builder.

## CLI Automation Flow

The CLI is for repeatable local workflows:

- verify a recipe JSON or stored recipe id;
- export a verified recipe package;
- validate and inspect redacted agent packages;
- import inspect-ready packages into local SQLite storage;
- list/show safe stored recipe summaries;
- emit safe JSON reports for agents, CI, and scripts.

CLI verification remains environment-first. It does not read GUI keyring or session-memory secrets.

## Real Verification Demos

FirstCall has reproducible checks that exercise the shipped paths rather than only compiling code:

- `cargo test --locked --test verify_loopback` runs actual local HTTP verification against a loopback server and checks that raw secrets are not written to outputs.
- `cargo test --locked --test lifecycle_cli` runs the package -> validate -> inspect -> import -> recipe-list/show -> dry-run -> actual local verify -> repackage lifecycle against temp SQLite storage and loopback HTTP.
- The [CLI lifecycle workflow](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml) runs real `firstcall-cli` commands on GitHub Actions: package, validate, inspect, import, list/show, and dry-run.

Optional live external verification can be run locally with a GitHub token. The token is read from `FIRSTCALL_BEARER_TOKEN`; it is not printed or written to the verified recipe, lock file, or JSON report.

```powershell
$env:FIRSTCALL_BEARER_TOKEN = gh auth token
cargo run --locked --bin firstcall-cli -- verify `
  --recipe-json fixtures/github-user-recipe.json `
  --json `
  --out ./tmp/github-user.verified.json `
  --lock-out ./tmp/github-user.lock.json
Remove-Item Env:FIRSTCALL_BEARER_TOKEN
```

Generated MCP server artifacts can also be compiled outside the default Rust test suite:

```powershell
cargo run --locked --bin firstcall-cli -- package --recipe-json fixtures/verified-agent-recipe.json --out ./dist/sample-agent-tool
Push-Location ./dist/sample-agent-tool/mcp-server
npm install
npm run build
Pop-Location
cargo run --locked --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --mcp-compile-smoke
```

This MCP check installs dependencies only in the generated package directory, compiles TypeScript, and does not run the generated MCP server or send HTTP.

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

`default-run = "firstcall"` is intentional: this package has both the desktop GUI and `firstcall-cli`, and bare `cargo run` launches the desktop workbench.

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
firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating] [--json]
firstcall-cli verify --recipe-json PATH [--allow-mutating] [--dry-run|--preflight] [--json]
firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--json]
firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--dry-run|--preflight] [--json]
firstcall-cli validate-package --dir PATH [--json] [--mcp-compile-smoke]
firstcall-cli inspect-package --dir PATH [--json]
firstcall-cli import-package --dir PATH [--data-dir PATH --config-dir PATH] [--json]
firstcall-cli recipe-list [--data-dir PATH --config-dir PATH] [--json]
firstcall-cli recipe-show --id ID [--data-dir PATH --config-dir PATH] [--json]
```

Without `--json`, CLI commands keep human-readable output. With `--json`, report-producing commands emit machine-readable JSON for agents, CI, and scripts. Actual `verify --json` is supported for recipe JSON and recipe id sources, but reports include only safe fields: no raw request/response bodies, headers, environment values, slot current values, or resolved secret-bearing URLs.

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

```powershell
cargo run --bin firstcall-cli -- verify `
  --recipe-json ./recipe.json `
  --json `
  --out ./recipe.verified.json `
  --lock-out ./verified.lock.json
```

`verify` executes the recipe from the local machine. Secrets must come from environment variables, and raw secret values are not written to the updated recipe, lock file, human output, or JSON report. `POST`, `PUT`, `PATCH`, and `DELETE` require `--allow-mutating`.

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
cargo run --bin firstcall-cli -- verify --recipe-id 1 --json
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1 --dry-run --json
```

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --dry-run --json
```

`verify --dry-run` and `verify --preflight` are aliases. They perform local static/runtime-input preflight only, do not execute HTTP, and do not write `--out` or `--lock-out` files. Human and JSON reports list required environment variables by name with `set` or `missing` status only, never environment values or raw secrets. Mutating methods still require `--allow-mutating` to be ready for real verification. `verify --recipe-id` reads from local recipe storage and can perform actual local verification; on success it updates local SQLite verification metadata. Actual `verify --recipe-id --json` reports that update as `updated_stored_recipe_verification`; actual `verify --recipe-id` still does not support `--out` or `--lock-out`.

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

Maintainers with local Node dependencies already installed can request an optional MCP compile smoke:

```powershell
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --mcp-compile-smoke
```

`--mcp-compile-smoke` checks the generated TypeScript template with the local `mcp-server/node_modules` TypeScript compiler when present. It does not run `npm install`, does not use `npx`, does not run MCP Inspector, does not execute the generated server, does not send HTTP, and does not read secrets. Missing `node_modules` is reported as a warning so default static validation remains usable without Node.

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
- GUI credential entry can use an optional native keyring backend when FirstCall is built with the `native-keyring` Cargo feature
- When native keyring is unavailable or the feature is disabled, credentials fall back to session-only in-memory storage via `secrecy`
- CLI verification remains environment-first and does not read GUI keyring or session-memory secrets
- GUI auth values use password-style transient input and are not displayed raw after save
- Raw secrets are never intentionally written to SQLite, exports, package files, CLI reports, recipe-list/show output, or logs
- Tests use fake keyring backends and do not require the actual OS keyring

## Known Limitations

- OpenAPI parsing supports internal refs and path-aware local relative JSON/YAML refs; remote `$ref` fetching is intentionally disabled, refs outside the resolver root are skipped, and cyclic/deep/malformed refs produce sanitized notes
- Multipart non-file fields are parsed where possible; binary/file upload fields are skipped and marked unsupported in v1
- Docs parsing is conservative and heuristic-only
- Postman Collection v2.1 parsing is limited and static-only; it is not full Postman compatibility, does not execute scripts/tests, and does not import variable values as current slot values
- HAR parsing is limited and static-only with aggressive redaction; response bodies, response headers, response cookies, raw cookies, and captured secret values are not imported, and obvious static assets are skipped or warned
- `.http` / `.rest` parsing is limited and static-only; it supports common request lines, headers, JSON/form/text bodies, `###` request separators, and `{{variable}}` placeholders, but does not execute requests/scripts, load environments, import variable values, or provide full JetBrains HTTP Client compatibility
- Hurl parsing is limited and static-only for request sections only; it does not execute Hurl files and ignores response bodies, response headers, captures, assertions, cookies, options, and captured variables with sanitized notes
- Bruno/OpenCollection parsing is limited and static-only for single request files; it supports a conservative `.bru` and OpenCollection YAML subset, ignores scripts/tests/runtime hooks/docs/variables/environments with sanitized notes, and never executes requests or imports variable values
- GraphQL-over-HTTP support is detected metadata from JSON bodies in supported parser paths; there is no direct GUI GraphQL input tab, introspection, schema validation, subscriptions, WebSockets, or GraphQL-specific execution, and mutation-looking operations produce advisory notes only
- OpenAPI body templating focuses on common object/JSON/form/multipart non-file cases
- Cookie-based auth is reduced to a simple header-oriented fallback in the current MVP
- Recipe export writes into the app export directory instead of opening a save-file dialog

## Architecture Summary

- `src/main.rs`: native entry point
- `src/app.rs`: app state, persistence wiring, execution dispatch
- `src/ui/*`: screens for New Attempt, Attempts, Recipes, Settings
- `src/model/*`: typed domain models
- `src/parse/*`: `curl`, docs, OpenAPI, Postman, HAR, `.http` / `.rest`, Hurl, Bruno/OpenCollection, GraphQL-over-HTTP detection, and request source adapter parsing
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
