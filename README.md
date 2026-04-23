# FirstCall

FirstCall is a native local-first desktop tool for turning pasted `curl` commands, prose API docs, or OpenAPI snippets into one executable HTTP request. It helps fill runtime values, execute the call, classify the outcome, persist redacted attempts locally, and promote successful attempts into reusable recipes.

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
- `fixtures/*`: sample manual test inputs
