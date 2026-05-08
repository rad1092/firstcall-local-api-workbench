# FirstCall

[![CI](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml)
[![CLI lifecycle](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml)
[![Security audit](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

FirstCall is a Rust 2024 local-first verified API recipe workbench. It turns request sources into `RequestDraft` candidates, requires local verification, promotes successful requests into reusable recipes, and exports verified recipes as redacted agent packages.

FirstCall is not a Postman, Hurl, or Bruno runner. Source adapters are static intake paths for building verified recipes; imported scripts, tests, runtime hooks, captured responses, and environment files are not executed.

## Demos

Desktop GUI workbench, captured from the current `firstcall` app.
Run it with `cargo run` or explicitly with `cargo run --bin firstcall`:

<img src="docs/assets/firstcall-gui-workbench.gif" alt="FirstCall desktop GUI workbench demo" width="900">

CLI lifecycle, rendered from actual `firstcall-cli` command output.
Run it with `cargo run --bin firstcall-cli -- version`; CLI-only builds use `cargo run --locked --bin firstcall-cli --no-default-features -- version`:

<img src="docs/assets/firstcall-cli-demo.gif" alt="FirstCall CLI lifecycle demo" width="900">

The terminal recording source is checked in as [docs/assets/firstcall-cli.cast](docs/assets/firstcall-cli.cast).

## Product Surfaces

FirstCall has two product surfaces built on shared local core logic:

- **FirstCall desktop GUI**: the `egui` / `eframe` human workbench for request source intake, source kind selection, parser notes, candidate review, runtime slot/auth entry, local HTTP execution, attempt review, recipe review, settings, and secret backend status.
- **`firstcall-cli`**: the automation surface for agents, CI, and scripts. It owns verify, package, validate-package, inspect-package, import-package, recipe-list/show, storage-backed verification flows, and JSON reports.

Current GUI source kinds are `curl`, docs, OpenAPI, Postman Collection, HAR, `.http` / `.rest`, Hurl, and Bruno/OpenCollection. GraphQL-over-HTTP is detected from JSON request bodies in supported parser paths; it is not a direct GUI input tab.

Read more:

- [Product surfaces](docs/surfaces.md)
- [Build surfaces](docs/build-surfaces.md)
- [Architecture map](docs/architecture.md)

## Trust Chain

FirstCall's core loop is:

```text
request source -> ParsedSource -> RequestDraft candidate -> local verification
-> verified Recipe -> redacted agent package -> validate/inspect/import
-> local re-verification before storage-backed re-export
```

The CLI lifecycle is documented in [docs/cli-lifecycle.md](docs/cli-lifecycle.md). Release and handoff checks are in [docs/release-readiness.md](docs/release-readiness.md).

## Quick Start

Build on the current host OS:

```powershell
cargo build --locked
```

Run the desktop workbench:

```powershell
cargo run
```

`default-run = "firstcall"` is intentional: this package has both the desktop GUI and `firstcall-cli`, and bare `cargo run` launches the desktop workbench.

Run the CLI:

```powershell
cargo run --bin firstcall-cli -- version
```

Run core local checks:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked
```

For the current package layout, GUI/CLI binaries, desktop feature, and CLI-only build commands, see [docs/build-surfaces.md](docs/build-surfaces.md).

## Verification And Packages

`firstcall-cli` supports:

- `verify --recipe-json` and `verify --recipe-id`
- `package --recipe-json` and `package --recipe-id`
- `validate-package`, `inspect-package`, and `import-package`
- `recipe-list` and `recipe-show`
- human-readable output and safe JSON reports

Recipes can be packaged only after successful local verification metadata exists. Imported packages are marked as requiring local re-verification before `package --recipe-id` can export them again. Generated `mcp-server/` files are package artifacts, not source of truth.

See [docs/cli-lifecycle.md](docs/cli-lifecycle.md) for the full command lifecycle and examples.

## Safety Summary

- CLI verification is environment-first and does not read GUI keyring or session-memory secrets.
- GUI auth values use password-style transient input and are not displayed raw after save.
- Raw secrets are not intentionally written to SQLite, exports, package files, CLI reports, recipe-list/show output, logs, or demo assets.
- Actual verify JSON reports do not include raw request/response bodies, environment values, slot current values, or resolved secret-bearing URLs.
- Mutating methods still require `--allow-mutating` where currently required.
- Optional MCP compile smoke is opt-in through `validate-package --mcp-compile-smoke`.

For non-goals and adapter limitations, see [docs/non-goals.md](docs/non-goals.md).

## Current Limitations

- Static adapters are intentionally limited and do not provide full compatibility with Postman, Hurl, Bruno, JetBrains HTTP Client, browsers, or GraphQL IDEs.
- OpenAPI remote refs are not fetched; path-aware local JSON/YAML refs are supported by the parser path that has a base directory.
- Multipart file uploads are not supported in v1; non-file fields are parsed where possible.
- GraphQL-over-HTTP support is detected metadata from JSON bodies only; there is no introspection, schema validation, subscriptions, or WebSockets.

More detail is in [docs/non-goals.md](docs/non-goals.md) and [docs/release-readiness.md](docs/release-readiness.md).
