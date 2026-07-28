# Contributing

FirstCall is a local-first verified API recipe workbench. Contributions should
keep the CLI, GUI, parser, storage, and package boundaries explicit.

## Development Setup

Install a stable Rust toolchain, then run:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked
```

The default build includes the desktop GUI:

```powershell
cargo run
```

The CLI can be built without desktop dependencies:

```powershell
cargo build --locked --bin firstcall-cli --no-default-features
cargo run --locked --bin firstcall-cli --no-default-features -- version
```

## Product Boundaries

- `firstcall` is the desktop GUI workbench.
- `firstcall-cli` is the automation surface for agents, CI, and scripts.
- Shared behavior should live in core library modules, not by shelling out from
  the GUI to the CLI.
- CLI verification remains environment-first and must not read GUI keyring or
  session-memory secrets.

## Safety Rules

- Do not write raw secrets to SQLite, exports, package files, CLI reports, logs,
  recipe-list, or recipe-show output.
- Do not include real tokens, private URLs, or user-specific paths in docs,
  fixtures, screenshots, GIFs, or release assets.
- Imported packages must require local re-verification before package-by-id
  re-export.
- Generated `mcp-server/` files are artifacts, not source of truth.
- Do not change the package schema, DB schema, CLI JSON schema, or parser
  semantics unless the change is explicitly scoped and tested.

## Release Checklist

Before cutting or backfilling a release, run the release-readiness checks in
[docs/release-readiness.md](docs/release-readiness.md).

Release assets should include both `firstcall` and `firstcall-cli` for each
supported target, plus `SHA256SUMS.txt`.
