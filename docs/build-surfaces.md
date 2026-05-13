# FirstCall Build Surfaces

This document records the current build boundary between the shared core
library, `firstcall-cli`, and the desktop GUI.

## Current State

The Rust package exposes one shared library crate and two binaries:

- `src/lib.rs`: shared library modules.
- `src/main.rs`: desktop GUI binary, enabled by the `desktop` feature.
- `src/bin/firstcall-cli.rs`: CLI automation binary.

`Cargo.toml` intentionally keeps `default-run = "firstcall"` and
`default = ["desktop"]`, so bare `cargo run` launches the desktop GUI in the
normal developer workflow.

`eframe`, `egui`, and `rfd` are optional dependencies enabled by the `desktop`
feature. The `app` and `ui` library modules are also gated behind `desktop`.
`firstcall-cli` builds without the desktop feature and does not depend on GUI
state or the GUI secret store for verification.

The `native-keyring` feature is separate from `desktop`. It enables the optional
native keyring backend for GUI credential UX while keeping CLI verification
environment-first.

## Current Commands

Default desktop workflow:

```powershell
cargo build --locked
cargo run
cargo run --bin firstcall-cli -- version
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
```

CLI-only workflow without desktop dependencies:

```powershell
cargo build --locked --bin firstcall-cli --no-default-features
cargo run --locked --bin firstcall-cli --no-default-features -- version
```

Feature checks:

```powershell
cargo build --locked --features desktop
cargo build --locked --features native-keyring
cargo build --locked --features "desktop native-keyring"
```

Release binary workflow:

```powershell
cargo build --locked --release --bin firstcall --bin firstcall-cli
```

GitHub release archives include both binaries for the target OS. CLI-only source
builds still use `--no-default-features` when desktop dependencies are not
wanted.

## Local Build Cache Size

Cargo writes build outputs and incremental caches under `target/`. This
directory is local developer cache, not source code and not part of release
archives.

`target/` can become large during FirstCall development because debug builds keep
symbols, integration tests produce separate binaries, GUI dependencies add large
native build artifacts, and Windows plus WSL builds may accumulate side by side.
This does not reflect normal user install size: release archives contain the
compiled `firstcall` and `firstcall-cli` binaries, not the local Cargo cache.

To reclaim disk space, remove Cargo build artifacts:

```powershell
cargo clean
```

If Windows and WSL builds are both used frequently, set separate target
directories to avoid mixing host artifacts:

```powershell
$env:CARGO_TARGET_DIR = "target\windows"
cargo build --locked
```

```bash
CARGO_TARGET_DIR=target/wsl cargo build --locked
```

## Boundary Rules

- `cargo run` launches the desktop GUI because default features include
  `desktop`.
- `cargo run --bin firstcall-cli -- ...` runs the CLI with the default feature
  set.
- `cargo run --bin firstcall-cli --no-default-features -- ...` runs the CLI
  without desktop dependencies.
- `cargo run --no-default-features` without `--bin firstcall-cli` is not the
  CLI-only command because the default desktop binary requires `desktop`.
- Product behavior should live in shared core modules when it is useful to both
  surfaces.
- CLI flag parsing and printing stay in `src/bin/firstcall-cli.rs`.
- GUI state and rendering stay in `src/app.rs` and `src/ui/*`.
