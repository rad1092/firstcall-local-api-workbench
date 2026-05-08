# FirstCall Build Surfaces

This document records the current build boundary between the shared core
library, `firstcall-cli`, and the desktop GUI.

## Current State

The Rust package exposes one shared library crate and two binaries:

- `src/lib.rs`: shared library modules.
- `src/main.rs`: default desktop GUI binary.
- `src/bin/firstcall-cli.rs`: CLI automation binary.

`Cargo.toml` intentionally keeps `default-run = "firstcall"` so bare
`cargo run` launches the desktop GUI in the multi-binary package.

`eframe` and `egui` are currently package-level dependencies. They are used by
the desktop GUI entry point and UI modules, but they are not directly used by
`firstcall-cli`.

Current desktop-specific code:

- `src/main.rs`
- `src/app.rs`
- `src/ui/*`

Current shared core modules:

- `model`
- `parse`
- `merge`
- `verify`
- `export`
- `store`
- `exec`
- `util`

The CLI calls shared core library APIs for verification, package export,
package validation/inspection/import, and local recipe storage. It does not
parse GUI state, use `egui` / `eframe` app state, or read the GUI secret store
for verification.

## Current Commands

These commands remain the supported developer workflow today:

```powershell
cargo build --locked
cargo run
cargo run --bin firstcall-cli -- version
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked --features native-keyring
```

`cargo run` currently launches the desktop GUI. `firstcall-cli` remains
available through `cargo run --bin firstcall-cli -- ...`.

## Optional Desktop Feature Design

A future dependency-boundary implementation can move the GUI behind a Cargo
feature such as:

```toml
[features]
desktop = ["dep:eframe", "dep:egui"]
```

That implementation would also need to:

- make `eframe` and `egui` optional dependencies;
- gate `app` and `ui` exports in `src/lib.rs` behind `#[cfg(feature = "desktop")]`;
- define the desktop binary with `required-features = ["desktop"]`;
- preserve `firstcall-cli` behavior without the desktop feature;
- keep `native-keyring` semantics unchanged.

Expected follow-up validation commands for that implementation:

```powershell
cargo build --locked --bin firstcall-cli
cargo run --bin firstcall-cli -- version
cargo build --locked --features desktop
cargo build --locked --features native-keyring
cargo build --locked --features "desktop native-keyring"
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

## Deferred Decision

The optional desktop split is deferred because it changes the meaning of
default build/run workflows. Before implementing it, FirstCall should decide
whether `cargo run` should continue to launch the desktop GUI, or whether the
CLI should become the default run target.

Until that decision is made, `eframe` and `egui` remain package-level
dependencies, and the current host-native desktop build remains the default
package build.
