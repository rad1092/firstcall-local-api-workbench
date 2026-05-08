# Release Readiness

This checklist is for local FirstCall release candidates and agent handoffs. It keeps validation local-first and does not require external services.

## Required Checks

Formatting:

```powershell
cargo fmt --all -- --check
```

Core checks:

```powershell
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked
```

Focused CLI lifecycle checks:

```powershell
cargo test --locked --test lifecycle_cli
cargo test --locked --test agent_export
cargo test --locked --test verify_loopback
cargo test --locked --test verify_cli
cargo test --locked --test recipe_cli
cargo test --locked --test package_validation
cargo test --locked --test package_inspect
cargo test --locked --test package_import
```

## Lifecycle Contract

The CLI-first lifecycle expected for a release candidate is:

1. Package a verified recipe JSON with `package --recipe-json`.
2. Validate and inspect the package with `validate-package` and `inspect-package`.
3. Import the inspect-ready package into local SQLite storage with `import-package`.
4. Review safe recipe summaries with `recipe-list` and `recipe-show`.
5. Run storage-backed preflight with `verify --recipe-id --dry-run` or `--preflight`.
6. Run actual local verification with `verify --recipe-id`.
7. Re-export the verified stored recipe with `package --recipe-id`.
8. Validate and inspect the re-exported package.

`tests/lifecycle_cli.rs` covers this flow with local temp files, temp SQLite storage, and loopback HTTP only.

## Safety Checks

- Raw secrets must not be exported, imported, printed, or stored intentionally.
- CLI reports may show environment variable names, but must not show environment variable values.
- `recipe-list` and `recipe-show` expose safe summaries only: no `RuntimeSlot.current_value`, raw secrets, env values, resolved secret-bearing URLs, or body contents.
- Imported recipes require local re-verification before `package --recipe-id` can export them.
- `package --recipe-id` requires successful local verification metadata and does not execute HTTP or mutate SQLite.
- Generated `mcp-server/` files are artifacts, not package import source of truth.

## Desktop GUI Smoke Checklist

Use this as a local human smoke pass for the desktop workbench:

- `cargo run` opens the desktop GUI.
- The source selector includes `curl`, docs, OpenAPI, Postman Collection, HAR, `.http` / `.rest`, Hurl, and Bruno/OpenCollection.
- The curl sample still analyzes and produces at least one candidate.
- At least one non-curl source kind is reachable from the selector.
- Parser notes and warnings are visible after analysis.
- Multiple candidates can be selected when present.
- Required runtime slots are visible before execution.
- Auth slot entry uses password-style input, and saved auth values are not displayed raw.
- Running a request disables context-changing controls until it finishes.
- A successful result can be saved as a recipe.
- The Recipes screen shows CLI lifecycle hints without executing them.
- The Settings screen explains the secret backend and that CLI verification remains environment-first.

## Non-Goals For Release Validation

Do not run or require:

- generated MCP runtime execution
- `npm install`, `npm build`, Node, TypeScript compilation, or MCP Inspector
- external live HTTP tests
- a cloud backend
- desktop UI import
- database schema migrations
- dependency or workflow changes
