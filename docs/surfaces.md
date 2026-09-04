# FirstCall Product Surfaces

FirstCall has two product surfaces built on the same local-first Rust library.
The boundary is intentional: the CLI is the automation surface, and the
desktop GUI is the interactive workbench.

For the current Cargo build boundary, desktop feature, and CLI-only build
commands, see [build-surfaces.md](build-surfaces.md).

## `firstcall-cli`

`firstcall-cli` is the scriptable surface for agents, CI, and local workflows.
It owns command-line behavior, human and JSON reports, and storage-backed
automation.

Current CLI-owned workflows:

- `serve --package`: native stdio MCP runtime with no Node dependency
- `verify --recipe-json`
- `verify --recipe-id`
- `package --recipe-json`
- `package --recipe-id`
- `validate-package`
- `inspect-package`
- `import-package`
- `recipe-list`
- `recipe-show`
- JSON reports for automation and inspection
- CI, agent, and script usage

CLI verification is environment-first. It must not read GUI keyring state or
session-memory credentials. CLI reports may name required environment variables,
but they must not print environment variable values, raw secrets, request or
response bodies, or resolved secret-bearing URLs.

## FirstCall Desktop GUI

The FirstCall desktop GUI is the `egui` / `eframe` human workbench. It owns
interactive authoring and local verification feedback.

Current GUI-owned workflows:

- interactive request-source intake
- source kind selection
- static parser notes and warnings
- `RequestDraft` candidate review
- runtime slot and auth entry
- local execution and verification feedback
- attempt list and detail review
- recipe list and detail review
- meaningful MCP tool name, purpose, parameter types and descriptions
- explicit write-operation permission for exported tools
- native package export, validation, connection configuration, and folder access
- settings and secret backend status display

The GUI currently exposes static source intake for `curl`, docs, OpenAPI,
Postman Collection, HAR, `.http` / `.rest`, Hurl, and Bruno/OpenCollection.
GraphQL-over-HTTP remains detected metadata from JSON request bodies rather
than a direct GUI input tab.

GUI execution context is protected while a request is running. Context-changing
actions are blocked, attempt persistence uses the run-start source input
snapshot, and successful recipe promotion uses the executed draft snapshot
rather than the mutable builder draft.

The GUI completes native package export through shared library functions,
validates the result, and provides the MCP client configuration. It never shells
out to firstcall-cli for product behavior. The connected MCP client later starts
the companion executable to run the tool. Advanced import and legacy TypeScript
packaging remain CLI workflows.

The optional native keyring backend is a GUI credential UX feature gated by the
`native-keyring` Cargo feature. When native keyring is unavailable or disabled,
the GUI falls back to session-memory secret storage. This does not change CLI
verification semantics.

## Shared Core Library

Both surfaces use shared library modules for core behavior:

- request and recipe model types
- source parsing and merge precedence
- local verification and preflight logic
- redaction and secret-safety helpers
- agent package export, validation, inspection, and import logic
- local SQLite storage repositories
- safe recipe summaries

New product behavior should be added to shared core modules when it is useful to
both surfaces. CLI flag parsing and CLI printing should stay in
`src/bin/firstcall-cli.rs`. GUI state and rendering should stay in `src/app.rs`
and `src/ui/*`.

## Coupling Rules

- The GUI must not parse CLI stdout.
- The GUI must not shell out to `firstcall-cli` for core behavior.
- The GUI must not duplicate CLI-only JSON report generation.
- Native package validation belongs in shared export code; the GUI presents its result.
- Package import and legacy TypeScript compilation remain advanced CLI operations.
- The CLI must not depend on `src/ui/*`.
- The CLI must not depend on `egui` / `eframe` app state.
- The CLI must not use GUI secret store or keyring state for verification.

Generated `mcp-server/` files remain package artifacts, not source of truth.
Optional MCP compile smoke remains opt-in through `validate-package`.
