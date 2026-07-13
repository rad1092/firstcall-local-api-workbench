# FirstCall Architecture Map

This is a short map of the current repository layout. For the product boundary between the CLI, desktop GUI, and shared library, see [surfaces.md](surfaces.md). For build-surface details, see [build-surfaces.md](build-surfaces.md).

## Entry Points

- `src/main.rs`: default desktop GUI binary.
- `src/bin/firstcall-cli.rs`: CLI automation binary for verify, package, validate, inspect, import, and recipe storage commands.
- `src/lib.rs`: shared library crate used by both product surfaces.

## Shared Core

- `src/model/*`: typed domain models for sources, drafts, recipes, attempts, auth, bodies, slots, evidence, and confidence.
- `src/parse/*`: static request-source adapters for `curl`, docs, OpenAPI, Postman, HAR, `.http` / `.rest`, Hurl, Bruno/OpenCollection, and GraphQL-over-HTTP detection.
- `src/merge/*`: source precedence and candidate merge rules.
- `src/exec/*`: request execution, preflight, response classification, validation, and redaction.
- `src/verify/*`: recipe verification flow and safe reporting support.
- `src/store/*`: SQLite migrations/repositories and secret storage abstraction.
- `src/export/*`: curl, markdown, JSON recipe export, agent package export, package validation, package inspection, and inspect-gated package import.
- `src/util/*`: shared helpers used across parser, execution, and export code.

## Desktop GUI

- `src/app.rs`: desktop app state, persistence wiring, source analysis, execution dispatch, and recipe promotion.
- `src/ui/*`: New Attempt, Attempts, Recipes, and Settings screens.

The GUI calls shared core logic directly. It must not parse CLI stdout or shell out to `firstcall-cli` for core behavior.

## Packages And Fixtures

- `fixtures/*`: sample request and recipe inputs used by tests and manual checks.
- Generated agent package directories contain `recipe.yaml`, `skill.md`, `policy.json`, `verified.lock.json`, `package.manifest.json`, and `mcp-server/` artifacts. The MCP directory includes exact dependency versions and `package-lock.json`; the generated runtime loads and enforces package-root policy rather than treating it as documentation only. Its direct Node HTTP(S) transport validates the complete initial DNS answer set, pins it for the MCP process lifetime, preserves the logical Host/TLS SNI, and ignores proxy environment variables. DNS changes and cached lookup failures refresh only after process restart.

Generated `mcp-server/` files are artifacts. They are not source of truth for package import.
