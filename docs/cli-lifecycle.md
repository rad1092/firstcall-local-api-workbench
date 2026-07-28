# FirstCall CLI Lifecycle

`firstcall-cli` is the automation surface for agents, CI, and local scripts. It owns recipe verification, package export, package validation and inspection, package import, local recipe summaries, and JSON reports.

CLI verification is environment-first. It does not read GUI keyring or session-memory secrets.

## Command Overview

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

Without `--json`, commands keep human-readable output. With `--json`, report-producing commands emit machine-readable JSON for agents, CI, and scripts. JSON reports are safe summaries and do not include raw request/response bodies, headers, environment values, slot current values, or resolved secret-bearing URLs.

## Recipe Verification

Verify a recipe JSON from the local machine:

```powershell
$env:FIRSTCALL_BEARER_TOKEN = "..."
cargo run --bin firstcall-cli -- verify `
  --recipe-json ./recipe.json `
  --out ./recipe.verified.json `
  --lock-out ./verified.lock.json
```

Actual verification executes HTTP. Secrets must come from environment variables, and raw secret values are not written to the updated recipe, lock file, human output, or JSON report. `POST`, `PUT`, `PATCH`, and `DELETE` require `--allow-mutating`.

Check readiness without sending HTTP:

```powershell
cargo run --bin firstcall-cli -- verify --recipe-json ./recipe.json --dry-run --json
```

`verify --dry-run` and `verify --preflight` are aliases. They perform local static/runtime-input preflight only, do not execute HTTP, and do not write `--out` or `--lock-out` files. Reports list required environment variables by name with `set` or `missing` status only, never values.

Verify or preflight a stored recipe:

```powershell
cargo run --bin firstcall-cli -- verify --recipe-id 1 --dry-run --json
cargo run --bin firstcall-cli -- verify --recipe-id 1 --allow-mutating --json
```

Actual `verify --recipe-id` reads from local recipe storage and updates local SQLite verification metadata only on success. It does not support `--out` or `--lock-out`.

## Package Export

Package a verified recipe JSON:

```powershell
cargo run --bin firstcall-cli -- package --recipe-json ./recipe.verified.json --out ./dist/my-agent-tool
```

Package a verified recipe from local recipe storage:

```powershell
cargo run --bin firstcall-cli -- package --recipe-id 1 --out ./dist/my-agent-tool
```

`package --recipe-id` reads the stored recipe payload from local SQLite storage. It does not execute HTTP, does not mutate SQLite, and requires successful local verification metadata before export.

The generated package includes:

- `recipe.yaml`
- `skill.md`
- `policy.json`
- `verified.lock.json`
- `package.manifest.json`
- `mcp-server/` with a TypeScript MCP server template

Raw secrets are never exported. Secret values are represented as environment variable references such as `FIRSTCALL_BEARER_TOKEN` or `FIRSTCALL_API_KEY`.

Generated `mcp-server/` files are template artifacts. They are not source of truth for package import. Static package validation does not install Node dependencies or execute generated MCP code; the CI lifecycle workflow runs a separate generated MCP round-trip after package export.

## Validate, Inspect, And Import

Create a local sample package:

```powershell
cargo run --bin firstcall-cli -- package --recipe-json fixtures/verified-agent-recipe.json --out ./dist/sample-agent-tool
```

Run static validation:

```powershell
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --json
```

`validate-package` checks package structure, schema metadata, lock metadata, policy shape, MCP template markers, obvious secret leaks, and manifest hashes when present. It does not execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, execute the generated MCP server, import recipes, or modify files.

Maintainers with local Node dependencies already installed can request optional compile smoke:

```powershell
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --mcp-compile-smoke
```

`--mcp-compile-smoke` uses local `mcp-server/node_modules` when present. It does not run `npm install`, use `npx`, run MCP Inspector, execute the generated server, send HTTP, or read secrets. Missing `node_modules` is reported as a warning.

Inspect import-readiness:

```powershell
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool --json
```

`inspect-package` runs validation and checks import-readiness conditions such as manifest presence, recipe/policy agreement, and verified lock metadata. It does not import recipes, modify files, modify app storage, execute HTTP, or use generated `mcp-server/` files as source of truth.

Import an inspect-ready package:

```powershell
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --json
```

`import-package` writes one recipe into local SQLite storage and marks it as requiring local re-verification. It does not preserve verified status, import raw secrets, execute HTTP, run npm, compile TypeScript, run Node, run MCP Inspector, or execute generated MCP runtime.

## Local Recipe Storage

List stored recipes:

```powershell
cargo run --bin firstcall-cli -- recipe-list --json
```

Show one stored recipe:

```powershell
cargo run --bin firstcall-cli -- recipe-show --id 1 --json
```

For controlled tests, storage can be overridden with both directories:

```powershell
cargo run --bin firstcall-cli -- recipe-list --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
```

`recipe-list` and `recipe-show` are read-only safe summary commands. Output does not include `RuntimeSlot.current_value`, raw secrets, environment values, resolved secret-bearing URLs, or body contents.

## Full Local-First Lifecycle

```powershell
cargo run --bin firstcall-cli -- package --recipe-json ./recipe.verified.json --out ./dist/sample-agent-tool
cargo run --bin firstcall-cli -- validate-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/sample-agent-tool --json
cargo run --bin firstcall-cli -- import-package --dir ./dist/sample-agent-tool --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- recipe-list --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- recipe-show --id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --json
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --dry-run --json
cargo run --bin firstcall-cli -- verify --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --allow-mutating
cargo run --bin firstcall-cli -- package --recipe-id 1 --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --out ./dist/reverified-agent-tool
cargo run --bin firstcall-cli -- validate-package --dir ./dist/reverified-agent-tool --json
cargo run --bin firstcall-cli -- inspect-package --dir ./dist/reverified-agent-tool --json
```

Imported recipes require local re-verification before `package --recipe-id` can export them. `verify --recipe-id --dry-run` does not execute HTTP or update SQLite. Actual `verify --recipe-id` updates SQLite verification metadata only on success. `package --recipe-id` does not execute HTTP or mutate SQLite.
