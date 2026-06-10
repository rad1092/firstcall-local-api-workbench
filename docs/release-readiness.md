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

CLI-only build check:

```powershell
cargo build --locked --bin firstcall-cli --no-default-features
cargo run --locked --bin firstcall-cli --no-default-features -- version
```

Release binary build check:

```powershell
cargo build --locked --release --bin firstcall --bin firstcall-cli
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

## Real Local And Live Checks

The two highest-value executable checks are:

```powershell
cargo test --locked --test verify_loopback
cargo test --locked --test lifecycle_cli
```

For an optional live external read-only verification, use a GitHub token through the normal CLI env-first path:

```powershell
$env:FIRSTCALL_BEARER_TOKEN = gh auth token
cargo run --locked --bin firstcall-cli -- verify --recipe-json fixtures/github-user-recipe.json --json --out ./tmp/github-user.verified.json --lock-out ./tmp/github-user.lock.json
Remove-Item Env:FIRSTCALL_BEARER_TOKEN
```

For generated MCP runtime confidence, verify a read-only recipe, build the
generated server, and call it through the MCP stdio client:

```powershell
$env:FIRSTCALL_BEARER_TOKEN = gh auth token
cargo run --locked --bin firstcall-cli -- verify --recipe-json fixtures/github-user-recipe.json --json --out ./tmp/github-user.verified.json --lock-out ./tmp/github-user.lock.json
cargo run --locked --bin firstcall-cli -- package --recipe-json ./tmp/github-user.verified.json --out ./tmp/github-user-agent-tool
Push-Location ./tmp/github-user-agent-tool/mcp-server
npm install
npm run build
Pop-Location
node ./scripts/mcp_roundtrip_client.mjs --package-dir ./tmp/github-user-agent-tool/mcp-server --tool github_authenticated_user --args "{}"
Remove-Item Env:FIRSTCALL_BEARER_TOKEN
```

The live GitHub and generated MCP checks send read-only GET requests. They use
environment variables for secrets and must not write raw tokens into repo files,
logs, GIFs, or release assets.

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
The CLI lifecycle GitHub Actions workflow also runs this storage-backed flow
through actual `verify --recipe-id` against a local loopback server and then
validates the re-exported package. It also installs generated MCP dependencies,
builds the generated server, and calls the generated tool against the loopback
server.

## Binary Release Assets

The release binary workflow should produce deterministic assets for each
published tag:

- `firstcall-<tag>-x86_64-pc-windows-msvc.zip`
- `firstcall-<tag>-x86_64-unknown-linux-gnu.tar.gz`
- `firstcall-<tag>-x86_64-apple-darwin.tar.gz`
- `firstcall-<tag>-aarch64-apple-darwin.tar.gz`
- `SHA256SUMS.txt`

Each archive should include both `firstcall` and `firstcall-cli`, plus a short
release README. Backfilled releases should keep the existing tag in place and
upload deterministic assets with `--clobber`.

After a release workflow run, verify:

```powershell
gh release view <tag> --repo rad1092/firstcall-local-api-workbench --json assets,url
```

Download at least one archive and run the packaged CLI:

```powershell
firstcall-cli version
firstcall-cli --help
```

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
- `firstcall --screen new --sample curl` opens the GUI with the curl sample parsed into a candidate.
- `firstcall --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --screen recipes` opens the GUI against an isolated store.
- The source selector includes `curl`, docs, OpenAPI, Postman Collection, HAR, `.http` / `.rest`, Hurl, and Bruno/OpenCollection.
- The curl sample still analyzes and produces at least one candidate.
- At least one non-curl source kind is reachable from the selector.
- Parser notes and warnings are visible after analysis.
- Multiple candidates can be selected when present.
- Required runtime slots are visible before execution.
- Auth slot entry uses password-style input, and saved auth values are not displayed raw.
- Running a request disables context-changing controls until it finishes.
- A successful result can be saved as a recipe.
- Markdown and JSON recipe exports open native save dialogs, write the selected file, and write nothing when canceled.
- The Recipes screen shows CLI lifecycle hints without executing them.
- The Settings screen explains the secret backend and that CLI verification remains environment-first.

## Demo Asset Refresh Checklist

Use this when README demo assets may have drifted:

- The GUI demo GIF still matches the current FirstCall desktop GUI.
- The GUI demo GIF is captured from an actual `firstcall.exe` window, preferably release profile or a downloaded release asset.
- The CLI demo GIF still matches current `firstcall-cli` behavior.
- `docs/assets/firstcall-cli.cast` commands match the displayed output mode.
- If the cast uses `--json`, output must be JSON-shaped.
- If the cast shows human-readable summaries, commands should not include `--json`.
- README demo links render correctly.
- Demo assets do not include secrets, real tokens, private URLs, or user-specific paths.
- Demo assets should be refreshed after major GUI flow or CLI lifecycle output changes.
- Demo refresh is not required for every code-only change.

## Release Validation Scope

Do not run or require:

- a cloud backend
- desktop UI import
- database schema migrations
- MCP Inspector
