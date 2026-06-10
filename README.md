# FirstCall

[![CI](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/ci.yml)
[![CLI lifecycle](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/cli-lifecycle.yml)
[![Release binaries](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/release-binaries.yml/badge.svg)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/release-binaries.yml)
[![Security audit](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rad1092/firstcall-local-api-workbench/actions/workflows/security.yml)

```text
  ______ _          _    _____      _ _
 |  ____(_)        | |  / ____|    | | |
 | |__   _ _ __ ___| |_| |     __ _| | |
 |  __| | | '__/ __| __| |    / _` | | |
 | |    | | |  \__ \ |_| |___| (_| | | |
 |_|    |_|_|  |___/\__|\_____\__,_|_|_|
```

FirstCall is a local-first Rust workbench for turning API request sources into verified, redacted, agent-ready recipe packages. Its useful part is the trust chain: parse a request, verify it locally, export a package, inspect/import it, then re-verify before storage-backed re-export.

<img src="docs/assets/firstcall-cli-demo.gif" alt="FirstCall release download, CLI, package, and MCP demo" width="900">

<img src="docs/assets/firstcall-gui-workbench.gif" alt="FirstCall desktop GUI parsing a sample request and reading CLI-created recipe storage" width="900">

## Download

Download the archive for your OS from [GitHub Releases](https://github.com/rad1092/firstcall-local-api-workbench/releases), extract it, then run:

```powershell
firstcall --screen new --sample curl
firstcall-cli version
firstcall-cli --help
```

Each release archive includes:

- `firstcall`: desktop GUI workbench.
- `firstcall-cli`: automation CLI for agents, CI, and scripts.

The desktop GUI can be started against an isolated store for repeatable demos or validation:

```powershell
firstcall --data-dir ./tmp/firstcall-data --config-dir ./tmp/firstcall-config --screen recipes
```

## Quick Start

```powershell
cargo run --locked --bin firstcall-cli -- package --recipe-json fixtures/verified-agent-recipe.json --out ./tmp/demo-pkg
cargo run --locked --bin firstcall-cli -- validate-package --dir ./tmp/demo-pkg --json
cargo run --locked --bin firstcall-cli -- inspect-package --dir ./tmp/demo-pkg --json
```

Generated packages include `recipe.yaml`, `verified.lock.json`, `policy.json`, `skill.md`, `package.manifest.json`, and a TypeScript `mcp-server/`. Runtime MCP confidence is checked separately by installing generated dependencies, building the server, listing tools, and calling the generated tool.

## Safety

- Secrets are represented as environment variables and are not intentionally written to SQLite, package files, CLI reports, logs, or demo assets.
- Package validation checks schema, policy, manifest hashes, generated MCP markers, and obvious secret leaks; import-readiness also recomputes verified lock fingerprints against `recipe.yaml`.
- Imported packages are marked as requiring local re-verification before `package --recipe-id` can export them again.
- Static adapters do not execute imported scripts, tests, hooks, captures, assertions, or environment files.

## Docs

- [CLI lifecycle](docs/cli-lifecycle.md)
- [Agent package schema](docs/agent-package-schema.md)
- [Release readiness](docs/release-readiness.md)
- [Product surfaces](docs/surfaces.md)
- [Architecture](docs/architecture.md)
- [Support boundaries](docs/support-boundaries.md)
- [Contributing](CONTRIBUTING.md)

## Contributors

- rad1092
- OpenAI Codex, AI-assisted engineering
