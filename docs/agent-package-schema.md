# FirstCall Agent Package Schema

## Purpose

This document defines the exported FirstCall Agent Recipe package format and the current CLI import-readiness policy.

FirstCall Agent Recipes packages are produced after a real local verification succeeds. The package format is local-first, redacted, environment-variable-backed, and intended to be useful to coding agents without becoming a cloud service or a marketplace format.

This document is a schema and design reference. `firstcall-cli validate-package`, `firstcall-cli inspect-package`, and `firstcall-cli import-package` exist today. `recipe-list` and `recipe-show` expose safe read-only summaries from local recipe storage. Recipe YAML-only import and desktop UI import do not exist today.

## Package Root Layout

Expected generated package tree:

```text
dist/sample-agent-tool/
  recipe.yaml
  verified.lock.json
  skill.md
  policy.json
  package.manifest.json
  mcp-server/
    package.json
    tsconfig.json
    src/server.ts
    README.md
```

File purposes:

- `recipe.yaml`: the portable agent recipe description. It contains method, URL template, auth metadata, headers, query parameters, body template, input slots, verification metadata, and security metadata.
- `verified.lock.json`: verification lock metadata. It records whether the recipe was verified, the last successful status/time, deterministic fingerprints, redaction policy version, and generator.
- `skill.md`: concise agent-facing usage notes, safety rules, inputs, environment variables, and last verification information.
- `policy.json`: static policy constraints for future agent governance, including allowed methods, hosts, paths, secret headers/query keys, confirmation requirements, and response redaction keys.
- `package.manifest.json`: integrity metadata for generated package files. It records package-relative paths and SHA-256 hashes over raw file bytes.
- `mcp-server/package.json`: generated TypeScript MCP server package metadata and dependencies.
- `mcp-server/tsconfig.json`: generated TypeScript compiler configuration.
- `mcp-server/src/server.ts`: generated MCP server template exposing one tool for the recipe.
- `mcp-server/README.md`: generated MCP server quickstart and environment-variable notes.

## recipe.yaml Schema

`recipe.yaml` is the main human-readable recipe artifact. It is not a secret store.

Required top-level fields:

- `schema_version`: package recipe schema version. Current value is `1`.
- `generator`: generator identifier. Current value is `firstcall`.
- `name`: stable tool/recipe name.
- `description`: short recipe description.
- `method`: HTTP method. It should be uppercase, for example `GET` or `POST`.
- `url_template`: absolute URL template with readable exported placeholders such as `${user_id}`.
- `auth`: auth metadata.
- `headers`: non-auth static or templated headers.
- `query`: non-auth static or templated query parameters.
- `body_template`: request body template.
- `slots`: runtime input slot definitions.
- `verified`: last successful verification metadata.
- `security`: secret/redaction metadata.

Compact example:

```yaml
schema_version: 1
generator: firstcall
name: example_get_user
description: "Verified API tool recipes for AI agents."
method: POST
url_template: "https://api.example.com/users/${user_id}"
auth:
  type: bearer
  env: FIRSTCALL_BEARER_TOKEN
  header_name: Authorization
headers:
  Accept: application/json
query:
  include: "${include}"
body_template:
  email: "${email}"
slots:
  - name: user_id
    location: path
    required: true
  - name: include
    location: query
    required: false
  - name: email
    location: body
    required: true
verified:
  last_success_at: "2026-04-29T00:00:00Z"
  last_success_status: 200
security:
  secrets_stored: false
  secret_source: env
  redacted: true
  environment_variables:
    - FIRSTCALL_BEARER_TOKEN
```

## Placeholder Syntax

FirstCall currently has two related placeholder forms:

- Source recipe and runtime templates may use double-brace placeholders such as `{{slot_name}}` or `{{user_id}}`.
- Exported agent package artifacts currently normalize runtime slot placeholders into `${slot_name}` form, such as `${user_id}`.

For example, a source recipe URL of `https://api.example.com/users/{{user_id}}` is exported in `recipe.yaml`, `skill.md`, and the generated MCP template as `https://api.example.com/users/${user_id}`.

Environment variable names are not runtime slot placeholders. `FIRSTCALL_API_KEY` is an environment variable name. `${FIRSTCALL_API_KEY}` is an env-backed reference in a templated value field. `auth.env: FIRSTCALL_BEARER_TOKEN` is metadata naming an environment variable, not a slot placeholder.

Secret environment references may appear as plain environment variable names or as env-backed template references depending on the field:

- Auth metadata fields such as `auth.env`, `username_env`, and `password_env` use plain names like `FIRSTCALL_BEARER_TOKEN`.
- Header, query, URL query, or body template values may use env-backed references such as `${FIRSTCALL_API_KEY}`.

The important invariant is readability: runtime placeholders and env-backed references must remain readable and must not be percent-encoded as `%24%7B...%7D`.

URL and template rules:

- `url_template` must be absolute enough for local verification and generated tool execution.
- Exported agent package placeholders should remain readable, for example `${slot_name}`.
- `url_template` must not contain executable `<redacted>` values.
- Secret-looking URL query values must be represented by environment-variable references, not raw values.

Headers, query, and body rules:

- `headers`, `query`, and `body_template` must not contain raw secrets.
- Auth-generated headers or query parameters should be represented through `auth`, not duplicated in `headers` or `query`.
- Non-auth secret-looking headers or query parameters must use environment-variable names.
- Body templates must not contain executable `<redacted>` values.

Slot rules:

- Each slot should define `name`, `location`, and `required`.
- Slot locations are expected to be values such as `path`, `query`, `header`, `body`, or `auth`.
- Exported/import-ready packages should not rely on raw secret slot current values.
- Non-secret current values may exist in source recipe JSON, but portable agent packages should prefer templates and environment-backed secrets.

Auth variants:

- `none`: no auth environment variables required.
- `bearer`: reads bearer token from `FIRSTCALL_BEARER_TOKEN`.
- `basic`: reads username from `FIRSTCALL_USERNAME` and password from `FIRSTCALL_PASSWORD`.
- `header_api_key`: reads API key from `FIRSTCALL_API_KEY` and sends it in the configured header.
- `query_api_key`: reads API key from `FIRSTCALL_API_KEY` and sends it in the configured query parameter.

Environment variable conventions:

- Bearer token: `FIRSTCALL_BEARER_TOKEN`
- API key: `FIRSTCALL_API_KEY`
- Basic username: `FIRSTCALL_USERNAME`
- Basic password: `FIRSTCALL_PASSWORD`
- Non-auth slot values during local verification: `FIRSTCALL_SLOT_<UPPER_SANITIZED_SLOT_NAME>`, for example `FIRSTCALL_SLOT_USER_ID`

## verified.lock.json Schema

`verified.lock.json` records verification and fingerprint metadata. It is integrity metadata, not a secret store.

Required fields:

- `schema_version`: lock schema version. Current value is `1`.
- `recipe_name`: source recipe name.
- `verified`: must be `true` for an exportable verified package.
- `last_success_at`: RFC3339 timestamp for the last successful local verification.
- `last_success_status`: HTTP status for the last successful verification. Must be `200..=299`.
- `request_fingerprint`: 64-character lowercase SHA-256-shaped hex string for the safe canonical request.
- `response_schema_fingerprint`: 64-character lowercase SHA-256-shaped hex string for response schema metadata.
- `redaction_policy_version`: redaction policy version used when generating the package.
- `generator`: generator identifier. Current value is `firstcall`.

Compact example:

```json
{
  "schema_version": 1,
  "recipe_name": "example_get_user",
  "verified": true,
  "last_success_at": "2026-04-29T00:00:00Z",
  "last_success_status": 200,
  "request_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "response_schema_fingerprint": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "redaction_policy_version": 1,
  "generator": "firstcall"
}
```

Rules:

- `verified` must be `true` for a verified package.
- `last_success_at` must be present and must not be `unverified`.
- `last_success_status` must be in `200..=299`.
- Fingerprints must be 64-character lowercase hex strings.
- The lock file must not contain request bodies, response bodies, headers, query values, or any raw secrets.

## policy.json Schema

`policy.json` constrains what an agent tool package may execute. It is a static governance artifact and should be conservative.

Required fields:

- `schema_version`: policy schema version. Current value is `1`.
- `allowed_methods`: non-empty array of allowed HTTP methods.
- `allowed_hosts`: non-empty array of allowed hosts.
- `allowed_paths`: non-empty array of allowed paths.
- `blocked_headers`: headers that should not be sent.
- `secret_headers`: headers treated as secret-bearing.
- `secret_query_keys`: query keys treated as secret-bearing.
- `requires_confirmation`: boolean confirmation flag for mutating/destructive calls.
- `redact_response_keys`: response keys to redact in previews or logs.

Compact example:

```json
{
  "schema_version": 1,
  "allowed_methods": ["GET"],
  "allowed_hosts": ["api.example.com"],
  "allowed_paths": ["/users/slot"],
  "blocked_headers": [],
  "secret_headers": [
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
    "X-API-Key"
  ],
  "secret_query_keys": [
    "api_key",
    "token",
    "secret",
    "access_token",
    "refresh_token"
  ],
  "requires_confirmation": false,
  "redact_response_keys": [
    "token",
    "secret",
    "password",
    "api_key",
    "access_token",
    "refresh_token"
  ]
}
```

Rules:

- `DELETE`, `PUT`, and `PATCH` require confirmation under current policy rules.
- `POST` requires confirmation when the path appears destructive, for example delete, remove, cancel, refund, or archive style paths.
- Non-destructive `POST` may remain confirmation-free under current policy rules.
- Current `policy.json` generation parses the source recipe URL with placeholder-safe replacements. Runtime placeholders such as `{{user_id}}` or `${user_id}` are replaced with the parse-safe literal `slot` for `allowed_paths`, so a recipe path like `/users/{{user_id}}` currently becomes `/users/slot`.
- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and `X-API-Key` are treated as secret headers.
- Common secret query keys include `api_key`, `token`, `secret`, `access_token`, and `refresh_token`.
- Common response redaction keys include `token`, `secret`, `password`, `api_key`, `access_token`, and `refresh_token`.
- Future import-readiness logic may need stricter reconciliation between `recipe.yaml` and `policy.json` before persistence, because `recipe.yaml` preserves exported runtime placeholders while current `policy.json` stores parse-safe paths.

## package.manifest.json Schema

`package.manifest.json` records SHA-256 hashes for generated package files. It is used by `validate-package` to detect tampering when present.

Required fields:

- `schema_version`: manifest schema version. Current value is `1`.
- `generator`: generator identifier. Current value is `firstcall`.
- `generated_at`: RFC3339 timestamp for manifest creation.
- `files`: non-empty array of package-relative file hash entries.

Compact example:

```json
{
  "schema_version": 1,
  "generator": "firstcall",
  "generated_at": "2026-04-29T00:00:00Z",
  "files": [
    {
      "path": "recipe.yaml",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
      "path": "verified.lock.json",
      "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    }
  ]
}
```

Rules:

- `package.manifest.json` must exclude itself from `files`.
- Hashes are computed from raw file bytes, not UTF-8 text.
- File paths must be package-relative paths using forward slashes.
- Unsafe paths are errors, including absolute paths, paths with `..`, paths with backslashes, empty path components, and `package.manifest.json` itself.
- Duplicate paths are errors.
- Missing expected file entries are errors.
- Hash mismatches are errors.
- Extra files are warning-only unless they violate safety or integrity rules.
- Deterministic manifest ordering means the `files` array order must be deterministic. The manifest itself may contain non-deterministic `generated_at` and does not need to be byte-for-byte reproducible across exports.

## MCP Server Template Files

The `mcp-server/` directory contains generated template artifacts.

Current generated MCP server behavior:

- Exposes one MCP tool matching the recipe.
- Reads required secrets from environment variables only.
- Accepts slot inputs as tool arguments.
- Constructs and performs the HTTP request at runtime.
- Returns text content plus `structuredContent`.
- Uses `outputSchema` with `status`, `ok`, and `body_preview`.
- Produces a redacted response preview.
- Includes tool annotations such as `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`.

Tool annotations are advisory hints only. They are not security controls. The real guardrails remain `policy.json`, local verify guards, `validate-package`, no raw secret export, and environment-variable-only secret handling.

Rust tests and `validate-package` do not execute:

- `npm install`
- `npm build`
- TypeScript compilation
- Node
- MCP Inspector
- the generated MCP runtime

The generated MCP server files are artifacts. They should not be treated as the source of truth for future import.

## Static Validation Rules

Current `firstcall-cli validate-package --dir PATH` behavior is static-only.

It checks:

- Required package layout.
- Required files and directories.
- YAML and JSON parseability.
- `recipe.yaml` required fields.
- `recipe.yaml` security metadata.
- 2xx verified semantics in `recipe.yaml`.
- `verified.lock.json` verified metadata.
- Secret leak markers and high-confidence bearer/API-key/password-like values.
- `policy.json` shape and confirmation requirements.
- MCP template markers, including structured output and annotations.
- `mcp-server/package.json` and `mcp-server/tsconfig.json` shape.
- Manifest paths and hashes when `package.manifest.json` is present.

It does not check:

- Live API availability.
- HTTP execution.
- npm installation.
- TypeScript compilation.
- Node execution.
- MCP Inspector.
- Generated MCP runtime behavior.
- Recipe import.
- File modification.
- Whether future agent execution is safe in every environment.

## Warning vs Error Policy

Warnings are compatibility or advisory findings. Warnings do not fail validation.

Errors are integrity, schema, safety, or required-structure failures. Errors make the package invalid and cause `validate-package` to exit non-zero.

Examples of warnings:

- Missing `package.manifest.json` under current validation behavior, for backward compatibility.
- Extra package files that do not violate safety or integrity rules.
- Conservative policy coverage suggestions.

Examples of errors:

- Missing required files.
- Required file path is a symlink.
- Invalid YAML or JSON.
- `verified.lock.json` does not have `verified: true`.
- `last_success_status` is not `200..=299`.
- Raw secret-like value is found.
- Manifest path is unsafe.
- Manifest hash mismatch.
- Policy allows guarded mutating methods without confirmation.

Import-readiness is stricter than current validation: missing `package.manifest.json` may remain a validation warning for legacy packages, but `inspect-package` and `import-package` block readiness by default.

## Secret Handling Rules

Raw secrets must never be exported.

Raw secrets must never be imported.

Secret values must not be written to:

- `recipe.yaml`
- `verified.lock.json`
- `policy.json`
- `package.manifest.json`
- `skill.md`
- `mcp-server/package.json`
- `mcp-server/tsconfig.json`
- `mcp-server/src/server.ts`
- `mcp-server/README.md`

Secret references must use environment variable names. Validation and preflight reports may show environment variable names and set/missing status only. They must not show values.

Examples of acceptable environment variable names:

- `FIRSTCALL_BEARER_TOKEN`
- `FIRSTCALL_API_KEY`
- `FIRSTCALL_USERNAME`
- `FIRSTCALL_PASSWORD`
- `FIRSTCALL_SLOT_USER_ID`

## 2xx Verification Semantics

A recipe is exportable only after successful local verification.

Successful verification means:

- `last_success_at` is present.
- `last_success_status` is in `200..=299`.

Non-2xx responses must not mark a recipe as verified.

Verification is local. The user supplies secrets through environment variables. Mutating methods such as `POST`, `PUT`, `PATCH`, and `DELETE` remain guarded by `--allow-mutating`.

Local loopback verification tests are allowed. External live HTTP tests are not required for Rust tests.

## Machine-Readable CLI Reports

Several CLI surfaces support `--json` for agents, CI, and scripts:

- `firstcall-cli validate-package --dir PATH --json`
- `firstcall-cli inspect-package --dir PATH --json`
- `firstcall-cli import-package --dir PATH --json`
- `firstcall-cli verify --recipe-json PATH --dry-run --json`
- `firstcall-cli verify --recipe-json PATH --preflight --json`
- `firstcall-cli recipe-list --json`
- `firstcall-cli recipe-show --id ID --json`

JSON reports use safe, sanitized fields. Environment variable names may appear, but environment variable values and raw secrets must not appear. Blocked report states should still emit parseable JSON to stdout when a report can be built. Argument and usage errors may remain normal stderr-only errors.

Actual non-dry-run HTTP `verify --json` is not supported yet.

## Import-Readiness Policy

`firstcall-cli inspect-package --dir PATH` implements a static import-readiness report. It does not import packages, persist recipes, modify app storage, execute HTTP, or run generated MCP tooling.

`firstcall-cli import-package --dir PATH` imports inspect-ready package directories into local SQLite recipe storage. It clears verification metadata during conversion, so imported recipes require local re-verification. It does not import raw secrets, execute HTTP, run generated MCP tooling, or use generated `mcp-server/` files as source of truth.

Actual desktop UI import remains design-only. The CLI import flow is package-directory-based and only runs after inspect-readiness succeeds.

Current CLI import and future desktop import decisions:

- Import is package-directory-based, not `recipe.yaml`-only.
- Import runs `validate-package` first through inspect-readiness.
- Import requires validation success and inspect-readiness success.
- Missing `package.manifest.json` may remain a validation warning for legacy packages, but import requires `package.manifest.json` by default.
- Imported recipes are marked as needing local re-verification.
- Raw secrets must never be imported.
- Imported auth must remain environment-variable-backed.
- If `policy.json` and `recipe.yaml` disagree, import should block.
- Full request fingerprint recomputation is deferred, but malformed `verified.lock.json` fingerprint fields block readiness.
- Generated `mcp-server/` files should be treated as artifacts, not source of truth.
- Import should not execute HTTP.
- Import should not run npm, TypeScript, Node, MCP Inspector, or generated MCP runtime.
- Import should not modify files outside the intended local app storage path.
- Inspect provides a clear readiness report before import persistence.
- `recipe-list` and `recipe-show` provide safe read-only summaries from local SQLite recipe storage.

## Open Questions and Future Phases

Phase 4B `inspect-package` is complete.

Phase 4C `import-package` is complete.

Phase 5A JSON reports and safe read-only recipe storage CLI are present.

Desktop UI integration should still wait until the CLI contract is stable.

Open questions:

- Whether future import should record package provenance in SQLite.
- Whether legacy packages without `package.manifest.json` should be importable behind an explicit flag.
- Whether future `recipe-export-json`, `verify --recipe-id`, and `package --recipe-id` should expose only safe/redacted recipe fields.

## Non-Goals

This document does not define implementation details for:

- Codecov
- release workflow
- SBOM
- signing
- SLSA provenance
- dependency upgrades
- OAuth
- cloud backend
- marketplace
- remote OpenAPI reference fetching
- full OpenAPI-to-MCP generation
- desktop UI redesign
