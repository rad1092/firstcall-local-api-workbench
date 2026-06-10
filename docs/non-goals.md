# FirstCall Non-Goals And Current Limits

FirstCall is a local-first verified API recipe workbench. Its source adapters are static intake paths for building `RequestDraft` candidates, not compatibility runners for other tools.

## Non-Goals

- FirstCall is not a Postman runner.
- FirstCall is not a Hurl runner.
- FirstCall is not a Bruno runner.
- Imported scripts, tests, pre-request hooks, post-response hooks, response handlers, runtime hooks, captures, assertions, and environment files are not executed.
- Captured response bodies, response headers, response cookies, and raw secret values are not imported as recipe data.
- Remote OpenAPI `http://` and `https://` refs are not fetched.
- There is no cloud backend or marketplace.
- Generated `mcp-server/` files are package artifacts, not source of truth for package import.
- `validate-package --mcp-compile-smoke` is a local compile check only; generated MCP runtime checks are run separately in release/CI verification.

## Static Adapter Limits

- **Postman Collection**: limited static Collection v2.1 parsing; scripts/tests and variable values are ignored.
- **HAR**: limited static request extraction with aggressive redaction; browser-captured response data is not imported, and obvious static assets are skipped or warned.
- **`.http` / `.rest`**: conservative JetBrains-style request-file subset; requests, scripts, environments, dynamic variables, and imported variable values are not executed or loaded.
- **Hurl**: request-only subset; response bodies, response headers, captures, assertions, cookies, options, and captured variables are ignored with sanitized notes.
- **Bruno/OpenCollection**: limited static single-request subset; scripts, tests, runtime hooks, docs, variables, and environments are ignored with sanitized notes.
- **GraphQL-over-HTTP**: detected from JSON request bodies in supported parser paths; no direct GUI GraphQL input tab, introspection, schema validation, subscriptions, WebSockets, or GraphQL-specific execution.
- **OpenAPI**: internal refs and path-aware local relative JSON/YAML refs are supported; remote refs, refs outside the resolver root, cyclic refs, deep refs, malformed refs, and unsupported schemes are skipped safely.

## Technical Limits

- Multipart non-file fields are parsed where possible; binary/file upload fields are unsupported in v1.
- OpenAPI body templating focuses on common object, JSON, form, and multipart non-file cases.
- Docs parsing is conservative and heuristic-only.
- Cookie-based auth is reduced to a simple header-oriented fallback in the current MVP.

## Safety Invariants

- CLI verification remains environment-first and must not read GUI keyring or session-memory secrets.
- Raw secrets are not intentionally written to SQLite, exports, package files, CLI reports, recipe-list/show output, logs, or demo assets.
- `recipe-list` and `recipe-show` expose safe summaries only.
- Imported recipes require local re-verification before storage-backed package export.
- `package --recipe-id` requires successful local verification metadata and does not execute HTTP or mutate SQLite.
