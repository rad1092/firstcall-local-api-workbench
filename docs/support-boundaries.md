# FirstCall Support Boundaries

FirstCall is a local-first verified API recipe workbench. The adapters focus on
extracting safe request candidates, preserving useful request shape, and keeping
secrets out of package artifacts.

## Adapter Coverage

- **curl**: primary request source for exact method, URL, headers, auth hints,
  query values, and common body shapes.
- **OpenAPI**: local JSON/YAML documents with internal refs and path-aware local
  relative refs.
- **Postman Collection**: static Collection v2.1 request extraction.
- **HAR**: browser-capture request extraction with aggressive redaction.
- **`.http` / `.rest`**: common request-line, header, separator, and body
  patterns.
- **Hurl**: request-side URL, method, headers, auth, query, form, and body data.
- **Bruno / OpenCollection**: static single-request intake.
- **GraphQL-over-HTTP**: GraphQL evidence from supported JSON request bodies.

## Execution Model

FirstCall intentionally separates request intake from request execution:

- Source adapters parse request definitions; they do not run imported scripts,
  tests, hooks, response handlers, captures, assertions, or environment files.
- Captured response bodies, response headers, response cookies, and raw secret
  values stay out of recipe data.
- Remote OpenAPI refs are not fetched during local parsing.
- Generated `mcp-server/` files are runtime package artifacts; package import
  uses the verified recipe and policy files as source of truth.
- `validate-package --mcp-compile-smoke` is a local compile check. Runtime MCP
  confidence comes from a separate install/build/tool-call pass in CI or release
  verification.

## Current Edges

- Multipart non-file fields are parsed where possible; binary/file upload fields
  are not represented as portable recipe inputs yet.
- Docs parsing is conservative and heuristic by design.
- Cookie-based auth is normalized into header-oriented request data.
- Direct GUI GraphQL authoring, schema introspection, subscriptions, and
  WebSockets are outside the current workbench surface.

## Safety Invariants

- CLI verification is environment-first and does not read GUI keyring or
  session-memory secrets.
- Raw secrets are not intentionally written to SQLite, exports, package files,
  CLI reports, recipe-list/show output, logs, or demo assets.
- `recipe-list` and `recipe-show` expose safe summaries only.
- Imported recipes require local re-verification before storage-backed package
  export.
- `package --recipe-id` requires successful local verification metadata and does
  not execute HTTP or mutate SQLite.
