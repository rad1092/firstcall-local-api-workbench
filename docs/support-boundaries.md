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
- Local verification and generated MCP execution disable automatic redirects,
  keep the configured HTTP(S) origin fixed, abort after 30 seconds, and stop
  reading after the 1 MiB response limit. Structural path-slot values and common
  method-override or reverse-proxy routing headers are rejected.
- Local verification ignores system and environment proxies, validates every
  resolved DNS address on a worker, and pins the first successful address set
  for the secure client's lifetime. Rebuilding the client refreshes the pin;
  failed lookups remain fail-closed but may be retried.
- Generated MCP execution resolves and validates the complete DNS answer set
  once, pins that immutable set for the process lifetime, and connects through a
  custom lookup that returns one validated address while preserving the original
  Host header and TLS SNI. It uses direct Node HTTP(S) sockets and ignores proxy
  environment variables.
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
- Release archives carry GitHub artifact attestations. Native Windows signing
  and macOS signing/notarization are not implemented yet.
- DNS pins refresh only when the generated MCP process restarts. A failed or
  rejected first lookup also remains fail-closed until restart, and legitimate
  DNS failover therefore requires an operator restart.
- Local-first policy allows loopback and private-network destinations. This is
  intentional for local APIs, but an exposed deployment should set both policy
  allow flags to false or enforce a stricter egress boundary; generated tools
  must not be exposed as unrestricted public fetch proxies.

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
