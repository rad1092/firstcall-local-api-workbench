use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::exec::redact::sanitize_response_schema;
use crate::model::{AuthStyle, Recipe};

use super::agent_common::{
    PRODUCT_LABEL, TAGLINE, all_env_requirements, auth_type, body_kind, body_template_value,
    destructive_method, ensure_no_read_only_method_override, export_slots, looks_destructive_path,
    non_auth_headers_map, non_auth_query_map, parse_agent_url_template, parse_url_template,
    recipe_slug, sanitize_url_template_for_agent,
};

#[derive(Serialize)]
struct McpRecipeTemplate {
    name: String,
    description: String,
    method: String,
    origin: String,
    path_template: String,
    url_query: Vec<(String, String)>,
    auth_type: String,
    bearer_token_env: Option<String>,
    basic_username_env: Option<String>,
    basic_password_env: Option<String>,
    header_api_key_header: Option<String>,
    header_api_key_env: Option<String>,
    query_api_key_param: Option<String>,
    query_api_key_env: Option<String>,
    headers: BTreeMap<String, String>,
    query: BTreeMap<String, String>,
    body_kind: String,
    body_template: Value,
    response_schema: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolAnnotations {
    read_only_hint: bool,
    destructive_hint: bool,
    idempotent_hint: bool,
    open_world_hint: bool,
}

pub fn write_mcp_server_package(recipe: &Recipe, out_dir: &Path) -> Result<()> {
    let server_dir = out_dir.join("mcp-server");
    let src_dir = server_dir.join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(server_dir.join("package.json"), package_json(recipe)?)?;
    fs::write(
        server_dir.join("package-lock.json"),
        package_lock_json(recipe)?,
    )?;
    fs::write(server_dir.join("tsconfig.json"), tsconfig_json())?;
    fs::write(src_dir.join("server.ts"), server_ts(recipe)?)?;
    fs::write(server_dir.join("README.md"), readme_md(recipe))?;
    Ok(())
}

fn package_json(recipe: &Recipe) -> Result<String> {
    let mut package: Value =
        serde_json::from_str(include_str!("../../assets/mcp-server/package.json"))?;
    set_package_identity(&mut package, recipe)?;
    serde_json::to_string_pretty(&package).map_err(anyhow::Error::from)
}

fn package_lock_json(recipe: &Recipe) -> Result<String> {
    let mut lock: Value =
        serde_json::from_str(include_str!("../../assets/mcp-server/package-lock.json"))?;
    set_package_identity(&mut lock, recipe)?;
    let root = lock
        .get_mut("packages")
        .and_then(Value::as_object_mut)
        .and_then(|packages| packages.get_mut(""))
        .context("MCP package lock template is missing packages['']")?;
    set_package_identity(root, recipe)?;
    serde_json::to_string_pretty(&lock).map_err(anyhow::Error::from)
}

fn set_package_identity(value: &mut Value, recipe: &Recipe) -> Result<()> {
    let object = value
        .as_object_mut()
        .context("MCP package template root must be an object")?;
    object.insert(
        "name".to_string(),
        Value::String(format!("{}-mcp-server", recipe_slug(&recipe.name))),
    );
    object.insert(
        "version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    Ok(())
}

fn tsconfig_json() -> String {
    r#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "dist",
    "rootDir": "src"
  },
  "include": ["src/**/*.ts"]
}
"#
    .to_string()
}

fn server_ts(recipe: &Recipe) -> Result<String> {
    let url = parse_agent_url_template(&recipe.url_template)?;
    ensure_no_read_only_method_override(recipe, &url.query_pairs)?;
    let recipe_template = McpRecipeTemplate {
        name: recipe_slug(&recipe.name),
        description: TAGLINE.to_string(),
        method: recipe.method.to_ascii_uppercase(),
        origin: url.origin,
        path_template: url.path_template,
        url_query: url.query_pairs,
        auth_type: auth_type(&recipe.auth_style).to_string(),
        bearer_token_env: bearer_token_env(&recipe.auth_style),
        basic_username_env: basic_username_env(&recipe.auth_style),
        basic_password_env: basic_password_env(&recipe.auth_style),
        header_api_key_header: header_api_key_header(&recipe.auth_style),
        header_api_key_env: header_api_key_env(&recipe.auth_style),
        query_api_key_param: query_api_key_param(&recipe.auth_style),
        query_api_key_env: query_api_key_env(&recipe.auth_style),
        headers: non_auth_headers_map(recipe),
        query: non_auth_query_map(recipe),
        body_kind: body_kind(&recipe.body_template).to_string(),
        body_template: body_template_value(&recipe.body_template),
        response_schema: recipe
            .response_schema
            .as_ref()
            .map(sanitize_response_schema)
            .map(|schema| schema.schema),
    };
    let recipe_json = serde_json::to_string_pretty(&recipe_template)?;
    let input_shape = input_shape_ts(recipe);
    let tool_annotations = serde_json::to_string_pretty(&tool_annotations(recipe))?;
    let tool_name = serde_json::to_string(&recipe_slug(&recipe.name))?;
    Ok(SERVER_TS_TEMPLATE
        .replace("__RECIPE_JSON__", &recipe_json)
        .replace("__INPUT_SHAPE__", &input_shape)
        .replace("__TOOL_ANNOTATIONS__", &tool_annotations)
        .replace("__TOOL_NAME__", &tool_name)
        .replace("__FIRSTCALL_VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__TOOL_DESCRIPTION__", &serde_json::to_string(TAGLINE)?))
}

fn input_shape_ts(recipe: &Recipe) -> String {
    let slots = export_slots(&recipe.slots);
    let mut fields = slots
        .into_iter()
        .map(|slot| {
            let key = serde_json::to_string(&slot.name).expect("slot names serialize");
            let base = format!("z.string().describe({})", json_string(&slot.location));
            if slot.required {
                format!("  {key}: {base}")
            } else {
                format!("  {key}: {base}.optional()")
            }
        })
        .collect::<Vec<_>>();
    if is_mutating_method(&recipe.method) {
        fields.push(
            "  \"confirm_mutation\": z.literal(true).describe(\"Explicit confirmation for this mutating request\")"
                .to_string(),
        );
    }
    if fields.is_empty() {
        "{}".to_string()
    } else {
        format!("{{\n{}\n}}", fields.join(",\n"))
    }
}

fn is_mutating_method(method: &str) -> bool {
    !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
}

fn readme_md(recipe: &Recipe) -> String {
    let env_vars = all_env_requirements(recipe);
    let env_text = if env_vars.is_empty() {
        "- none".to_string()
    } else {
        env_vars
            .iter()
            .map(|item| format!("- `{}`: {}", item.name, item.description))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let readme = format!(
        "# {} MCP Server\n\nGenerated by {PRODUCT_LABEL}.\n\n{TAGLINE}\n\nThis is a template TypeScript MCP server for the verified recipe `{}`.\n\n## Quickstart\n\n```bash\nnpm ci --ignore-scripts\nnpm run build\nnpm start\n```\n\n## Tool\n\n- Name: `{}`\n- Method: `{}`\n- URL: `{}`\n\n## Required environment variables\n\n{}\n\n## Files\n\n- `package.json`\n- `package-lock.json`\n- `tsconfig.json`\n- `src/server.ts`\n\n## Notes\n\n- Secrets must come from environment variables only.\n- Do not commit raw secrets.\n- The server loads the package-root `policy.json` at startup and fails closed when it is missing, malformed, or inconsistent with the generated recipe.\n- Redirects are not followed, requests time out, and response bodies are read with the policy byte limit.\n- Structural path inputs plus method-override and proxy-routing headers are rejected.\n- A preserved response schema is compiled once with Ajv; truncated or schema-invalid responses return `ok: false`.\n- The tool returns text content plus structuredContent with `status`, `ok`, redacted `body_preview`, `body_truncated`, `bytes_read`, `schema_valid`, and `validation_errors`.\n- Mutating tools require both `FIRSTCALL_ALLOW_MUTATING=1` and `confirm_mutation=true`.\n- Tool annotations are advisory hints only; runtime policy enforcement and local verification remain the guardrails.\n- `firstcall-cli validate-package` is static by design. For runtime confidence, run `npm ci --ignore-scripts`, `npm run build`, and call the generated tool with an MCP stdio client.\n",
        recipe.name,
        recipe.name,
        recipe_slug(&recipe.name),
        recipe.method.to_ascii_uppercase(),
        sanitize_url_template_for_agent(&recipe.url_template),
        env_text
    );
    readme.replace(
        "- Structural path inputs plus method-override and proxy-routing headers are rejected.",
        "- The first DNS lookup validates the complete address set and pins it for the MCP process lifetime; restart the process to refresh DNS or clear a cached rejected lookup.\n- Requests use direct Node HTTP(S) sockets with the original Host and TLS SNI, and do not read proxy environment variables.\n- Structural path inputs plus method-override and proxy-routing headers are rejected.",
    )
}

fn tool_annotations(recipe: &Recipe) -> ToolAnnotations {
    let method = recipe.method.to_ascii_uppercase();
    let read_only_hint = matches!(method.as_str(), "GET" | "HEAD");
    let destructive_hint = destructive_method(&method)
        || (method == "POST" && looks_destructive_path(&annotation_path(recipe)));
    ToolAnnotations {
        read_only_hint,
        destructive_hint,
        idempotent_hint: read_only_hint,
        open_world_hint: true,
    }
}

fn annotation_path(recipe: &Recipe) -> String {
    parse_url_template(&recipe.url_template)
        .map(|(_, path)| path)
        .unwrap_or_else(|_| fallback_path_from_url_template(&recipe.url_template))
}

fn fallback_path_from_url_template(url_template: &str) -> String {
    let sanitized = sanitize_url_template_for_agent(url_template);
    let without_fragment = sanitized
        .split_once('#')
        .map_or(sanitized.as_str(), |(head, _)| head);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(head, _)| head);
    let Some(scheme_end) = without_query.find("://") else {
        return without_query.to_string();
    };
    let authority_start = scheme_end + 3;
    without_query[authority_start..]
        .find('/')
        .map(|index| without_query[authority_start + index..].to_string())
        .unwrap_or_default()
}

fn bearer_token_env(auth: &AuthStyle) -> Option<String> {
    matches!(auth, AuthStyle::Bearer { .. }).then(|| "FIRSTCALL_BEARER_TOKEN".to_string())
}

fn basic_username_env(auth: &AuthStyle) -> Option<String> {
    matches!(auth, AuthStyle::Basic { .. }).then(|| "FIRSTCALL_USERNAME".to_string())
}

fn basic_password_env(auth: &AuthStyle) -> Option<String> {
    matches!(auth, AuthStyle::Basic { .. }).then(|| "FIRSTCALL_PASSWORD".to_string())
}

fn header_api_key_header(auth: &AuthStyle) -> Option<String> {
    match auth {
        AuthStyle::HeaderApiKey { header_name, .. } => Some(header_name.clone()),
        _ => None,
    }
}

fn header_api_key_env(auth: &AuthStyle) -> Option<String> {
    matches!(auth, AuthStyle::HeaderApiKey { .. }).then(|| "FIRSTCALL_API_KEY".to_string())
}

fn query_api_key_param(auth: &AuthStyle) -> Option<String> {
    match auth {
        AuthStyle::QueryApiKey { param_name, .. } => Some(param_name.clone()),
        _ => None,
    }
}

fn query_api_key_env(auth: &AuthStyle) -> Option<String> {
    matches!(auth, AuthStyle::QueryApiKey { .. }).then(|| "FIRSTCALL_API_KEY".to_string())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

const SERVER_TS_TEMPLATE: &str = r#"import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { readFileSync } from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { Ajv, type AnySchema, type ErrorObject } from "ajv";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type ToolArgs = Record<string, string | boolean | undefined>;
type TemplateValue = string | number | boolean | null | TemplateValue[] | { [key: string]: TemplateValue };
type RecipeTemplate = {
  name: string;
  description: string;
  method: string;
  origin: string;
  path_template: string;
  url_query: Array<[string, string]>;
  auth_type: string;
  bearer_token_env: string | null;
  basic_username_env: string | null;
  basic_password_env: string | null;
  header_api_key_header: string | null;
  header_api_key_env: string | null;
  query_api_key_param: string | null;
  query_api_key_env: string | null;
  headers: Record<string, string>;
  query: Record<string, string>;
  body_kind: string;
  body_template: TemplateValue;
  response_schema: TemplateValue | null;
};
type ToolOutput = {
  status: number;
  ok: boolean;
  body_preview: string;
  body_truncated: boolean;
  bytes_read: number;
  schema_valid: boolean | null;
  validation_errors: string[];
};

type BoundedBody = {
  text: string;
  truncated: boolean;
  bytesRead: number;
};

type PinnedAddress = {
  address: string;
  family: 4 | 6;
};

type DirectResponse = {
  status: number;
  ok: boolean;
  body: BoundedBody;
};

const RECIPE: RecipeTemplate = __RECIPE_JSON__;
const TOOL_NAME = __TOOL_NAME__;
const TOOL_DESCRIPTION = __TOOL_DESCRIPTION__;
const TOOL_ANNOTATIONS = __TOOL_ANNOTATIONS__;
const POLICY_PATH = new URL("../../policy.json", import.meta.url);
const PolicySchema = z.object({
  schema_version: z.literal(2),
  allowed_methods: z.array(z.string().min(1)).min(1),
  allowed_origins: z.array(z.string().url()).min(1),
  allowed_path_templates: z.array(z.string().startsWith("/")).min(1),
  allowed_hosts: z.array(z.string().min(1)).min(1),
  allowed_paths: z.array(z.string().startsWith("/")).min(1),
  redirect_policy: z.object({
    mode: z.literal("none"),
    max_hops: z.literal(0),
  }).strict(),
  dns_policy: z.object({
    resolve_all_addresses: z.literal(true),
    pin_connection: z.literal(true),
    allow_loopback: z.boolean(),
    allow_private_networks: z.boolean(),
    blocked_address_classes: z.array(
      z.enum(["unspecified", "link_local", "multicast"]),
    ).length(3).refine(
      (classes) => ["unspecified", "link_local", "multicast"]
        .every((required) => classes.includes(required as typeof classes[number])),
      "must contain each required blocked address class exactly once",
    ),
  }).strict(),
  proxy_policy: z.object({
    mode: z.literal("direct"),
    environment_variables: z.literal("ignore"),
  }).strict(),
  timeout_ms: z.literal(30000),
  max_response_bytes: z.literal(1048576),
  blocked_headers: z.array(z.string().min(1)),
  secret_headers: z.array(z.string().min(1)),
  secret_query_keys: z.array(z.string().min(1)),
  requires_confirmation: z.boolean(),
  redact_response_keys: z.array(z.string().min(1)),
}).strict();
const POLICY = PolicySchema.parse(JSON.parse(readFileSync(POLICY_PATH, "utf8")));
const DNS_PIN_CACHE = new Map<string, Promise<readonly PinnedAddress[]>>();
const ajv = new Ajv({ strict: false, allErrors: true });
const validateResponse = RECIPE.response_schema === null
  ? null
  : ajv.compile(RECIPE.response_schema as AnySchema);

assertRecipePolicyReconciliation();

const server = new McpServer({
  name: `${TOOL_NAME}-firstcall`,
  version: "__FIRSTCALL_VERSION__",
});

const inputShape = __INPUT_SHAPE__;
const inputSchema = z.object(inputShape);
const outputSchema = z.object({
  status: z.number(),
  ok: z.boolean(),
  body_preview: z.string(),
  body_truncated: z.boolean(),
  bytes_read: z.number().int().nonnegative(),
  schema_valid: z.boolean().nullable(),
  validation_errors: z.array(z.string()),
});

server.registerTool(TOOL_NAME, {
  title: TOOL_NAME,
  description: TOOL_DESCRIPTION,
  inputSchema,
  outputSchema,
  annotations: TOOL_ANNOTATIONS,
}, async (args) => {
  const toolArgs = args as ToolArgs;
  assertMutationAllowed(toolArgs);

  const url = new URL(RECIPE.origin);
  url.pathname = renderPathTemplate(RECIPE.path_template, toolArgs);
  for (const [key, value] of RECIPE.url_query) {
    url.searchParams.append(key, fillTemplate(String(value), toolArgs));
  }
  for (const [key, value] of Object.entries(RECIPE.query)) {
    url.searchParams.append(key, fillTemplate(String(value), toolArgs));
  }

  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(RECIPE.headers)) {
    headers[key] = fillTemplate(String(value), toolArgs);
  }
  applyAuth(headers, url);

  const abortController = new AbortController();
  let requestBody: string | undefined;

  if (RECIPE.body_kind !== "none") {
    const renderedBody = renderTemplateValue(RECIPE.body_template, toolArgs);
    if (RECIPE.body_kind === "text") {
      requestBody = String(renderedBody);
    } else if (RECIPE.body_kind === "form") {
      requestBody = new URLSearchParams(stringRecord(renderedBody)).toString();
      setDefaultHeader(headers, "Content-Type", "application/x-www-form-urlencoded");
    } else if (RECIPE.body_kind === "multipart") {
      const multipart = renderMultipartBody(stringRecord(renderedBody));
      requestBody = multipart.body;
      setDefaultHeader(headers, "Content-Type", `multipart/form-data; boundary=${multipart.boundary}`);
    } else {
      requestBody = JSON.stringify(renderedBody);
      setDefaultHeader(headers, "Content-Type", "application/json");
    }
  }

  assertRequestAllowed(url, headers);
  const timeout = setTimeout(() => abortController.abort(), POLICY.timeout_ms);
  try {
    const response = await directRequest(
      url,
      headers,
      requestBody,
      abortController.signal,
      POLICY.max_response_bytes,
    );
    const boundedBody = response.body;
    const schemaResult = validateResponseBody(boundedBody.text, boundedBody.truncated);
    const redactedBodyPreview = redactResponsePreview(boundedBody.text);
    const structuredContent: ToolOutput = {
      status: response.status,
      ok: response.ok && !boundedBody.truncated && schemaResult.schemaValid !== false,
      body_preview: redactedBodyPreview,
      body_truncated: boundedBody.truncated,
      bytes_read: boundedBody.bytesRead,
      schema_valid: schemaResult.schemaValid,
      validation_errors: schemaResult.validationErrors,
    };
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(structuredContent),
        },
      ],
      structuredContent,
    };
  } catch (error) {
    if (abortController.signal.aborted) {
      throw new Error(`Request timed out after ${POLICY.timeout_ms} ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
});

function assertRecipePolicyReconciliation(): void {
  const method = RECIPE.method.toUpperCase();
  const canonicalOrigin = new URL(RECIPE.origin).origin;
  if (canonicalOrigin !== RECIPE.origin) {
    throw new Error("Generated recipe origin is not canonical");
  }
  assertLiteralHostAllowed(new URL(RECIPE.origin));
  if (!POLICY.allowed_methods.some((allowed) => allowed.toUpperCase() === method)) {
    throw new Error("Generated recipe method is not allowed by policy.json");
  }
  if (!POLICY.allowed_origins.includes(RECIPE.origin)) {
    throw new Error("Generated recipe origin is not allowed by policy.json");
  }
  if (!POLICY.allowed_path_templates.includes(RECIPE.path_template)) {
    throw new Error("Generated recipe path template is not allowed by policy.json");
  }
  if (POLICY.requires_confirmation !== isMutatingMethod(method)) {
    throw new Error("Generated recipe mutation policy is inconsistent");
  }
  const blockedHeaders = new Set(POLICY.blocked_headers.map((header) => header.toLowerCase()));
  for (const required of [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "cookie",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-for",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
  ]) {
    if (!blockedHeaders.has(required)) {
      throw new Error(`policy.json is missing required blocked header: ${required}`);
    }
  }
  for (const required of ["unspecified", "link_local", "multicast"] as const) {
    if (!POLICY.dns_policy.blocked_address_classes.includes(required)) {
      throw new Error(`policy.json is missing required blocked address class: ${required}`);
    }
  }
  assertNoReadOnlyMethodOverrideTemplate();
}

function assertMutationAllowed(args: ToolArgs): void {
  if (!isMutatingMethod(RECIPE.method)) {
    return;
  }
  if (process.env.FIRSTCALL_ALLOW_MUTATING !== "1") {
    throw new Error("Mutating tools require FIRSTCALL_ALLOW_MUTATING=1");
  }
  if (args.confirm_mutation !== true) {
    throw new Error("Mutating tools require confirm_mutation=true");
  }
}

function isMutatingMethod(method: string): boolean {
  const upper = method.toUpperCase();
  return upper !== "GET" && upper !== "HEAD";
}

function renderPathTemplate(template: string, args: ToolArgs): string {
  if (!template.startsWith("/")) {
    throw new Error("Generated path template must start with /");
  }
  const rendered = template.replace(/\$\{([^}]+)\}/g, (_match, name) => {
    const value = templateValue(String(name), args);
    if (isUnsafePathSlot(value)) {
      throw new Error(
        `Path slot ${String(name)} must not decode to a slash, backslash, or dot segment`,
      );
    }
    return encodeURIComponent(value);
  });
  for (const segment of rendered.split("/")) {
    if (isUnsafePathSlot(segment)) {
      throw new Error("Rendered path must not contain structural path segments");
    }
  }
  return rendered;
}

function isUnsafePathSlot(value: string): boolean {
  let candidate = value;
  for (let depth = 0; depth <= value.length; depth += 1) {
    if (
      candidate.includes("/") ||
      candidate.includes("\\") ||
      candidate === "." ||
      candidate === ".."
    ) {
      return true;
    }
    const decoded = candidate.replace(/%([0-9a-f]{2})/gi, (_match, hex) =>
      String.fromCharCode(Number.parseInt(String(hex), 16)));
    if (decoded === candidate) {
      return false;
    }
    candidate = decoded;
  }
  return true;
}

function templateValue(name: string, args: ToolArgs): string {
  if (Object.prototype.hasOwnProperty.call(args, name) && args[name] !== undefined) {
    return String(args[name]);
  }
  const fromEnv = process.env[name];
  if (fromEnv) {
    return fromEnv;
  }
  throw new Error(`Missing required value: ${name}`);
}

function assertRequestAllowed(url: URL, headers: Record<string, string>): void {
  const method = RECIPE.method.toUpperCase();
  if (!POLICY.allowed_methods.some((allowed) => allowed.toUpperCase() === method)) {
    throw new Error("Request method is not allowed by policy.json");
  }
  if (url.origin !== RECIPE.origin || !POLICY.allowed_origins.includes(url.origin)) {
    throw new Error("Request origin is not allowed by policy.json");
  }
  assertLiteralHostAllowed(url);
  if (!POLICY.allowed_path_templates.includes(RECIPE.path_template)) {
    throw new Error("Request path template is not allowed by policy.json");
  }

  const blocked = new Set(POLICY.blocked_headers.map((header) => header.toLowerCase()));
  for (const header of Object.keys(headers)) {
    if (blocked.has(header.toLowerCase())) {
      throw new Error(`Request header is blocked by policy.json: ${header}`);
    }
  }
  if (!isMutatingMethod(method)) {
    for (const key of url.searchParams.keys()) {
      if (key.toLowerCase() === "_method") {
        throw new Error("GET/HEAD requests must not contain a _method query parameter");
      }
    }
  }
}

async function directRequest(
  url: URL,
  headers: Record<string, string>,
  body: string | undefined,
  signal: AbortSignal,
  maxResponseBytes: number,
): Promise<DirectResponse> {
  const logicalHostname = hostnameWithoutBrackets(url.hostname);
  const pinnedSet = await resolvePinnedAddressSet(logicalHostname, signal);
  const pinned = pinnedSet[0];
  if (!pinned) {
    throw new Error("DNS resolution returned no usable addresses");
  }

  const options: https.RequestOptions = {
    protocol: url.protocol,
    hostname: logicalHostname,
    port: url.port ? Number(url.port) : undefined,
    path: `${url.pathname}${url.search}`,
    method: RECIPE.method,
    headers,
    agent: false,
    signal,
    family: pinned.family,
    lookup: createPinnedLookup(pinned),
    servername: url.protocol === "https:" && isIP(logicalHostname) === 0
      ? logicalHostname
      : undefined,
  };
  const requestFn = url.protocol === "https:" ? https.request : http.request;

  return new Promise<DirectResponse>((resolve, reject) => {
    let settled = false;
    const finish = (error: unknown, response?: DirectResponse): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (error) {
        reject(error);
      } else if (response) {
        resolve(response);
      } else {
        reject(new Error("Direct request ended without a response"));
      }
    };

    const request = requestFn(options, async (response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        response.destroy();
        finish(new Error(`Redirect blocked by policy (HTTP ${status})`));
        return;
      }
      try {
        const boundedBody = await readBoundedBody(response, maxResponseBytes);
        finish(null, {
          status,
          ok: status >= 200 && status < 300,
          body: boundedBody,
        });
      } catch (error) {
        finish(error);
      }
    });
    request.once("error", (error) => finish(error));
    request.end(body);
  });
}

async function resolvePinnedAddressSet(
  hostname: string,
  signal: AbortSignal,
): Promise<readonly PinnedAddress[]> {
  const literalFamily = isIP(hostname);
  if (literalFamily === 4 || literalFamily === 6) {
    assertAddressAllowed(hostname);
    return [{ address: hostname, family: literalFamily }];
  }

  const cacheKey = hostname.toLowerCase();
  let pinnedSetPromise = DNS_PIN_CACHE.get(cacheKey);
  if (!pinnedSetPromise) {
    pinnedSetPromise = lookupAndValidateAllAddresses(hostname);
    DNS_PIN_CACHE.set(cacheKey, pinnedSetPromise);
  }
  return awaitWithAbort(pinnedSetPromise, signal);
}

async function lookupAndValidateAllAddresses(hostname: string): Promise<readonly PinnedAddress[]> {
  const resolved = await dns.lookup(hostname, { all: true, verbatim: true });
  if (resolved.length === 0) {
    throw new Error(`DNS resolution returned no addresses for ${hostname}`);
  }
  const addresses = resolved.map(({ address, family }) => {
    if (family !== 4 && family !== 6) {
      throw new Error(`DNS returned an unsupported address family for ${hostname}`);
    }
    if (isIP(address) !== family) {
      throw new Error(`DNS returned an invalid address for ${hostname}`);
    }
    assertAddressAllowed(address);
    return { address, family } as PinnedAddress;
  });
  return Object.freeze(addresses.map((address) => Object.freeze(address)));
}

function awaitWithAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(new Error("Request aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new Error("Request aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function createPinnedLookup(pinned: PinnedAddress): LookupFunction {
  return (_hostname, options, callback) => {
    const requestedFamily = typeof options.family === "string"
      ? Number(options.family.slice(-1))
      : (options.family ?? 0);
    if (requestedFamily !== 0 && requestedFamily !== pinned.family) {
      const error = Object.assign(new Error("Pinned DNS address family mismatch"), {
        code: "EAI_ADDRFAMILY",
      }) as NodeJS.ErrnoException;
      callback(error, "", 0);
      return;
    }
    if (options.all === true) {
      callback(null, [{ address: pinned.address, family: pinned.family }]);
      return;
    }
    callback(null, pinned.address, pinned.family);
  };
}

function assertNoReadOnlyMethodOverrideTemplate(): void {
  if (isMutatingMethod(RECIPE.method)) {
    return;
  }
  const queryKeys = [
    ...RECIPE.url_query.map(([key]) => key),
    ...Object.keys(RECIPE.query),
    ...(RECIPE.query_api_key_param ? [RECIPE.query_api_key_param] : []),
  ];
  if (queryKeys.some((key) => key.toLowerCase() === "_method")) {
    throw new Error("GET/HEAD recipes must not contain a _method query parameter");
  }
  if (
    (RECIPE.body_kind === "form" || RECIPE.body_kind === "multipart") &&
    Object.keys(stringRecord(RECIPE.body_template)).some((key) => key.toLowerCase() === "_method")
  ) {
    throw new Error("GET/HEAD recipes must not contain a _method form field");
  }
}

function assertLiteralHostAllowed(url: URL): void {
  const hostname = hostnameWithoutBrackets(url.hostname);
  if (isIP(hostname) !== 0) {
    assertAddressAllowed(hostname);
  }
}

function hostnameWithoutBrackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function assertAddressAllowed(address: string): void {
  const addressKind = isIP(address);
  const classes = addressKind === 4
    ? classifyIpv4(parseIpv4Bytes(address))
    : addressKind === 6
      ? classifyIpv6(parseIpv6Bytes(address))
      : null;
  if (!classes) {
    throw new Error("DNS resolution returned an invalid IP address");
  }
  for (const blockedClass of POLICY.dns_policy.blocked_address_classes) {
    if (classes[blockedClass]) {
      throw new Error(`Request targets a blocked ${blockedClass} address`);
    }
  }
  if (classes.loopback && !POLICY.dns_policy.allow_loopback) {
    throw new Error("Request targets loopback but policy.json does not allow it");
  }
  if (classes.privateNetwork && !POLICY.dns_policy.allow_private_networks) {
    throw new Error("Request targets a private network but policy.json does not allow it");
  }
}

type AddressClasses = {
  unspecified: boolean;
  link_local: boolean;
  multicast: boolean;
  loopback: boolean;
  privateNetwork: boolean;
};

function parseIpv4Bytes(address: string): number[] | null {
  const parts = address.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const bytes = parts.map((part) => Number(part));
  return bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    ? bytes
    : null;
}

function parseIpv6Bytes(address: string): number[] | null {
  let normalized = address.toLowerCase();
  const lastColon = normalized.lastIndexOf(":");
  const ipv4Tail = lastColon >= 0 ? normalized.slice(lastColon + 1) : "";
  if (ipv4Tail.includes(".")) {
    const ipv4 = parseIpv4Bytes(ipv4Tail);
    if (!ipv4) {
      return null;
    }
    normalized = normalized.slice(0, lastColon + 1)
      + ((ipv4[0] << 8) | ipv4[1]).toString(16)
      + ":"
      + ((ipv4[2] << 8) | ipv4[3]).toString(16);
  }
  const compressed = normalized.split("::");
  if (compressed.length > 2) {
    return null;
  }
  const left = compressed[0] ? compressed[0].split(":") : [];
  const right = compressed.length === 2 && compressed[1] ? compressed[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((compressed.length === 1 && missing !== 0) || (compressed.length === 2 && missing < 1)) {
    return null;
  }
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }
  return groups.flatMap((group) => {
    const value = Number.parseInt(group, 16);
    return [value >> 8, value & 0xff];
  });
}

function classifyIpv4(address: number[] | null): AddressClasses | null {
  if (!address) {
    return null;
  }
  return {
    unspecified: address.every((byte) => byte === 0),
    link_local: address[0] === 169 && address[1] === 254,
    multicast: address[0] >= 224 && address[0] <= 239,
    loopback: address[0] === 127,
    privateNetwork:
      address[0] === 10 ||
      (address[0] === 172 && address[1] >= 16 && address[1] <= 31) ||
      (address[0] === 192 && address[1] === 168),
  };
}

function classifyIpv6(address: number[] | null): AddressClasses | null {
  if (!address) {
    return null;
  }
  const mapped = address.slice(0, 10).every((byte) => byte === 0)
    && address[10] === 0xff
    && address[11] === 0xff;
  if (mapped) {
    return classifyIpv4(address.slice(12));
  }
  return {
    unspecified: address.every((byte) => byte === 0),
    link_local: address[0] === 0xfe && (address[1] & 0xc0) === 0x80,
    multicast: address[0] === 0xff,
    loopback: address.slice(0, 15).every((byte) => byte === 0) && address[15] === 1,
    privateNetwork: (address[0] & 0xfe) === 0xfc,
  };
}

async function readBoundedBody(
  response: http.IncomingMessage,
  maxBytes: number,
): Promise<BoundedBody> {
  const decoder = new TextDecoder();
  let text = "";
  let bytesRead = 0;
  let truncated = false;
  try {
    for await (const chunk of response) {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      const remaining = maxBytes - bytesRead;
      if (value.byteLength > remaining) {
        if (remaining > 0) {
          text += decoder.decode(value.subarray(0, remaining), { stream: true });
          bytesRead += remaining;
        }
        truncated = true;
        response.destroy();
        break;
      }
      text += decoder.decode(value, { stream: true });
      bytesRead += value.byteLength;
    }
    text += decoder.decode();
  } catch (error) {
    if (!truncated) {
      throw error;
    }
  }
  return { text, truncated, bytesRead };
}

function validateResponseBody(
  bodyText: string,
  truncated: boolean,
): { schemaValid: boolean | null; validationErrors: string[] } {
  if (!validateResponse) {
    return { schemaValid: null, validationErrors: [] };
  }
  if (truncated) {
    return {
      schemaValid: null,
      validationErrors: ["Response schema validation skipped because the body was truncated"],
    };
  }
  let body: unknown;
  try {
    body = JSON.parse(bodyText) as unknown;
  } catch {
    return {
      schemaValid: false,
      validationErrors: ["Response schema expected valid JSON"],
    };
  }
  if (validateResponse(body)) {
    return { schemaValid: true, validationErrors: [] };
  }
  return {
    schemaValid: false,
    validationErrors: (validateResponse.errors ?? []).map(formatValidationError),
  };
}

function formatValidationError(error: ErrorObject): string {
  const location = error.instancePath || "/";
  return `${location} ${error.message ?? "failed response schema validation"}`;
}

function applyAuth(headers: Record<string, string>, url: URL): void {
  if (RECIPE.auth_type === "basic") {
    const username = envValue(RECIPE.basic_username_env);
    const password = envValue(RECIPE.basic_password_env);
    headers["Authorization"] = "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
  } else if (RECIPE.auth_type === "bearer") {
    headers["Authorization"] = `Bearer ${envValue(RECIPE.bearer_token_env)}`;
  } else if (RECIPE.auth_type === "header_api_key" && RECIPE.header_api_key_header) {
    headers[RECIPE.header_api_key_header] = envValue(RECIPE.header_api_key_env);
  } else if (RECIPE.auth_type === "query_api_key" && RECIPE.query_api_key_param) {
    url.searchParams.set(RECIPE.query_api_key_param, envValue(RECIPE.query_api_key_env));
  }
}

function renderTemplateValue(value: TemplateValue, args: ToolArgs): TemplateValue {
  if (typeof value === "string") {
    return fillTemplate(value, args);
  }
  if (Array.isArray(value)) {
    return value.map((item) => renderTemplateValue(item, args));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, renderTemplateValue(item, args)]),
    );
  }
  return value;
}

function fillTemplate(value: string, args: ToolArgs): string {
  return value.replace(/\$\{([^}]+)\}/g, (_match, name) =>
    templateValue(String(name), args));
}

function envValue(name: string | null | undefined): string {
  if (!name) {
    throw new Error("Missing environment variable name in generated recipe");
  }
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function stringRecord(value: TemplateValue): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, item == null ? "" : String(item)]),
  );
}

function renderMultipartBody(fields: Record<string, string>): { boundary: string; body: string } {
  const boundary = `firstcall-${randomBytes(16).toString("hex")}`;
  const parts: string[] = [];
  for (const [key, value] of Object.entries(fields)) {
    if (/[\\r\\n]/.test(key)) {
      throw new Error("Multipart field names must not contain line breaks");
    }
    const escapedKey = key.replace(/\\/g, "\\\\").replace(/"/g, "%22");
    parts.push(
      `--${boundary}\r\nContent-Disposition: form-data; name="${escapedKey}"\r\n\r\n${value}\r\n`,
    );
  }
  parts.push(`--${boundary}--\r\n`);
  return { boundary, body: parts.join("") };
}

function redactResponsePreview(bodyText: string): string {
  try {
    const parsed = JSON.parse(bodyText) as unknown;
    return JSON.stringify(redactSensitiveValue(parsed)).slice(0, 4000);
  } catch {
    return redactSensitiveText(bodyText).slice(0, 4000);
  }
}

function redactSensitiveValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveValue(item));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      output[key] = isSensitiveResponseKey(key) ? "<redacted>" : redactSensitiveValue(item);
    }
    return output;
  }
  return value;
}

function isSensitiveResponseKey(key: string): boolean {
  const lower = key.toLowerCase();
  return (
    lower === "token" ||
    lower === "access_token" ||
    lower === "refresh_token" ||
    lower === "secret" ||
    lower === "password" ||
    lower === "api_key" ||
    lower === "authorization" ||
    lower === "x-api-key" ||
    lower.endsWith("_token") ||
    lower.endsWith("_secret") ||
    lower.endsWith("_password")
  );
}

function redactSensitiveText(text: string): string {
  return text
    .replace(
      /\b(token|access_token|refresh_token|secret|password|api_key|authorization|x-api-key)\b\s*[:=]\s*["']?[^&\s,"'}]+/gi,
      "$1=<redacted>",
    )
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, "Bearer <redacted>");
}

function setDefaultHeader(headers: Record<string, string>, name: string, value: string): void {
  const lower = name.toLowerCase();
  const hasHeader = Object.keys(headers).some((key) => key.toLowerCase() === lower);
  if (!hasHeader) {
    headers[name] = value;
  }
}

const transport = new StdioServerTransport();
await server.connect(transport);
"#;
