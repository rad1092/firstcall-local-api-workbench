use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::model::{AuthStyle, Recipe};

use super::agent_common::{
    PRODUCT_LABEL, TAGLINE, all_env_requirements, auth_type, body_kind, body_template_value,
    destructive_method, export_slots, looks_destructive_path, non_auth_headers_map,
    non_auth_query_map, parse_url_template, recipe_slug, sanitize_url_template_for_agent,
};

#[derive(Serialize)]
struct McpRecipeTemplate {
    name: String,
    description: String,
    method: String,
    url_template: String,
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
    fs::write(server_dir.join("tsconfig.json"), tsconfig_json())?;
    fs::write(src_dir.join("server.ts"), server_ts(recipe)?)?;
    fs::write(server_dir.join("README.md"), readme_md(recipe))?;
    Ok(())
}

fn package_json(recipe: &Recipe) -> Result<String> {
    let package = serde_json::json!({
        "name": format!("{}-mcp-server", recipe_slug(&recipe.name)),
        "version": env!("CARGO_PKG_VERSION"),
        "private": true,
        "type": "module",
        "scripts": {
            "build": "tsc",
            "start": "node dist/server.js"
        },
        "dependencies": {
            "@modelcontextprotocol/sdk": "^1.0.0",
            "zod": "^3.23.8"
        },
        "devDependencies": {
            "@types/node": "^20.0.0",
            "typescript": "^5.6.0"
        }
    });
    serde_json::to_string_pretty(&package).map_err(anyhow::Error::from)
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
    let recipe_template = McpRecipeTemplate {
        name: recipe_slug(&recipe.name),
        description: TAGLINE.to_string(),
        method: recipe.method.to_ascii_uppercase(),
        url_template: sanitize_url_template_for_agent(&recipe.url_template),
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
    if slots.is_empty() {
        return "{}".to_string();
    }
    let fields = slots
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
        .collect::<Vec<_>>()
        .join(",\n");
    format!("{{\n{fields}\n}}")
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
    format!(
        "# {} MCP Server\n\nGenerated by {PRODUCT_LABEL}.\n\n{TAGLINE}\n\nThis is a template TypeScript MCP server for the verified recipe `{}`.\n\n## Quickstart\n\n```bash\nnpm install\nnpm run build\nnpm start\n```\n\n## Tool\n\n- Name: `{}`\n- Method: `{}`\n- URL: `{}`\n\n## Required environment variables\n\n{}\n\n## Files\n\n- `package.json`\n- `tsconfig.json`\n- `src/server.ts`\n\n## Notes\n\n- Secrets must come from environment variables only.\n- Do not commit raw secrets.\n- The tool returns text content plus structuredContent with `status`, `ok`, and redacted `body_preview`.\n- Tool annotations are advisory hints only; policy and local verification remain the guardrails.\n- `firstcall-cli validate-package` is static by design. For runtime confidence, run `npm install`, `npm run build`, and call the generated tool with an MCP stdio client.\n",
        recipe.name,
        recipe.name,
        recipe_slug(&recipe.name),
        recipe.method.to_ascii_uppercase(),
        sanitize_url_template_for_agent(&recipe.url_template),
        env_text
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

const SERVER_TS_TEMPLATE: &str = r#"import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type ToolArgs = Record<string, string | undefined>;
type TemplateValue = string | number | boolean | null | TemplateValue[] | { [key: string]: TemplateValue };
type ToolOutput = {
  status: number;
  ok: boolean;
  body_preview: string;
};

const RECIPE = __RECIPE_JSON__;
const TOOL_NAME = __TOOL_NAME__;
const TOOL_DESCRIPTION = __TOOL_DESCRIPTION__;
const TOOL_ANNOTATIONS = __TOOL_ANNOTATIONS__;

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
});

server.registerTool(TOOL_NAME, {
  title: TOOL_NAME,
  description: TOOL_DESCRIPTION,
  inputSchema,
  outputSchema,
  annotations: TOOL_ANNOTATIONS,
}, async (args) => {
  const toolArgs = args as ToolArgs;
  const url = new URL(fillTemplate(RECIPE.url_template, toolArgs));
  for (const [key, value] of Object.entries(RECIPE.query)) {
    url.searchParams.append(key, fillTemplate(String(value), toolArgs));
  }

  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(RECIPE.headers)) {
    headers[key] = fillTemplate(String(value), toolArgs);
  }
  applyAuth(headers, url);

  const init: RequestInit = {
    method: RECIPE.method,
    headers,
  };

  if (RECIPE.body_kind !== "none") {
    const renderedBody = renderTemplateValue(RECIPE.body_template, toolArgs);
    if (RECIPE.body_kind === "text") {
      init.body = String(renderedBody);
    } else if (RECIPE.body_kind === "form") {
      init.body = new URLSearchParams(stringRecord(renderedBody)).toString();
      setDefaultHeader(headers, "Content-Type", "application/x-www-form-urlencoded");
    } else if (RECIPE.body_kind === "multipart") {
      const form = new FormData();
      for (const [key, value] of Object.entries(stringRecord(renderedBody))) {
        form.append(key, value);
      }
      init.body = form;
    } else {
      init.body = JSON.stringify(renderedBody);
      setDefaultHeader(headers, "Content-Type", "application/json");
    }
  }

  const response = await fetch(url, init);
  const bodyText = await response.text();
  const redactedBodyPreview = redactResponsePreview(bodyText);
  const structuredContent: ToolOutput = {
    status: response.status,
    ok: response.ok,
    body_preview: redactedBodyPreview,
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
});

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
  return value.replace(/\$\{([^}]+)\}/g, (_match, name) => {
    if (Object.prototype.hasOwnProperty.call(args, name)) {
      return String(args[name]);
    }
    const fromEnv = process.env[name];
    if (fromEnv) {
      return fromEnv;
    }
    throw new Error(`Missing required value: ${name}`);
  });
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
