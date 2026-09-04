//! Native MCP stdio server (2026-07-28, with 2025 handshake compatibility).
//! No generated code, subprocess, or package install.
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::exec::client::bounded::execute_request_bounded;
use crate::exec::redact::{REDACTED, is_secret_key, redact_free_text};
use crate::export::package_import::recipe_from_agent_package_dir;
use crate::export::package_inspect::inspect_agent_package_dir;
use crate::model::{AuthStyle, BodyTemplate, Recipe, RuntimeSlot, SlotLocation};
use crate::util::{extract_slot_names, replace_slots};
use crate::verify::prepare_draft_for_verify_with_env;

pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_RESPONSE_BYTES: usize = 262_144;
const MAX_OUTPUT_BYTES: usize = 1_048_576;
const MAX_PACKAGE_FILE_BYTES: u64 = 1_048_576;
const PROTOCOL_VERSION: &str = "2025-11-25";
const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";

#[derive(Clone, Copy, Default)]
pub struct ServeOptions {
    pub allow_mutating: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDefinition {
    schema_version: u8,
    name: String,
    title: String,
    description: String,
    input_schema: Value,
}

struct PackageTool {
    recipe: Recipe,
    definition: ToolDefinition,
    validator: jsonschema::Validator,
    origin: String,
    response_secret_keys: BTreeSet<String>,
    client: Client,
    last_request_at: RefCell<Option<Instant>>,
}

pub fn serve_stdio(package: &Path, options: ServeOptions) -> Result<()> {
    let tool = PackageTool::load(package, options)?;
    serve(tool, io::stdin().lock(), io::stdout().lock())
}

impl PackageTool {
    fn load(path: &Path, options: ServeOptions) -> Result<Self> {
        bound_package_files(path)?;
        let report = inspect_agent_package_dir(path);
        if !report.is_ready() {
            // Validation details can contain package-controlled text. Never echo it to MCP.
            bail!(
                "Invalid tool package; run firstcall-cli validate-package --dir PATH for details"
            );
        }
        let recipe = recipe_from_agent_package_dir(path).context("Cannot load package recipe")?;
        let method = recipe.method.as_str();
        if !matches!(method, "GET" | "HEAD") && !options.allow_mutating {
            bail!(
                "This package requires --allow-mutating; only GET and HEAD are enabled by default"
            );
        }
        let origin = validate_recipe_boundary(&recipe)?;
        let policy: Value = serde_json::from_slice(&fs::read(path.join("policy.json"))?)?;
        let sample_url = representative_url(&recipe)?;
        if policy["allowed_methods"] != json!([method])
            || policy["allowed_hosts"] != json!([sample_url.host_str().unwrap_or_default()])
            || policy["allowed_paths"] != json!([sample_url.path()])
        {
            bail!("Package policy must authorize exactly its recipe method, host, and path");
        }
        let blocked = policy["blocked_headers"]
            .as_array()
            .context("Invalid blocked_headers policy")?;
        if request_header_names(&recipe).iter().any(|header| {
            blocked.iter().any(|item| {
                item.as_str()
                    .is_some_and(|key| key.eq_ignore_ascii_case(header))
            })
        }) {
            bail!("Recipe contains a header forbidden by its policy");
        }
        let response_secret_keys = policy["redact_response_keys"]
            .as_array()
            .context("Invalid response redaction policy")?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_ascii_lowercase)
            .collect();
        let definition = if path.join("tool.json").exists() {
            serde_json::from_slice(&fs::read(path.join("tool.json"))?)
                .context("Invalid tool.json")?
        } else {
            default_definition(&recipe)
        };
        validate_definition(&recipe, &definition)?;
        let validator = jsonschema::validator_for(&definition.input_schema)
            .map_err(|_| anyhow::anyhow!("Invalid tool input schema"))?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Cannot create HTTP client")?;
        Ok(Self {
            recipe,
            definition,
            validator,
            origin,
            response_secret_keys,
            client,
            last_request_at: RefCell::new(None),
        })
    }

    fn descriptor(&self) -> Value {
        let read_only = matches!(self.recipe.method.as_str(), "GET" | "HEAD");
        json!({
            "name": self.definition.name, "title": self.definition.title,
            "description": self.definition.description, "inputSchema": self.definition.input_schema,
            "annotations": {"readOnlyHint": read_only, "destructiveHint": !read_only,
                "idempotentHint": read_only, "openWorldHint": true}
        })
    }

    fn call(&self, arguments: &Map<String, Value>) -> Value {
        if !self.validator.is_valid(&Value::Object(arguments.clone())) {
            return tool_error(
                "invalid_arguments",
                "Arguments do not match the declared tool schema. Check required fields, types, and allowed values.",
            );
        }
        let secrets = RefCell::new(Vec::<String>::new());
        match self.execute(arguments, &secrets) {
            Ok(result) => result,
            Err(error) => {
                let message = redact_text(&error.to_string(), &secrets.borrow());
                tool_error("request_failed", &message)
            }
        }
    }

    fn execute(
        &self,
        arguments: &Map<String, Value>,
        secrets: &RefCell<Vec<String>>,
    ) -> Result<Value> {
        let mut recipe = self.recipe.clone();
        for slot in &mut recipe.slots {
            if !safe_slot(&self.recipe, slot) {
                slot.current_value = None;
                continue;
            }
            slot.current_value = arguments.get(&slot.name).map(primitive_text).transpose()?;
            if let Some(value) = slot.current_value.as_mut() {
                if value.len() > 8192 || value.trim().is_empty() {
                    bail!("Arguments must contain a nonempty value of at most 8192 bytes");
                }
                if slot.location == SlotLocation::Path {
                    *value = encode_path_segment(value)?;
                } else if slot.location == SlotLocation::Body
                    && matches!(recipe.body_template, BodyTemplate::Json { .. })
                {
                    // Shared execution substitutes into JSON string templates. Escape the
                    // string content so values cannot add keys or change the JSON structure.
                    let quoted = serde_json::to_string(value)?;
                    *value = quoted[1..quoted.len() - 1].to_string();
                } else if slot.location == SlotLocation::Header
                    && value.chars().any(char::is_control)
                {
                    bail!("Header arguments cannot contain control characters");
                }
            }
        }
        // Absent optional query/header fields are omitted rather than substituted with a
        // hidden environment value. Required path/body slots are checked during preparation.
        let missing: BTreeSet<_> = recipe
            .slots
            .iter()
            .filter(|slot| safe_slot(&self.recipe, slot) && slot.current_value.is_none())
            .map(|slot| slot.name.clone())
            .collect();
        recipe.query_template.retain(|field| {
            !extract_slot_names(&field.value)
                .iter()
                .any(|name| missing.contains(name))
        });
        recipe.headers_template.retain(|field| {
            !extract_slot_names(&field.value)
                .iter()
                .any(|name| missing.contains(name))
        });
        let draft = prepare_draft_for_verify_with_env(&recipe, |name| {
            // Public arguments only come from tools/call, including optional arguments.
            if recipe.slots.iter().any(|slot| safe_slot(&self.recipe, slot)
                && crate::verify::slot_env_name(&slot.name) == name) { return None; }
            let value = std::env::var(name).ok().filter(|value| !value.trim().is_empty());
            if let Some(value) = &value { secrets.borrow_mut().push(value.clone()); }
            value
        }).map_err(|_| anyhow::anyhow!("Missing declared argument or required environment credential; check tool inputs and client environment settings"))?;
        // Include derived Basic credentials as exact redaction values too.
        if let AuthStyle::Basic {
            username_slot,
            password_slot,
        } = &draft.auth
        {
            let username = draft
                .slots
                .iter()
                .find(|slot| &slot.name == username_slot)
                .and_then(|slot| slot.current_value.as_deref());
            let password = draft
                .slots
                .iter()
                .find(|slot| &slot.name == password_slot)
                .and_then(|slot| slot.current_value.as_deref());
            if let (Some(username), Some(password)) = (username, password) {
                secrets.borrow_mut().push(
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{username}:{password}")),
                );
            }
        }
        let values: HashMap<_, _> = draft
            .slots
            .iter()
            .filter_map(|slot| {
                slot.current_value
                    .clone()
                    .map(|value| (slot.name.clone(), value))
            })
            .collect();
        let (path, missing) = replace_slots(&draft.path, &values);
        if !missing.is_empty() {
            bail!("A required path argument is missing");
        }
        let expected = url::Url::parse(&format!("{}{}", self.origin, path))?;
        if expected.path() != path {
            bail!("Path arguments cannot change endpoint structure");
        }
        if self
            .last_request_at
            .borrow()
            .is_some_and(|last| last.elapsed() < Duration::from_millis(100))
        {
            bail!("Request rate limit reached; wait at least 100 milliseconds before retrying");
        }
        self.last_request_at.replace(Some(Instant::now()));
        let response = execute_request_bounded(
            &draft,
            &self.client,
            &self.origin,
            &path,
            MAX_RESPONSE_BYTES,
        )?;
        let data = if response.body.is_empty() {
            Value::Null
        } else if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
            redact_value(value, &secrets.borrow(), &self.response_secret_keys)
        } else if response.content_type.to_ascii_lowercase().contains("json") {
            bail!("API returned invalid JSON; no partial or repaired JSON is returned");
        } else {
            let text = String::from_utf8(response.body)
                .context("API returned unsupported binary content")?;
            Value::String(redact_text(&text, &secrets.borrow()))
        };
        let structured = json!({"status": response.status,
            "content_type": redact_text(&response.content_type, &secrets.borrow()),
            "data": data, "truncated": false});
        let text = serde_json::to_string(&structured)?;
        let result = json!({"content": [{"type":"text", "text":text}],
            "structuredContent":structured, "isError": !(200..300).contains(&response.status)});
        if serde_json::to_vec(&result)?.len() > MAX_OUTPUT_BYTES {
            bail!("Response too large after JSON encoding; no partial response returned");
        }
        Ok(result)
    }
}

fn serve(tool: PackageTool, mut input: impl BufRead, mut output: impl Write) -> Result<()> {
    let mut initialized = false;
    let mut ready = false;
    loop {
        let mut line = Vec::new();
        let read = (&mut input)
            .take(MAX_INPUT_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > MAX_INPUT_BYTES {
            write_message(
                &mut output,
                &rpc_error(Value::Null, -32700, "Message exceeds 65536 byte limit"),
            )?;
            return Ok(());
        }
        let request: Value = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(_) => {
                write_message(&mut output, &rpc_error(Value::Null, -32700, "Invalid JSON"))?;
                continue;
            }
        };
        let Some(object) = request.as_object() else {
            write_message(
                &mut output,
                &rpc_error(Value::Null, -32600, "Expected a JSON-RPC request object"),
            )?;
            continue;
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str);
        if object.get("jsonrpc") != Some(&json!("2.0"))
            || method.is_none()
            || id
                .as_ref()
                .is_some_and(|id| !id.is_string() && !id.is_i64() && !id.is_u64())
            || object
                .get("params")
                .is_some_and(|params| !params.is_object())
        {
            write_message(
                &mut output,
                &rpc_error(Value::Null, -32600, "Invalid JSON-RPC request"),
            )?;
            continue;
        }
        let method = method.unwrap_or_default();
        let Some(id) = id else {
            // Notifications have no response. Unknown notifications are safe to ignore.
            if method == "notifications/initialized" && initialized {
                ready = true;
            }
            continue;
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        // Current MCP is stateless. Legacy clients select the earlier handshake
        // behavior with initialize; modern requests carry their own metadata.
        if method == "server/discover"
            || params["_meta"]
                .get("io.modelcontextprotocol/protocolVersion")
                .is_some()
            || params["_meta"]
                .get("io.modelcontextprotocol/clientCapabilities")
                .is_some()
        {
            write_message(&mut output, &modern_request(&tool, id, method, &params))?;
            continue;
        }
        let result = match method {
            "initialize" if !initialized => {
                if !params["protocolVersion"].is_string()
                    || !params["capabilities"].is_object()
                    || !params["clientInfo"]["name"].is_string()
                    || !params["clientInfo"]["version"].is_string()
                {
                    rpc_error(
                        id,
                        -32602,
                        "initialize requires protocolVersion, capabilities, and clientInfo",
                    )
                } else {
                    initialized = true;
                    let requested = params["protocolVersion"].as_str().unwrap_or_default();
                    let version = match requested {
                        "2025-03-26" | "2025-06-18" | "2025-11-25" => requested,
                        _ => PROTOCOL_VERSION,
                    };
                    rpc_result(
                        id,
                        json!({"protocolVersion":version, "capabilities":{"tools":{"listChanged":false}},
                        "serverInfo":{"name":"firstcall", "title":"FirstCall", "version":env!("CARGO_PKG_VERSION")},
                        "instructions":"Calls only the endpoint declared by this package. Credentials come from the server process environment. Responses are redacted and limited to 262144 bytes."}),
                    )
                }
            }
            "initialize" => rpc_error(id, -32600, "Already initialized"),
            "ping" => rpc_result(id, json!({})),
            _ if !ready => rpc_error(
                id,
                -32002,
                "Initialize and send notifications/initialized before using tools",
            ),
            "tools/list" => {
                if params.get("cursor").is_some() {
                    rpc_error(
                        id,
                        -32602,
                        "This server has one tool and no pagination cursor",
                    )
                } else {
                    rpc_result(id, json!({"tools":[tool.descriptor()]}))
                }
            }
            "tools/call" => {
                if params["name"].as_str() != Some(&tool.definition.name) {
                    rpc_error(id, -32602, "Unknown tool name")
                } else {
                    match params.get("arguments") {
                        Some(Value::Object(arguments)) => rpc_result(id, tool.call(arguments)),
                        None => rpc_result(id, tool.call(&Map::new())),
                        _ => rpc_error(id, -32602, "Tool arguments must be an object"),
                    }
                }
            }
            _ => rpc_error(id, -32601, "Method not found"),
        };
        write_message(&mut output, &result)?;
    }
}

fn modern_request(tool: &PackageTool, id: Value, method: &str, params: &Value) -> Value {
    let meta = &params["_meta"];
    let Some(version) = meta["io.modelcontextprotocol/protocolVersion"].as_str() else {
        return rpc_error(
            id,
            -32602,
            "Request metadata must declare io.modelcontextprotocol/protocolVersion",
        );
    };
    if !meta["io.modelcontextprotocol/clientCapabilities"].is_object() {
        return rpc_error(
            id,
            -32602,
            "Request metadata must declare io.modelcontextprotocol/clientCapabilities",
        );
    }
    if let Some(info) = meta.get("io.modelcontextprotocol/clientInfo")
        && (!info["name"].is_string() || !info["version"].is_string())
    {
        return rpc_error(
            id,
            -32602,
            "Client identity must contain a name and version",
        );
    }
    if version != CURRENT_PROTOCOL_VERSION {
        return json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32022,
            "message":"Unsupported protocol version", "data":{"supported":[CURRENT_PROTOCOL_VERSION],"requested":version}}});
    }
    let mut response = match method {
        "server/discover" => rpc_result(
            id,
            json!({"supportedVersions":[CURRENT_PROTOCOL_VERSION],
            "capabilities":{"tools":{"listChanged":false}},"ttlMs":300000,"cacheScope":"private",
            "instructions":"Call the package's declared tool. Credentials come from the process environment; API responses are redacted and limited to 262144 bytes."}),
        ),
        "tools/list" if params.get("cursor").is_none() => rpc_result(
            id,
            json!({
            "tools":[tool.descriptor()],"ttlMs":300000,"cacheScope":"private"}),
        ),
        "tools/list" => rpc_error(
            id,
            -32602,
            "This server has one tool and no pagination cursor",
        ),
        "tools/call" if params["name"].as_str() == Some(&tool.definition.name) => {
            match params.get("arguments") {
                Some(Value::Object(arguments)) => rpc_result(id, tool.call(arguments)),
                None => rpc_result(id, tool.call(&Map::new())),
                _ => rpc_error(id, -32602, "Tool arguments must be an object"),
            }
        }
        "tools/call" => rpc_error(id, -32602, "Unknown tool name"),
        _ => rpc_error(id, -32601, "Method not found in protocol 2026-07-28"),
    };
    if let Some(result) = response.get_mut("result") {
        result["resultType"] = json!("complete");
        result["_meta"] = json!({"io.modelcontextprotocol/serverInfo":{
            "name":"firstcall", "title":"FirstCall", "version":env!("CARGO_PKG_VERSION")}});
    }
    response
}

fn write_message(output: &mut impl Write, message: &Value) -> Result<()> {
    serde_json::to_writer(&mut *output, message)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "result":result})
}
fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}})
}
fn tool_error(code: &str, message: &str) -> Value {
    let error = json!({"error":{"code":code,"message":message}, "truncated":false});
    json!({"isError":true, "content":[{"type":"text","text":error.to_string()}], "structuredContent":error})
}

fn bound_package_files(root: &Path) -> Result<()> {
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        bail!("Package cannot be a symlink");
    }
    for relative in [
        "package.manifest.json",
        "recipe.yaml",
        "verified.lock.json",
        "policy.json",
        "tool.json",
        "client-config.json",
        "README.md",
        "skill.md",
        "mcp-server/package.json",
        "mcp-server/tsconfig.json",
        "mcp-server/src/server.ts",
        "mcp-server/README.md",
    ] {
        let path = root.join(relative);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (!metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > MAX_PACKAGE_FILE_BYTES)
        {
            bail!("Package contains an oversized or unsupported file");
        }
    }
    for relative in ["mcp-server", "mcp-server/src"] {
        if let Ok(metadata) = fs::symlink_metadata(root.join(relative))
            && (!metadata.is_dir() || metadata.file_type().is_symlink())
        {
            bail!("Package contains an unsupported directory");
        }
    }
    Ok(())
}

fn auth_slot_names(recipe: &Recipe) -> Vec<&str> {
    match &recipe.auth_style {
        AuthStyle::None => vec![],
        AuthStyle::Bearer { token_slot, .. } => vec![token_slot],
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => vec![username_slot, password_slot],
        AuthStyle::HeaderApiKey { slot_name, .. } | AuthStyle::QueryApiKey { slot_name, .. } => {
            vec![slot_name]
        }
    }
}

fn request_header_names(recipe: &Recipe) -> Vec<&str> {
    let mut names: Vec<_> = recipe
        .headers_template
        .iter()
        .map(|header| header.key.as_str())
        .collect();
    match &recipe.auth_style {
        AuthStyle::Bearer { header_name, .. } | AuthStyle::HeaderApiKey { header_name, .. } => {
            names.push(header_name)
        }
        AuthStyle::Basic { .. } => names.push("Authorization"),
        _ => (),
    }
    names
}

fn safe_slot(recipe: &Recipe, slot: &RuntimeSlot) -> bool {
    slot.location != SlotLocation::Auth
        && !is_secret_key(&slot.name)
        && !slot.name.starts_with("FIRSTCALL_")
        && !auth_slot_names(recipe).contains(&slot.name.as_str())
        && !recipe.headers_template.iter().any(|header| {
            is_secret_key(&header.key) && extract_slot_names(&header.value).contains(&slot.name)
        })
        && !recipe.query_template.iter().any(|field| {
            is_secret_key(&field.key) && extract_slot_names(&field.value).contains(&slot.name)
        })
}

fn representative_url(recipe: &Recipe) -> Result<url::Url> {
    let values: HashMap<_, _> = extract_slot_names(&recipe.url_template)
        .into_iter()
        .map(|name| (name, "slot".to_string()))
        .collect();
    let (template, _) = replace_slots(&recipe.url_template, &values);
    // Exported credentials occur in the query and have no bearing on the endpoint path.
    let template = regex::Regex::new(r"\$\{[^}]+\}")?.replace_all(&template, "slot");
    url::Url::parse(&template).context("Recipe URL must be absolute")
}

pub(crate) fn validate_recipe_boundary(recipe: &Recipe) -> Result<String> {
    if !matches!(
        recipe.method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        bail!("Unsupported HTTP method in tool package");
    }
    let url = representative_url(recipe)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!(
            "Recipe must declare an HTTP(S) endpoint without credentials or fragments in its URL"
        );
    }
    let authority_start = recipe
        .url_template
        .find("://")
        .context("Invalid recipe URL")?
        + 3;
    let authority_end = recipe.url_template[authority_start..]
        .find(['/', '?'])
        .map(|index| index + authority_start)
        .unwrap_or(recipe.url_template.len());
    if !extract_slot_names(&recipe.url_template[..authority_end]).is_empty()
        || recipe.url_template[..authority_end].contains("${")
    {
        bail!("Runtime slots cannot change the endpoint host");
    }
    let mut names = BTreeSet::new();
    for slot in &recipe.slots {
        if slot.name.is_empty() || !names.insert(&slot.name) {
            bail!("Package slot names must be unique");
        }
    }
    let rest = &recipe.url_template[authority_end..];
    let path = rest.split('?').next().unwrap_or_default();
    check_slot_locations(recipe, path, SlotLocation::Path)?;
    if let Some((_, query)) = rest.split_once('?') {
        check_slot_locations(recipe, query, SlotLocation::Query)?;
    }
    for name in request_header_names(recipe) {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection"
        ) {
            bail!("Recipe cannot override HTTP routing or framing headers");
        }
    }
    for header in &recipe.headers_template {
        check_slot_locations(recipe, &header.value, SlotLocation::Header)?;
    }
    for field in &recipe.query_template {
        check_slot_locations(recipe, &field.value, SlotLocation::Query)?;
    }
    match &recipe.body_template {
        BodyTemplate::None => (),
        BodyTemplate::Json { template } => {
            check_slot_locations(recipe, template, SlotLocation::Body)?
        }
        BodyTemplate::Text { text } => check_slot_locations(recipe, text, SlotLocation::Body)?,
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            for field in fields {
                check_slot_locations(recipe, &field.value, SlotLocation::Body)?;
            }
        }
    }
    Ok(url.origin().ascii_serialization())
}

fn check_slot_locations(recipe: &Recipe, template: &str, location: SlotLocation) -> Result<()> {
    for name in extract_slot_names(template) {
        let slot = recipe
            .slots
            .iter()
            .find(|slot| slot.name == name)
            .context("Undeclared parameter slot in recipe")?;
        if safe_slot(recipe, slot) && slot.location != location {
            bail!("A parameter slot is used outside its declared location");
        }
    }
    Ok(())
}

fn default_definition(recipe: &Recipe) -> ToolDefinition {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for slot in recipe.slots.iter().filter(|slot| safe_slot(recipe, slot)) {
        properties.insert(
            slot.name.clone(),
            json!({"type":"string", "description":slot.description, "maxLength":8192}),
        );
        if slot.required {
            required.push(slot.name.clone());
        }
    }
    let name: String = recipe
        .name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    ToolDefinition {
        schema_version: 1,
        name: if name.is_empty() {
            "firstcall_recipe".into()
        } else {
            name
        },
        title: recipe.name.clone(),
        description: format!(
            "Execute {} against its verified {} endpoint and return redacted API response data.",
            recipe.name, recipe.method
        ),
        input_schema: json!({"type":"object", "properties":properties,"required":required,"additionalProperties":false}),
    }
}

fn validate_definition(recipe: &Recipe, definition: &ToolDefinition) -> Result<()> {
    if definition.schema_version != 1
        || definition.name.is_empty()
        || definition.name.len() > 128
        || !definition
            .name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
        || definition.title.trim().is_empty()
        || definition.title.len() > 256
        || definition.description.trim().is_empty()
        || definition.description.len() > 4096
    {
        bail!("Invalid tool name, title, or description");
    }
    let schema = &definition.input_schema;
    if serde_json::to_vec(schema)?.len() > 32_768
        || schema["type"] != "object"
        || schema["additionalProperties"] != false
    {
        bail!("Tool schema must be a bounded object with additionalProperties false");
    }
    reject_schema_references(schema)?;
    let properties = schema["properties"]
        .as_object()
        .context("Tool schema requires properties")?;
    let expected: BTreeSet<_> = recipe
        .slots
        .iter()
        .filter(|slot| safe_slot(recipe, slot))
        .map(|slot| slot.name.as_str())
        .collect();
    if properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        bail!("Tool schema properties must exactly match the recipe's public parameter slots");
    }
    for property in properties.values() {
        if !matches!(
            property["type"].as_str(),
            Some("string" | "integer" | "number" | "boolean")
        ) {
            bail!("Tool parameters must be strings, numbers, integers, or booleans");
        }
    }
    let required = schema["required"]
        .as_array()
        .context("Tool schema requires a required array")?;
    let required: BTreeSet<_> = required.iter().filter_map(Value::as_str).collect();
    let expected_required: BTreeSet<_> = recipe
        .slots
        .iter()
        .filter(|slot| slot.required && safe_slot(recipe, slot))
        .map(|slot| slot.name.as_str())
        .collect();
    if required != expected_required {
        bail!("Tool schema required fields must match the recipe");
    }
    Ok(())
}

fn reject_schema_references(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "$ref" | "$dynamicRef" | "$id" | "$schema") {
                    bail!("Tool schema references and external schemas are not supported");
                }
                reject_schema_references(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_schema_references(item)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn primitive_text(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(_) | Value::Bool(_) => Ok(value.to_string()),
        _ => bail!("Only primitive parameter values are supported"),
    }
}

fn encode_path_segment(value: &str) -> Result<String> {
    if matches!(value, "." | "..")
        || value
            .chars()
            .any(|character| character.is_control() || "/\\?#%".contains(character))
    {
        bail!("Path arguments must be single segments without traversal or URL delimiters");
    }
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(encoded)
}

fn redact_text(text: &str, secrets: &[String]) -> String {
    let mut result = text.to_string();
    let mut values = secrets.to_vec();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for value in values.iter().filter(|value| !value.is_empty()) {
        result = result.replace(value, REDACTED);
        let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
        result = result.replace(&encoded, REDACTED);
    }
    redact_free_text(&result)
}

fn redact_value(value: Value, secrets: &[String], keys: &BTreeSet<String>) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let redacted =
                        if is_secret_key(&key) || keys.contains(&key.to_ascii_lowercase()) {
                            Value::String(REDACTED.into())
                        } else {
                            redact_value(value, secrets, keys)
                        };
                    (redact_text(&key, secrets), redacted)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| redact_value(item, secrets, keys))
                .collect(),
        ),
        Value::String(value) => Value::String(redact_text(&value, secrets)),
        other if secrets.iter().any(|secret| secret == &other.to_string()) => {
            Value::String(REDACTED.into())
        }
        other => other,
    }
}
