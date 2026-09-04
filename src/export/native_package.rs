//! A ready-to-connect MCP package. Export is independent of desktop state and
//! never starts a process, contacts an API, or copies credential values.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::exec::redact::{is_secret_key, redact_free_text};
use crate::model::{AuthStyle, Recipe, RuntimeSlot, SlotLocation};
use crate::util::extract_slot_names;

use super::agent_common::{all_env_requirements, recipe_slug};
use super::agent_package::is_agent_export_eligible;
use super::agent_yaml::recipe_to_agent_yaml;
use super::package_inspect::inspect_agent_package_dir;
use super::package_manifest::write_native_package_manifest;
use super::policy::recipe_to_policy_json;
use super::verified_lock::recipe_to_verified_lock_json;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeToolDefinition {
    pub schema_version: u8,
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Clone, Debug)]
pub struct NativePackageExport {
    pub directory: PathBuf,
    pub client_config: String,
    pub required_environment: Vec<String>,
    pub tool_name: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeExportOptions {
    pub allow_mutating: bool,
}

pub fn is_mutating_recipe(recipe: &Recipe) -> bool {
    !matches!(recipe.method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
}

pub fn tool_input_slots(recipe: &Recipe) -> impl Iterator<Item = &RuntimeSlot> {
    let auth_names = match &recipe.auth_style {
        AuthStyle::None => vec![],
        AuthStyle::Bearer { token_slot, .. } => vec![token_slot.as_str()],
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => vec![username_slot.as_str(), password_slot.as_str()],
        AuthStyle::HeaderApiKey { slot_name, .. } | AuthStyle::QueryApiKey { slot_name, .. } => {
            vec![slot_name.as_str()]
        }
    };
    recipe.slots.iter().filter(move |slot| {
        slot.location != SlotLocation::Auth
            && !is_secret_key(&slot.name)
            && !slot.name.starts_with("FIRSTCALL_")
            && !auth_names.contains(&slot.name.as_str())
            && !recipe.headers_template.iter().any(|header| {
                is_secret_key(&header.key) && extract_slot_names(&header.value).contains(&slot.name)
            })
            && !recipe.query_template.iter().any(|field| {
                is_secret_key(&field.key) && extract_slot_names(&field.value).contains(&slot.name)
            })
    })
}

pub fn default_tool_definition(recipe: &Recipe) -> NativeToolDefinition {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for slot in tool_input_slots(recipe) {
        properties.insert(
            slot.name.clone(),
            json!({
                "type": "string",
                "description": if slot.description.trim().is_empty() {
                    format!("{} used in the request {}", slot.name, slot.location.label())
                } else { redact_free_text(&slot.description) },
            }),
        );
        if slot.required {
            required.push(slot.name.clone());
        }
    }
    NativeToolDefinition {
        schema_version: 1,
        name: recipe_slug(&recipe.name),
        title: redact_free_text(&recipe.name),
        // A meaningful purpose must be written before export, rather than
        // giving every tool a shared marketing tagline.
        description: String::new(),
        input_schema: json!({
            "type": "object", "properties": properties,
            "required": required, "additionalProperties": false,
        }),
    }
}

pub fn validate_tool_definition(recipe: &Recipe, tool: &NativeToolDefinition) -> Result<()> {
    if tool.schema_version != 1 {
        bail!("Tool definition schema_version must be 1");
    }
    if tool.name.is_empty()
        || tool.name.len() > 64
        || !tool
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        bail!("Use 1–64 letters, numbers, underscores, or hyphens for the tool name");
    }
    if tool.title.trim().is_empty() || tool.title.len() > 120 {
        bail!("Give the tool a readable title of up to 120 characters");
    }
    if tool.description.trim().len() < 12 || tool.description.len() > 2000 {
        bail!("Describe when to use this tool and what it returns (12–2,000 characters)");
    }
    for text in [&tool.title, &tool.description] {
        if redact_free_text(text) != *text {
            bail!("Remove credential values from the tool description");
        }
    }
    let schema = tool
        .input_schema
        .as_object()
        .context("Tool input_schema must be an object")?;
    if schema.get("type") != Some(&json!("object"))
        || schema.get("additionalProperties") != Some(&json!(false))
    {
        bail!("Tool inputs must be an object with additionalProperties set to false");
    }
    if schema.keys().any(|key| {
        !["type", "properties", "required", "additionalProperties"].contains(&key.as_str())
    }) {
        bail!("Tool input_schema contains unsupported fields");
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .context("Tool inputs must declare properties")?;
    let expected = tool_input_slots(recipe)
        .map(|s| (s.name.as_str(), s))
        .collect::<BTreeMap<_, _>>();
    if properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected.keys().copied().collect()
    {
        bail!("Tool inputs must match the verified request's nonsecret parameters");
    }
    for (name, field) in properties {
        let field = field
            .as_object()
            .context("Each tool input must be an object")?;
        if field
            .keys()
            .any(|key| !["type", "description"].contains(&key.as_str()))
        {
            bail!("Input {name} contains unsupported schema fields");
        }
        if !matches!(
            field.get("type").and_then(Value::as_str),
            Some("string" | "integer" | "number" | "boolean")
        ) {
            bail!("Choose text, integer, number, or boolean for input {name}");
        }
        let description = field
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if description.trim().is_empty() || description.len() > 1000 {
            bail!("Describe what input {name} means (up to 1,000 characters)");
        }
        if redact_free_text(description) != description {
            bail!("Remove credentials from input {name}'s description");
        }
    }
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .context("Tool inputs must declare required")?;
    let actual = required
        .iter()
        .map(|v| v.as_str().context("Required input names must be strings"))
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_required = expected
        .values()
        .filter(|s| s.required)
        .map(|s| s.name.as_str())
        .collect::<BTreeSet<_>>();
    if actual != expected_required || actual.len() != required.len() {
        bail!("Required inputs must match the verified request");
    }
    Ok(())
}

pub fn required_environment(recipe: &Recipe) -> Vec<String> {
    all_env_requirements(recipe)
        .into_iter()
        .map(|item| item.name)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn native_client_config(
    recipe: &Recipe,
    tool: &NativeToolDefinition,
    cli_path: &Path,
    package_dir: &Path,
) -> Result<String> {
    native_client_config_with_options(
        recipe,
        tool,
        cli_path,
        package_dir,
        NativeExportOptions::default(),
    )
}

fn native_client_config_with_options(
    recipe: &Recipe,
    tool: &NativeToolDefinition,
    cli_path: &Path,
    package_dir: &Path,
    options: NativeExportOptions,
) -> Result<String> {
    if !cli_path.is_absolute() || !package_dir.is_absolute() {
        bail!("The executable and package directory must use absolute paths");
    }
    let environment = required_environment(recipe)
        .into_iter()
        .map(|name| (name, String::new()))
        .collect::<BTreeMap<_, _>>();
    let mut args = vec![json!("serve"), json!("--package"), json!(package_dir)];
    if is_mutating_recipe(recipe) {
        if !options.allow_mutating {
            bail!(
                "This request changes remote data. Explicitly allow write requests before exporting its MCP connection"
            );
        }
        args.push(json!("--allow-mutating"));
    }
    Ok(serde_json::to_string_pretty(&json!({"mcpServers": {
        (tool.name.clone()): {"command": cli_path, "args": args, "env": environment}
    }}))?)
}

pub fn export_native_mcp_package(
    recipe: &Recipe,
    out_dir: &Path,
    tool: &NativeToolDefinition,
    cli_path: &Path,
) -> Result<NativePackageExport> {
    export_native_mcp_package_with_options(
        recipe,
        out_dir,
        tool,
        cli_path,
        NativeExportOptions::default(),
    )
}

pub fn export_native_mcp_package_with_options(
    recipe: &Recipe,
    out_dir: &Path,
    tool: &NativeToolDefinition,
    cli_path: &Path,
    options: NativeExportOptions,
) -> Result<NativePackageExport> {
    if !is_agent_export_eligible(recipe) {
        bail!("Verify this request successfully before creating an MCP tool");
    }
    crate::mcp::validate_recipe_boundary(recipe)?;
    validate_tool_definition(recipe, tool)?;
    if !cli_path.is_file() {
        bail!(
            "The companion firstcall-cli executable is missing; keep it beside the FirstCall app"
        );
    }
    if !out_dir.is_absolute() {
        bail!("Choose an absolute export directory");
    }
    if out_dir.exists() {
        bail!("The export directory already exists; choose a new folder to preserve its contents");
    }
    let parent = out_dir
        .parent()
        .context("Export directory needs a parent")?;
    if !parent.is_dir() {
        bail!("The parent export folder does not exist");
    }
    let cli_path =
        fs::canonicalize(cli_path).context("Could not resolve the FirstCall CLI path")?;
    let out_dir = fs::canonicalize(parent)?.join(
        out_dir
            .file_name()
            .context("Export directory needs a name")?,
    );
    let client_config =
        native_client_config_with_options(recipe, tool, &cli_path, &out_dir, options)?;
    let staging = parent.join(format!(".firstcall-export-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&staging).context("Could not create the export folder")?;
    let result = (|| -> Result<()> {
        fs::write(staging.join("recipe.yaml"), recipe_to_agent_yaml(recipe)?)?;
        fs::write(
            staging.join("verified.lock.json"),
            recipe_to_verified_lock_json(recipe)?,
        )?;
        fs::write(staging.join("policy.json"), recipe_to_policy_json(recipe)?)?;
        fs::write(
            staging.join("tool.json"),
            serde_json::to_string_pretty(tool)?,
        )?;
        fs::write(staging.join("client-config.json"), &client_config)?;
        let names = required_environment(recipe);
        let env_help = if names.is_empty() {
            "This tool needs no authentication environment variables.".to_string()
        } else {
            format!(
                "Set these variables in your MCP client's environment: {}. The empty values in client-config.json are placeholders; put credentials in your client's settings, not in this package.",
                names.join(", ")
            )
        };
        fs::write(
            staging.join("README.md"),
            format!(
                "# {}\n\n{}\n\n## Connect\n\n1. Keep this folder and the FirstCall installation at their exported locations.\n2. Copy the server entry from client-config.json into your MCP client's local-server settings.\n3. {}\n4. Restart the MCP connection and call the {} tool.\n\nFirstCall runs this tool directly. Node.js, npm, and a build step are not required.\n\nThe request was verified before export; the first MCP call performs a new request. The package's file hashes and request policy are checked when the server starts. If you move the folder or application, export a new connection configuration.\n\nPackage: {}\nRuntime: {}\n",
                tool.title,
                tool.description,
                env_help,
                tool.name,
                out_dir.display(),
                cli_path.display()
            ),
        )?;
        write_native_package_manifest(&staging)?;
        let inspection = inspect_agent_package_dir(&staging);
        if !inspection.is_ready() {
            bail!(
                "Export validation failed: {}",
                inspection
                    .validation
                    .errors
                    .iter()
                    .chain(inspection.blockers.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        fs::rename(&staging, &out_dir).context("Could not finish the exported package")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(NativePackageExport {
        directory: out_dir,
        client_config,
        required_environment: required_environment(recipe),
        tool_name: tool.name.clone(),
    })
}
