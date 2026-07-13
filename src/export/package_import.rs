use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Map, Value};

use crate::exec::redact::sanitize_response_schema;
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, KeyValueField, Recipe, RuntimeSlot,
    SchemaSpec, SlotLocation,
};
use crate::store::db::{AppPaths, open_database};
use crate::store::repos::AppRepository;

use super::agent_package::sanitized_agent_url_template;
use super::package_inspect::{PackageInspectReport, inspect_agent_package_for_import};

#[derive(Clone, Debug)]
pub struct PackageImportReport {
    pub package_dir: std::path::PathBuf,
    pub status: PackageImportStatus,
    pub imported_recipe_id: Option<i64>,
    pub recipe_name: Option<String>,
    pub method: Option<String>,
    pub safe_url_template: Option<String>,
    pub blockers: Vec<String>,
    pub inspect_report: PackageInspectReport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageImportStatus {
    Imported,
    Blocked,
}

impl PackageImportReport {
    pub fn imported(&self) -> bool {
        self.status == PackageImportStatus::Imported
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            PackageImportStatus::Imported => "imported",
            PackageImportStatus::Blocked => "blocked",
        }
    }
}

pub fn import_agent_package_dir(path: &Path, paths: &AppPaths) -> Result<PackageImportReport> {
    let (inspect_report, recipe_snapshot) = inspect_agent_package_for_import(path);
    if !inspect_report.is_ready() {
        return Ok(blocked_report(
            path,
            inspect_report.blockers.clone(),
            inspect_report,
        ));
    }

    let recipe = match recipe_snapshot
        .as_ref()
        .context("validated recipe snapshot is unavailable")
        .and_then(recipe_from_agent_recipe_yaml)
    {
        Ok(recipe) => recipe,
        Err(error) => {
            return Ok(blocked_report(
                path,
                vec![format!("package recipe conversion failed: {error}")],
                inspect_report,
            ));
        }
    };

    let connection = open_database(paths)?;
    let repository = AppRepository::new(connection);
    let id = repository.insert_recipe(&recipe)?;
    Ok(PackageImportReport {
        package_dir: path.to_path_buf(),
        status: PackageImportStatus::Imported,
        imported_recipe_id: Some(id),
        recipe_name: Some(recipe.name.clone()),
        method: Some(recipe.method.clone()),
        safe_url_template: Some(sanitized_agent_url_template(&recipe)),
        blockers: Vec::new(),
        inspect_report,
    })
}

pub fn recipe_from_agent_package_dir(path: &Path) -> Result<Recipe> {
    let recipe_yaml = fs::read_to_string(path.join("recipe.yaml"))
        .with_context(|| format!("Could not read {}", path.join("recipe.yaml").display()))?;
    let value =
        yaml_serde::from_str::<Value>(&recipe_yaml).context("Could not parse recipe.yaml")?;
    recipe_from_agent_recipe_yaml(&value)
}

fn blocked_report(
    path: &Path,
    blockers: Vec<String>,
    inspect_report: PackageInspectReport,
) -> PackageImportReport {
    PackageImportReport {
        package_dir: path.to_path_buf(),
        status: PackageImportStatus::Blocked,
        imported_recipe_id: None,
        recipe_name: None,
        method: None,
        safe_url_template: None,
        blockers,
        inspect_report,
    }
}

fn recipe_from_agent_recipe_yaml(value: &Value) -> Result<Recipe> {
    let name = required_string(value, "name")?.to_string();
    let method = required_string(value, "method")?.to_ascii_uppercase();
    let url_template = convert_agent_placeholders(required_string(value, "url_template")?);
    let auth_style = auth_style(value.get("auth").context("recipe.yaml missing auth")?)?;
    let slots = slots(value.get("slots"));
    let slot_requirements = slots
        .iter()
        .map(|slot| (slot.name.clone(), slot.required))
        .collect::<BTreeMap<_, _>>();

    let recipe = Recipe {
        id: None,
        name,
        method,
        url_template,
        headers_template: headers_from_object(value.get("headers"), &slot_requirements),
        query_template: query_from_object(value.get("query"), &slot_requirements),
        body_template: body_template(
            value.get("body_kind").and_then(Value::as_str),
            value.get("body_template"),
            &slot_requirements,
        ),
        auth_style,
        slots,
        response_schema: response_schema(value)?,
        last_success_at: None,
        last_success_status: None,
    };
    Ok(recipe)
}

fn response_schema(value: &Value) -> Result<Option<SchemaSpec>> {
    let Some(schema) = value.get("response_schema") else {
        return Ok(None);
    };
    if schema.is_null() {
        return Ok(None);
    }
    let schema: SchemaSpec = serde_json::from_value(schema.clone())
        .context("recipe.yaml response_schema must match the supported schema shape")?;
    Ok(Some(sanitize_response_schema(&schema)))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    match value.get(field).and_then(Value::as_str) {
        Some(text) if !text.trim().is_empty() => Ok(text),
        _ => bail!("recipe.yaml {field} must be a non-empty string"),
    }
}

fn auth_style(value: &Value) -> Result<AuthStyle> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase();
    match kind.as_str() {
        "none" => Ok(AuthStyle::None),
        "bearer" => Ok(AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: value
                .get("header_name")
                .and_then(Value::as_str)
                .unwrap_or("Authorization")
                .to_string(),
        }),
        "basic" => Ok(AuthStyle::Basic {
            username_slot: "username".to_string(),
            password_slot: "password".to_string(),
        }),
        "header_api_key" => Ok(AuthStyle::HeaderApiKey {
            header_name: value
                .get("header_name")
                .and_then(Value::as_str)
                .unwrap_or("X-API-Key")
                .to_string(),
            slot_name: "api_key".to_string(),
        }),
        "query_api_key" => Ok(AuthStyle::QueryApiKey {
            param_name: value
                .get("query_param")
                .and_then(Value::as_str)
                .unwrap_or("api_key")
                .to_string(),
            slot_name: "api_key".to_string(),
        }),
        _ => bail!("recipe.yaml auth type is not supported"),
    }
}

fn slots(value: Option<&Value>) -> Vec<RuntimeSlot> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let name = item.get("name").and_then(Value::as_str)?;
            if name.trim().is_empty() {
                return None;
            }
            Some(RuntimeSlot {
                name: name.to_string(),
                location: slot_location(item.get("location").and_then(Value::as_str)),
                required: item
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                current_value: None,
                description: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                confidence: Confidence::High,
            })
        })
        .collect()
}

fn slot_location(value: Option<&str>) -> SlotLocation {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "query" => SlotLocation::Query,
        "header" => SlotLocation::Header,
        "body" => SlotLocation::Body,
        "auth" => SlotLocation::Auth,
        _ => SlotLocation::Path,
    }
}

fn query_from_object(
    value: Option<&Value>,
    slot_requirements: &BTreeMap<String, bool>,
) -> Vec<KeyValueField> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Vec::new();
    };
    object
        .iter()
        .map(|(key, value)| {
            let value = stringify_template_value(value);
            KeyValueField {
                key: key.clone(),
                value: convert_agent_placeholders(&value),
                required: field_required(&value, slot_requirements),
                description: "Imported from agent package".to_string(),
                confidence: Confidence::High,
            }
        })
        .collect()
}

fn headers_from_object(
    value: Option<&Value>,
    slot_requirements: &BTreeMap<String, bool>,
) -> Vec<HeaderField> {
    query_from_object(value, slot_requirements)
        .into_iter()
        .map(|field| HeaderField {
            key: field.key,
            value: field.value,
            required: field.required,
            description: field.description,
            confidence: field.confidence,
        })
        .collect()
}

fn field_required(value: &str, slot_requirements: &BTreeMap<String, bool>) -> bool {
    let names = agent_placeholder_names(value);
    if names.is_empty() {
        return true;
    }
    names
        .iter()
        .any(|name| *slot_requirements.get(name).unwrap_or(&true))
}

fn body_template(
    kind: Option<&str>,
    value: Option<&Value>,
    slot_requirements: &BTreeMap<String, bool>,
) -> BodyTemplate {
    let Some(value) = value else {
        return BodyTemplate::None;
    };
    if value.is_null() || value.as_object().is_some_and(Map::is_empty) {
        return BodyTemplate::None;
    }
    let kind = kind.unwrap_or("json").to_ascii_lowercase();
    let converted = convert_json_placeholders(value);
    match kind.as_str() {
        "none" => BodyTemplate::None,
        "text" => BodyTemplate::Text {
            text: stringify_template_value(&converted),
        },
        "form" => BodyTemplate::Form {
            fields: fields_from_body_object(&converted, slot_requirements),
        },
        "multipart" => BodyTemplate::Multipart {
            fields: fields_from_body_object(&converted, slot_requirements),
        },
        _ => BodyTemplate::Json {
            template: serde_json::to_string(&converted).unwrap_or_else(|_| "{}".to_string()),
        },
    }
}

fn fields_from_body_object(
    value: &Value,
    slot_requirements: &BTreeMap<String, bool>,
) -> Vec<KeyValueField> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    object
        .iter()
        .map(|(key, value)| {
            let value = stringify_template_value(value);
            KeyValueField {
                key: key.clone(),
                required: field_required(&value, slot_requirements),
                value,
                description: "Imported from agent package body template".to_string(),
                confidence: Confidence::High,
            }
        })
        .collect()
}

fn stringify_template_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn convert_json_placeholders(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(convert_agent_placeholders(text)),
        Value::Array(items) => Value::Array(items.iter().map(convert_json_placeholders).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), convert_json_placeholders(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn convert_agent_placeholders(text: &str) -> String {
    let regex = Regex::new(r"\$\{\s*([A-Za-z0-9_\-]+)\s*\}").expect("valid placeholder regex");
    regex
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let name = captures.get(1).map_or("", |capture| capture.as_str());
            if name.starts_with("FIRSTCALL_") {
                format!("${{{name}}}")
            } else {
                format!("{{{{{name}}}}}")
            }
        })
        .to_string()
}

fn agent_placeholder_names(text: &str) -> Vec<String> {
    let regex = Regex::new(r"\$\{\s*([A-Za-z0-9_\-]+)\s*\}").expect("valid placeholder regex");
    regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|capture| capture.as_str().to_string()))
        .filter(|name| !name.starts_with("FIRSTCALL_"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::recipe_from_agent_recipe_yaml;
    use crate::export::package_inspect::inspect_agent_package_for_import;

    #[test]
    fn inspected_recipe_snapshot_remains_the_conversion_source() {
        let package = tempdir().expect("package tempdir");
        fs::write(
            package.path().join("recipe.yaml"),
            "name: snapshot-name\nmethod: GET\nurl_template: https://api.example.com/users\nauth:\n  type: none\n",
        )
        .expect("write recipe");

        let (_report, snapshot) = inspect_agent_package_for_import(package.path());
        fs::write(
            package.path().join("recipe.yaml"),
            "name: changed-after-inspect\nmethod: DELETE\nurl_template: https://evil.example/users\nauth:\n  type: none\n",
        )
        .expect("replace recipe after inspect");

        let recipe = recipe_from_agent_recipe_yaml(snapshot.as_ref().expect("recipe snapshot"))
            .expect("convert snapshot");
        assert_eq!(recipe.name, "snapshot-name");
        assert_eq!(recipe.method, "GET");
        assert_eq!(recipe.url_template, "https://api.example.com/users");
    }
}
