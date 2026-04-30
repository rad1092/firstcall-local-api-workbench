use std::collections::BTreeMap;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::exec::redact::{REDACTED, is_secret_key, redact_body};
use crate::model::{
    AuthStyle, BodyTemplate, HeaderField, KeyValueField, Recipe, RuntimeSlot, SlotLocation,
};

pub(crate) const PRODUCT_LABEL: &str = "FirstCall Agent Recipes";
pub(crate) const TAGLINE: &str = "Verified API tool recipes for AI agents.";
pub(crate) const GENERATOR: &str = "firstcall";

pub(crate) fn has_successful_verification(recipe: &Recipe) -> bool {
    recipe.last_success_at.is_some() && matches!(recipe.last_success_status, Some(200..=299))
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ExportSlot {
    pub name: String,
    pub location: String,
    pub required: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvRequirement {
    pub name: String,
    pub description: String,
}

pub(crate) fn recipe_slug(name: &str) -> String {
    let mut output = String::new();
    let mut previous_underscore = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            previous_underscore = false;
        } else if !previous_underscore {
            output.push('_');
            previous_underscore = true;
        }
    }
    let trimmed = output.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "firstcall_recipe".to_string()
    } else {
        trimmed
    }
}

pub(crate) fn env_var_from_name(name: &str, fallback: &str) -> String {
    let mut output = String::new();
    let mut previous_underscore = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_uppercase());
            previous_underscore = false;
        } else if !previous_underscore {
            output.push('_');
            previous_underscore = true;
        }
    }
    let trimmed = output.trim_matches('_').to_string();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

pub(crate) fn auth_env_requirements(auth: &AuthStyle) -> Vec<EnvRequirement> {
    match auth {
        AuthStyle::None => Vec::new(),
        AuthStyle::Bearer { .. } => vec![EnvRequirement {
            name: "FIRSTCALL_BEARER_TOKEN".to_string(),
            description: "Bearer token for this verified recipe".to_string(),
        }],
        AuthStyle::Basic { .. } => vec![
            EnvRequirement {
                name: "FIRSTCALL_USERNAME".to_string(),
                description: "Basic auth username for this verified recipe".to_string(),
            },
            EnvRequirement {
                name: "FIRSTCALL_PASSWORD".to_string(),
                description: "Basic auth password for this verified recipe".to_string(),
            },
        ],
        AuthStyle::HeaderApiKey { .. } | AuthStyle::QueryApiKey { .. } => vec![EnvRequirement {
            name: "FIRSTCALL_API_KEY".to_string(),
            description: "API key for this verified recipe".to_string(),
        }],
    }
}

pub(crate) fn auth_type(auth: &AuthStyle) -> &'static str {
    match auth {
        AuthStyle::None => "none",
        AuthStyle::Bearer { .. } => "bearer",
        AuthStyle::Basic { .. } => "basic",
        AuthStyle::HeaderApiKey { .. } => "header_api_key",
        AuthStyle::QueryApiKey { .. } => "query_api_key",
    }
}

pub(crate) fn secret_env_for_key(key: &str, value: &str) -> String {
    if key.eq_ignore_ascii_case("authorization") && value.to_ascii_lowercase().contains("bearer") {
        return "FIRSTCALL_BEARER_TOKEN".to_string();
    }
    if key.to_ascii_lowercase().contains("api") {
        return "FIRSTCALL_API_KEY".to_string();
    }
    format!("FIRSTCALL_{}", env_var_from_name(key, "SECRET"))
}

pub(crate) fn env_ref(env_name: &str) -> String {
    format!("${{{env_name}}}")
}

pub(crate) fn template_to_agent_slots(text: &str) -> String {
    let slot_regex = Regex::new(r"\{\{\s*([A-Za-z0-9_\-]+)\s*\}\}").expect("valid slot regex");
    slot_regex.replace_all(text, "$${$1}").to_string()
}

pub(crate) fn sanitize_url_template_for_agent(url_template: &str) -> String {
    let normalized = template_to_agent_slots(url_template);
    let parseable = template_to_url_placeholders(&normalized);
    if Url::parse(&parseable).is_err() {
        return normalized;
    }
    sanitize_query_params(&normalized)
}

pub(crate) fn sanitized_header_value(header: &HeaderField) -> String {
    if header.key.eq_ignore_ascii_case("authorization") {
        if header.value.to_ascii_lowercase().starts_with("basic ") {
            return format!(
                "Basic {}:{}",
                env_ref("FIRSTCALL_USERNAME"),
                env_ref("FIRSTCALL_PASSWORD")
            );
        }
        return format!("Bearer {}", env_ref("FIRSTCALL_BEARER_TOKEN"));
    }
    if is_secret_key(&header.key) || header.value.contains(REDACTED) {
        return env_ref(&secret_env_for_key(&header.key, &header.value));
    }
    template_to_agent_slots(&header.value)
}

pub(crate) fn sanitized_key_value(field: &KeyValueField) -> String {
    if is_secret_key(&field.key) || field.value.contains(REDACTED) {
        return env_ref(&secret_env_for_key(&field.key, &field.value));
    }
    template_to_agent_slots(&field.value)
}

pub(crate) fn non_auth_headers_map(recipe: &Recipe) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for header in &recipe.headers_template {
        if is_auth_generated_header(&recipe.auth_style, &header.key) {
            continue;
        }
        headers.insert(header.key.clone(), sanitized_header_value(header));
    }
    headers
}

pub(crate) fn non_auth_query_map(recipe: &Recipe) -> BTreeMap<String, String> {
    let mut query = BTreeMap::new();
    for item in &recipe.query_template {
        if is_auth_generated_query_param(&recipe.auth_style, &item.key) {
            continue;
        }
        query.insert(item.key.clone(), sanitized_key_value(item));
    }
    query
}

pub(crate) fn body_template_value(body: &BodyTemplate) -> Value {
    match body {
        BodyTemplate::None => json!({}),
        BodyTemplate::Json { template } => {
            let redacted = redact_body(template, Some("application/json"));
            match serde_json::from_str::<Value>(&redacted) {
                Ok(value) => sanitize_json_template(&value),
                Err(_) => Value::String(template_to_agent_slots(&redacted)),
            }
        }
        BodyTemplate::Text { text } => {
            Value::String(template_to_agent_slots(&redact_body(text, None)))
        }
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            let mut object = serde_json::Map::new();
            for field in fields {
                object.insert(field.key.clone(), Value::String(sanitized_key_value(field)));
            }
            Value::Object(object)
        }
    }
}

pub(crate) fn export_slots(slots: &[RuntimeSlot]) -> Vec<ExportSlot> {
    slots
        .iter()
        .filter(|slot| slot.location != SlotLocation::Auth)
        .map(|slot| ExportSlot {
            name: slot.name.clone(),
            location: slot.location.label().to_string(),
            required: slot.required,
        })
        .collect()
}

pub(crate) fn parse_url_template(url_template: &str) -> Result<(String, String)> {
    let sanitized = template_to_url_placeholders(url_template);
    let parsed = Url::parse(&sanitized).context("Recipe URL template must be absolute")?;
    let host = parsed
        .host_str()
        .context("Recipe URL template must include a host")?
        .to_string();
    Ok((host, parsed.path().to_string()))
}

pub(crate) fn destructive_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "DELETE" | "PATCH" | "PUT"
    )
}

pub(crate) fn looks_destructive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "delete",
        "remove",
        "deactivate",
        "archive",
        "cancel",
        "refund",
        "void",
        "close",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn safe_canonical_recipe(recipe: &Recipe) -> Value {
    json!({
        "name": recipe_slug(&recipe.name),
        "method": recipe.method.to_ascii_uppercase(),
        "url_template": sanitize_url_template_for_agent(&recipe.url_template),
        "auth_type": auth_type(&recipe.auth_style),
        "headers": non_auth_headers_map(recipe),
        "query": non_auth_query_map(recipe),
        "body_template": body_template_value(&recipe.body_template),
        "slots": export_slots(&recipe.slots),
        "last_success_at": recipe.last_success_at.map(|value| value.to_rfc3339()),
        "last_success_status": recipe.last_success_status,
    })
}

pub(crate) fn all_env_requirements(recipe: &Recipe) -> Vec<EnvRequirement> {
    let mut requirements = auth_env_requirements(&recipe.auth_style);
    for item in url_query_env_requirements(&recipe.url_template) {
        if !requirements
            .iter()
            .any(|existing| existing.name == item.name)
        {
            requirements.push(item);
        }
    }
    for header in &recipe.headers_template {
        if is_secret_key(&header.key) || header.value.contains(REDACTED) {
            let name = secret_env_for_key(&header.key, &header.value);
            if !requirements.iter().any(|item| item.name == name) {
                requirements.push(EnvRequirement {
                    name,
                    description: format!("Secret value for header {}", header.key),
                });
            }
        }
    }
    for item in &recipe.query_template {
        if is_secret_key(&item.key) || item.value.contains(REDACTED) {
            let name = secret_env_for_key(&item.key, &item.value);
            if !requirements.iter().any(|existing| existing.name == name) {
                requirements.push(EnvRequirement {
                    name,
                    description: format!("Secret value for query parameter {}", item.key),
                });
            }
        }
    }
    requirements
}

fn url_query_env_requirements(url_template: &str) -> Vec<EnvRequirement> {
    let normalized = template_to_agent_slots(url_template);
    let (without_fragment, _) = normalized
        .split_once('#')
        .map_or((normalized.as_str(), None), |(before, after)| {
            (before, Some(after))
        });
    let Some((_, query)) = without_fragment.split_once('?') else {
        return Vec::new();
    };

    query
        .split('&')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            is_secret_key(key).then(|| EnvRequirement {
                name: secret_env_for_key(key, value),
                description: format!("Secret value for URL query parameter {key}"),
            })
        })
        .collect()
}

fn is_auth_generated_header(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::Bearer { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::Basic { .. } => key.eq_ignore_ascii_case("authorization"),
        AuthStyle::HeaderApiKey { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::None | AuthStyle::QueryApiKey { .. } => false,
    }
}

fn is_auth_generated_query_param(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::QueryApiKey { param_name, .. } => param_name.eq_ignore_ascii_case(key),
        AuthStyle::None
        | AuthStyle::Bearer { .. }
        | AuthStyle::Basic { .. }
        | AuthStyle::HeaderApiKey { .. } => false,
    }
}

fn sanitize_json_template(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in object {
                if is_secret_key(key) || value == REDACTED {
                    sanitized.insert(
                        key.clone(),
                        Value::String(env_ref(&secret_env_for_key(key, ""))),
                    );
                } else {
                    sanitized.insert(key.clone(), sanitize_json_template(value));
                }
            }
            Value::Object(sanitized)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize_json_template).collect()),
        Value::String(text) => Value::String(template_to_agent_slots(text)),
        _ => value.clone(),
    }
}

fn template_to_url_placeholders(text: &str) -> String {
    let double_brace =
        Regex::new(r"\{\{\s*[A-Za-z0-9_\-]+\s*\}\}").expect("valid double brace regex");
    let dollar_brace =
        Regex::new(r"\$\{\s*[A-Za-z0-9_\-]+\s*\}").expect("valid dollar brace regex");
    let replaced = double_brace.replace_all(text, "slot");
    dollar_brace.replace_all(&replaced, "slot").to_string()
}

fn sanitize_query_params(normalized_url: &str) -> String {
    let (without_fragment, fragment) = normalized_url
        .split_once('#')
        .map_or((normalized_url, None), |(before, after)| {
            (before, Some(after))
        });
    let Some((base, query)) = without_fragment.split_once('?') else {
        return normalized_url.to_string();
    };
    if query.is_empty() {
        return normalized_url.to_string();
    }

    let sanitized_query = query
        .split('&')
        .map(|part| {
            let Some((key, value)) = part.split_once('=') else {
                return part.to_string();
            };
            if is_secret_key(key) {
                format!("{key}={}", env_ref(&secret_env_for_key(key, value)))
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    let mut output = format!("{base}?{sanitized_query}");
    if let Some(fragment) = fragment {
        output.push('#');
        output.push_str(fragment);
    }
    output
}
