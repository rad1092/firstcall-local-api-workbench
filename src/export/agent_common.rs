use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
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
pub(crate) const BLOCKED_REQUEST_HEADERS: &[&str] = &[
    "Host",
    "Content-Length",
    "Transfer-Encoding",
    "Connection",
    "Upgrade",
    "Proxy-Authorization",
    "Proxy-Connection",
    "Keep-Alive",
    "TE",
    "Trailer",
    "Cookie",
    "Forwarded",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
];

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

#[derive(Clone, Debug)]
pub(crate) struct AgentUrlTemplateParts {
    pub origin: String,
    pub host: String,
    pub path_template: String,
    pub legacy_path: String,
    pub query_pairs: Vec<(String, String)>,
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

pub(crate) fn body_kind(body: &BodyTemplate) -> &'static str {
    match body {
        BodyTemplate::None => "none",
        BodyTemplate::Json { .. } => "json",
        BodyTemplate::Text { .. } => "text",
        BodyTemplate::Form { .. } => "form",
        BodyTemplate::Multipart { .. } => "multipart",
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
    let parts = parse_agent_url_template(url_template)?;
    Ok((parts.host, parts.legacy_path))
}

pub(crate) fn parse_agent_url_template(url_template: &str) -> Result<AgentUrlTemplateParts> {
    let normalized = sanitize_url_template_for_agent(url_template);
    if normalized.contains('#') {
        bail!("Recipe URL template must not include a fragment");
    }
    if normalized.contains('\\') {
        bail!("Recipe URL template must not include backslashes");
    }

    let scheme_end = normalized
        .find("://")
        .context("Recipe URL template must be absolute")?;
    let authority_start = scheme_end + 3;
    let authority_end = normalized[authority_start..]
        .find(['/', '?'])
        .map(|index| authority_start + index)
        .unwrap_or(normalized.len());
    let authority = &normalized[authority_start..authority_end];
    if authority.is_empty() {
        bail!("Recipe URL template must include a host");
    }
    if contains_url_placeholder(authority) {
        bail!("Recipe URL template authority must not contain placeholders");
    }

    let parseable = template_to_url_placeholders(&normalized);
    let parsed = Url::parse(&parseable).context("Recipe URL template must be absolute")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("Recipe URL template scheme must be http or https");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("Recipe URL template must not include userinfo");
    }
    validate_literal_host(&parsed)?;
    let host = parsed
        .host_str()
        .context("Recipe URL template must include a host")?
        .to_string();
    let origin = parsed.origin().ascii_serialization();

    let remainder = &normalized[authority_end..];
    let (path_template, raw_query) = if remainder.is_empty() {
        ("/".to_string(), None)
    } else if let Some(query) = remainder.strip_prefix('?') {
        ("/".to_string(), Some(query))
    } else if let Some((path, query)) = remainder.split_once('?') {
        (path.to_string(), Some(query))
    } else {
        (remainder.to_string(), None)
    };
    if !path_template.starts_with('/') {
        bail!("Recipe URL template path must be absolute");
    }

    let mut query_pairs = Vec::new();
    if let Some(query) = raw_query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if contains_url_placeholder(&key) {
                bail!("Recipe URL template query keys must not contain placeholders");
            }
            let key = key.into_owned();
            let value = value.into_owned();
            let value = if is_secret_key(&key) || value.contains(REDACTED) {
                env_ref(&secret_env_for_key(&key, &value))
            } else {
                value
            };
            query_pairs.push((key, value));
        }
    }

    Ok(AgentUrlTemplateParts {
        origin,
        host,
        path_template,
        legacy_path: parsed.path().to_string(),
        query_pairs,
    })
}

fn validate_literal_host(url: &Url) -> Result<()> {
    match url.host() {
        Some(url::Host::Ipv4(address)) if disallowed_ipv4(address) => {
            bail!("Recipe URL template targets a disallowed IPv4 address class")
        }
        Some(url::Host::Ipv6(address)) if disallowed_ipv6(address) => {
            bail!("Recipe URL template targets a disallowed IPv6 address class")
        }
        Some(_) => Ok(()),
        None => bail!("Recipe URL template must include a host"),
    }
}

fn disallowed_ipv4(address: std::net::Ipv4Addr) -> bool {
    address.is_unspecified() || address.is_link_local() || address.is_multicast()
}

fn disallowed_ipv6(address: std::net::Ipv6Addr) -> bool {
    address.is_unspecified()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || address.to_ipv4_mapped().is_some_and(disallowed_ipv4)
}

pub(crate) fn destructive_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "DELETE" | "PATCH" | "PUT"
    )
}

pub(crate) fn ensure_no_read_only_method_override(
    recipe: &Recipe,
    url_query_pairs: &[(String, String)],
) -> Result<()> {
    if !matches!(recipe.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
        return Ok(());
    }

    let has_override_header = recipe
        .headers_template
        .iter()
        .any(|header| matches_method_override_header(&header.key))
        || match &recipe.auth_style {
            AuthStyle::Bearer { header_name, .. } | AuthStyle::HeaderApiKey { header_name, .. } => {
                matches_method_override_header(header_name)
            }
            AuthStyle::None | AuthStyle::Basic { .. } | AuthStyle::QueryApiKey { .. } => false,
        };
    if has_override_header {
        bail!("GET/HEAD recipes must not contain an HTTP method override header");
    }

    let has_override_query = url_query_pairs
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("_method"))
        || recipe
            .query_template
            .iter()
            .any(|field| field.key.eq_ignore_ascii_case("_method"))
        || matches!(
            &recipe.auth_style,
            AuthStyle::QueryApiKey { param_name, .. } if param_name.eq_ignore_ascii_case("_method")
        );
    if has_override_query {
        bail!("GET/HEAD recipes must not contain a _method query parameter");
    }

    if matches!(
        &recipe.body_template,
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields }
            if fields.iter().any(|field| field.key.eq_ignore_ascii_case("_method"))
    ) {
        bail!("GET/HEAD recipes must not contain a _method form field");
    }
    Ok(())
}

fn matches_method_override_header(header: &str) -> bool {
    [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    ]
    .iter()
    .any(|candidate| header.eq_ignore_ascii_case(candidate))
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
        "body_kind": body_kind(&recipe.body_template),
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
    for name in env_refs_in_value(&body_template_value(&recipe.body_template)) {
        if !requirements.iter().any(|existing| existing.name == name) {
            requirements.push(EnvRequirement {
                description: format!("Environment value referenced by body template {name}"),
                name,
            });
        }
    }
    requirements
}

fn env_refs_in_value(value: &Value) -> Vec<String> {
    let mut refs = Vec::new();
    collect_env_refs(value, &mut refs);
    refs.sort();
    refs.dedup();
    refs
}

fn collect_env_refs(value: &Value, refs: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let regex =
                Regex::new(r"\$\{\s*(FIRSTCALL_[A-Z0-9_]+)\s*\}").expect("valid env ref regex");
            refs.extend(
                regex
                    .captures_iter(text)
                    .filter_map(|captures| captures.get(1).map(|capture| capture.as_str()))
                    .map(str::to_string),
            );
        }
        Value::Array(items) => {
            for item in items {
                collect_env_refs(item, refs);
            }
        }
        Value::Object(object) => {
            for item in object.values() {
                collect_env_refs(item, refs);
            }
        }
        _ => {}
    }
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

fn contains_url_placeholder(text: &str) -> bool {
    let placeholder =
        Regex::new(r"\$\{\s*[A-Za-z0-9_\-]+\s*\}").expect("valid URL placeholder regex");
    placeholder.is_match(text)
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
