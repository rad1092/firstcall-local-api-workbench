use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::exec::redact::sanitize_response_schema;
use crate::model::Recipe;

use super::agent_common::{GENERATOR, has_successful_verification, safe_canonical_recipe};

#[derive(Serialize)]
struct VerifiedLock {
    schema_version: u8,
    recipe_name: String,
    verified: bool,
    last_success_at: String,
    last_success_status: u16,
    request_fingerprint: String,
    response_schema_fingerprint: String,
    redaction_policy_version: u8,
    generator: String,
}

pub fn recipe_to_verified_lock_json(recipe: &Recipe) -> Result<String> {
    let artifact = VerifiedLock {
        schema_version: 1,
        recipe_name: recipe.name.clone(),
        verified: has_successful_verification(recipe),
        last_success_at: recipe
            .last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "unverified".to_string()),
        last_success_status: recipe.last_success_status.unwrap_or_default(),
        request_fingerprint: request_fingerprint_for_recipe(recipe)?,
        response_schema_fingerprint: response_schema_fingerprint_for_recipe(recipe)?,
        redaction_policy_version: 1,
        generator: GENERATOR.to_string(),
    };
    serde_json::to_string_pretty(&artifact).map_err(anyhow::Error::from)
}

pub fn request_fingerprint_for_recipe(recipe: &Recipe) -> Result<String> {
    let canonical = serde_json::to_string(&safe_canonical_recipe(recipe))?;
    Ok(sha256_hex(&canonical))
}

pub fn request_fingerprint_for_agent_recipe_yaml(value: &Value) -> Result<String> {
    let verified = value.get("verified").unwrap_or(&Value::Null);
    let auth = value.get("auth").unwrap_or(&Value::Null);
    let canonical = json!({
        "name": value.get("name").and_then(Value::as_str).unwrap_or_default(),
        "method": value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_uppercase(),
        "url_template": value.get("url_template").and_then(Value::as_str).unwrap_or_default(),
        "auth_type": auth.get("type").and_then(Value::as_str).unwrap_or("none"),
        "headers": value.get("headers").cloned().unwrap_or_else(|| json!({})),
        "query": value.get("query").cloned().unwrap_or_else(|| json!({})),
        "body_kind": value.get("body_kind").and_then(Value::as_str).unwrap_or("json"),
        "body_template": value.get("body_template").cloned().unwrap_or_else(|| json!({})),
        "slots": value.get("slots").cloned().unwrap_or_else(|| json!([])),
        "last_success_at": verified.get("last_success_at").and_then(Value::as_str),
        "last_success_status": verified.get("last_success_status").and_then(Value::as_u64),
    });
    let canonical = serde_json::to_string(&canonical)?;
    Ok(sha256_hex(&canonical))
}

pub fn response_schema_fingerprint_for_recipe(recipe: &Recipe) -> Result<String> {
    match recipe.response_schema.as_ref() {
        Some(schema) => {
            let sanitized = sanitize_response_schema(schema);
            Ok(sha256_hex(&serde_json::to_string(&sanitized)?))
        }
        None => Ok(sha256_hex("no_response_schema")),
    }
}

pub fn response_schema_fingerprint_for_agent_recipe_yaml(value: &Value) -> Result<String> {
    let Some(schema) = value.get("response_schema") else {
        return Ok(sha256_hex("no_response_schema"));
    };
    if schema.is_null() {
        return Ok(sha256_hex("no_response_schema"));
    }
    let schema = serde_json::from_value(schema.clone())?;
    let sanitized = sanitize_response_schema(&schema);
    Ok(sha256_hex(&serde_json::to_string(&sanitized)?))
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
