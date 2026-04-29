use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::Recipe;

use super::agent_common::{GENERATOR, safe_canonical_recipe};

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
    let canonical = serde_json::to_string(&safe_canonical_recipe(recipe))?;
    let artifact = VerifiedLock {
        schema_version: 1,
        recipe_name: recipe.name.clone(),
        verified: recipe.last_success_at.is_some() && recipe.last_success_status.is_some(),
        last_success_at: recipe
            .last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "unverified".to_string()),
        last_success_status: recipe.last_success_status.unwrap_or_default(),
        request_fingerprint: sha256_hex(&canonical),
        response_schema_fingerprint: sha256_hex("no_response_schema"),
        redaction_policy_version: 1,
        generator: GENERATOR.to_string(),
    };
    serde_json::to_string_pretty(&artifact).map_err(anyhow::Error::from)
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
