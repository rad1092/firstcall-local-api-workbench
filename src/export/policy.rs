use anyhow::Result;
use serde::Serialize;

use crate::model::Recipe;

use super::agent_common::{destructive_method, looks_destructive_path, parse_url_template};

#[derive(Serialize)]
struct AgentPolicy {
    schema_version: u8,
    allowed_methods: Vec<String>,
    allowed_hosts: Vec<String>,
    allowed_paths: Vec<String>,
    blocked_headers: Vec<String>,
    secret_headers: Vec<String>,
    secret_query_keys: Vec<String>,
    requires_confirmation: bool,
    redact_response_keys: Vec<String>,
}

pub fn recipe_to_policy_json(recipe: &Recipe) -> Result<String> {
    let (host, path) = parse_url_template(&recipe.url_template)?;
    let method = recipe.method.to_ascii_uppercase();
    let requires_confirmation =
        destructive_method(&method) || (method == "POST" && looks_destructive_path(&path));
    let policy = AgentPolicy {
        schema_version: 1,
        allowed_methods: vec![method],
        allowed_hosts: vec![host],
        allowed_paths: vec![path],
        blocked_headers: Vec::new(),
        secret_headers: vec![
            "Authorization".to_string(),
            "Proxy-Authorization".to_string(),
            "Cookie".to_string(),
            "Set-Cookie".to_string(),
            "X-API-Key".to_string(),
        ],
        secret_query_keys: vec![
            "api_key".to_string(),
            "token".to_string(),
            "secret".to_string(),
            "access_token".to_string(),
            "refresh_token".to_string(),
        ],
        requires_confirmation,
        redact_response_keys: vec![
            "token".to_string(),
            "secret".to_string(),
            "password".to_string(),
            "api_key".to_string(),
            "access_token".to_string(),
            "refresh_token".to_string(),
        ],
    };
    serde_json::to_string_pretty(&policy).map_err(anyhow::Error::from)
}
