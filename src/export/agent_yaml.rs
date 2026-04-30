use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::model::{AuthStyle, Recipe};

use super::agent_common::{
    ExportSlot, GENERATOR, TAGLINE, all_env_requirements, auth_type, body_template_value,
    export_slots, non_auth_headers_map, non_auth_query_map, recipe_slug,
    sanitize_url_template_for_agent,
};

#[derive(Serialize)]
struct AgentRecipeYaml {
    schema_version: u8,
    generator: String,
    name: String,
    description: String,
    method: String,
    url_template: String,
    auth: AgentAuthYaml,
    headers: BTreeMap<String, String>,
    query: BTreeMap<String, String>,
    body_template: Value,
    slots: Vec<ExportSlot>,
    verified: VerifiedYaml,
    security: SecurityYaml,
}

#[derive(Serialize)]
struct AgentAuthYaml {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_param: Option<String>,
}

#[derive(Serialize)]
struct VerifiedYaml {
    last_success_at: String,
    last_success_status: u16,
}

#[derive(Serialize)]
struct SecurityYaml {
    secrets_stored: bool,
    secret_source: String,
    redacted: bool,
    environment_variables: Vec<String>,
}

pub fn recipe_to_agent_yaml(recipe: &Recipe) -> Result<String> {
    let artifact = AgentRecipeYaml {
        schema_version: 1,
        generator: GENERATOR.to_string(),
        name: recipe_slug(&recipe.name),
        description: TAGLINE.to_string(),
        method: recipe.method.to_ascii_uppercase(),
        url_template: sanitize_url_template_for_agent(&recipe.url_template),
        auth: auth_yaml(&recipe.auth_style),
        headers: non_auth_headers_map(recipe),
        query: non_auth_query_map(recipe),
        body_template: body_template_value(&recipe.body_template),
        slots: export_slots(&recipe.slots),
        verified: VerifiedYaml {
            last_success_at: recipe
                .last_success_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "unverified".to_string()),
            last_success_status: recipe.last_success_status.unwrap_or_default(),
        },
        security: SecurityYaml {
            secrets_stored: false,
            secret_source: "env".to_string(),
            redacted: true,
            environment_variables: all_env_requirements(recipe)
                .into_iter()
                .map(|item| item.name)
                .collect(),
        },
    };
    yaml_serde::to_string(&artifact).map_err(anyhow::Error::from)
}

fn auth_yaml(auth: &AuthStyle) -> AgentAuthYaml {
    match auth {
        AuthStyle::None => AgentAuthYaml {
            kind: auth_type(auth).to_string(),
            env: None,
            username_env: None,
            password_env: None,
            header_name: None,
            query_param: None,
        },
        AuthStyle::Bearer { header_name, .. } => AgentAuthYaml {
            kind: auth_type(auth).to_string(),
            env: Some("FIRSTCALL_BEARER_TOKEN".to_string()),
            username_env: None,
            password_env: None,
            header_name: Some(header_name.clone()),
            query_param: None,
        },
        AuthStyle::Basic { .. } => AgentAuthYaml {
            kind: auth_type(auth).to_string(),
            env: None,
            username_env: Some("FIRSTCALL_USERNAME".to_string()),
            password_env: Some("FIRSTCALL_PASSWORD".to_string()),
            header_name: Some("Authorization".to_string()),
            query_param: None,
        },
        AuthStyle::HeaderApiKey { header_name, .. } => AgentAuthYaml {
            kind: auth_type(auth).to_string(),
            env: Some("FIRSTCALL_API_KEY".to_string()),
            username_env: None,
            password_env: None,
            header_name: Some(header_name.clone()),
            query_param: None,
        },
        AuthStyle::QueryApiKey { param_name, .. } => AgentAuthYaml {
            kind: auth_type(auth).to_string(),
            env: Some("FIRSTCALL_API_KEY".to_string()),
            username_env: None,
            password_env: None,
            header_name: None,
            query_param: Some(param_name.clone()),
        },
    }
}
