use anyhow::Result;
use serde::Serialize;

use crate::model::Recipe;

use super::agent_common::{
    BLOCKED_REQUEST_HEADERS, ensure_no_read_only_method_override, parse_agent_url_template,
};

const MAX_RESPONSE_BYTES: usize = 1_048_576;
const TIMEOUT_MS: u32 = 30_000;

#[derive(Serialize)]
struct RedirectPolicy {
    mode: &'static str,
    max_hops: u8,
}

#[derive(Serialize)]
struct DnsPolicy {
    resolve_all_addresses: bool,
    pin_connection: bool,
    allow_loopback: bool,
    allow_private_networks: bool,
    blocked_address_classes: Vec<&'static str>,
}

#[derive(Serialize)]
struct ProxyPolicy {
    mode: &'static str,
    environment_variables: &'static str,
}

#[derive(Serialize)]
struct AgentPolicy {
    schema_version: u8,
    allowed_methods: Vec<String>,
    allowed_origins: Vec<String>,
    allowed_path_templates: Vec<String>,
    allowed_hosts: Vec<String>,
    allowed_paths: Vec<String>,
    redirect_policy: RedirectPolicy,
    dns_policy: DnsPolicy,
    proxy_policy: ProxyPolicy,
    timeout_ms: u32,
    max_response_bytes: usize,
    blocked_headers: Vec<String>,
    secret_headers: Vec<String>,
    secret_query_keys: Vec<String>,
    requires_confirmation: bool,
    redact_response_keys: Vec<String>,
}

pub fn recipe_to_policy_json(recipe: &Recipe) -> Result<String> {
    let url = parse_agent_url_template(&recipe.url_template)?;
    ensure_no_read_only_method_override(recipe, &url.query_pairs)?;
    let method = recipe.method.to_ascii_uppercase();
    let requires_confirmation = !matches!(method.as_str(), "GET" | "HEAD");
    let policy = AgentPolicy {
        schema_version: 2,
        allowed_methods: vec![method],
        allowed_origins: vec![url.origin],
        allowed_path_templates: vec![url.path_template],
        allowed_hosts: vec![url.host],
        allowed_paths: vec![url.legacy_path],
        redirect_policy: RedirectPolicy {
            mode: "none",
            max_hops: 0,
        },
        dns_policy: DnsPolicy {
            resolve_all_addresses: true,
            pin_connection: true,
            allow_loopback: true,
            allow_private_networks: true,
            blocked_address_classes: vec!["unspecified", "link_local", "multicast"],
        },
        proxy_policy: ProxyPolicy {
            mode: "direct",
            environment_variables: "ignore",
        },
        timeout_ms: TIMEOUT_MS,
        max_response_bytes: MAX_RESPONSE_BYTES,
        blocked_headers: BLOCKED_REQUEST_HEADERS
            .iter()
            .map(|header| (*header).to_string())
            .collect(),
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
