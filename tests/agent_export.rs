use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use firstcall::export::agent_package::{export_agent_package, is_agent_export_eligible};
use firstcall::export::agent_yaml::recipe_to_agent_yaml;
use firstcall::export::policy::recipe_to_policy_json;
use firstcall::export::verified_lock::recipe_to_verified_lock_json;
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, Recipe, RuntimeSlot, SlotLocation,
};
use serde_json::Value;
use tempfile::tempdir;

const RAW_SECRET: &str = "sk_test_raw_secret_123";

#[test]
fn verified_recipe_can_export_and_unverified_recipe_cannot() {
    let recipe = fake_recipe("POST", "https://api.stripe.com/v1/customers");
    assert!(is_agent_export_eligible(&recipe));

    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");

    let mut missing_time = recipe.clone();
    missing_time.last_success_at = None;
    assert!(!is_agent_export_eligible(&missing_time));
    assert!(export_agent_package(&missing_time, out.path()).is_err());

    let mut missing_status = recipe;
    missing_status.last_success_status = None;
    assert!(!is_agent_export_eligible(&missing_status));
    assert!(export_agent_package(&missing_status, out.path()).is_err());
}

#[test]
fn yaml_export_contains_agent_fields_without_raw_secrets() {
    let recipe = fake_recipe("POST", "https://api.stripe.com/v1/customers");
    let yaml = recipe_to_agent_yaml(&recipe).expect("yaml");

    assert!(yaml.contains("method: POST"));
    assert!(yaml.contains("url_template: https://api.stripe.com/v1/customers"));
    assert!(yaml.contains("${FIRSTCALL_BEARER_TOKEN}"));
    assert!(!yaml.contains(RAW_SECRET));
}

#[test]
fn verified_lock_marks_successful_recipe_verified() {
    let recipe = fake_recipe("POST", "https://api.stripe.com/v1/customers");
    let lock = recipe_to_verified_lock_json(&recipe).expect("lock");
    let value: Value = serde_json::from_str(&lock).expect("json");

    assert_eq!(value["verified"], true);
    assert_eq!(value["last_success_status"], 200);
    assert!(value["request_fingerprint"].as_str().unwrap().len() >= 64);
    assert!(!lock.contains(RAW_SECRET));
}

#[test]
fn policy_extracts_host_path_and_requires_confirmation_for_mutating_methods() {
    let post = fake_recipe("POST", "https://api.stripe.com/v1/customers");
    let policy: Value =
        serde_json::from_str(&recipe_to_policy_json(&post).expect("policy")).expect("json");
    assert_eq!(policy["allowed_hosts"][0], "api.stripe.com");
    assert_eq!(policy["allowed_paths"][0], "/v1/customers");
    assert_eq!(policy["requires_confirmation"], false);

    for method in ["DELETE", "PATCH", "PUT"] {
        let recipe = fake_recipe(method, "https://api.example.com/v1/customers/123");
        let policy: Value =
            serde_json::from_str(&recipe_to_policy_json(&recipe).expect("policy")).expect("json");
        assert_eq!(policy["requires_confirmation"], true);
    }
}

#[test]
fn package_export_creates_expected_files_without_raw_secrets() {
    let recipe = fake_recipe("POST", "https://api.stripe.com/v1/customers");
    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");

    for relative in [
        "recipe.yaml",
        "verified.lock.json",
        "skill.md",
        "policy.json",
        "mcp-server/package.json",
        "mcp-server/tsconfig.json",
        "mcp-server/src/server.ts",
        "mcp-server/README.md",
    ] {
        assert!(out.path().join(relative).exists(), "missing {relative}");
    }

    for content in read_all_files(out.path()) {
        assert!(!content.contains(RAW_SECRET));
    }
}

fn fake_recipe(method: &str, url_template: &str) -> Recipe {
    Recipe {
        id: None,
        name: "Stripe Create Customer".to_string(),
        method: method.to_string(),
        url_template: url_template.to_string(),
        headers_template: vec![HeaderField {
            key: "Authorization".to_string(),
            value: format!("Bearer {RAW_SECRET}"),
            required: true,
            description: String::new(),
            confidence: Confidence::High,
        }],
        query_template: Vec::new(),
        body_template: BodyTemplate::Json {
            template: r#"{"email":"{{email}}"}"#.to_string(),
        },
        auth_style: AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        },
        slots: vec![
            RuntimeSlot {
                name: "email".to_string(),
                location: SlotLocation::Body,
                required: true,
                current_value: Some("person@example.com".to_string()),
                description: "Customer email".to_string(),
                confidence: Confidence::High,
            },
            RuntimeSlot {
                name: "bearer_token".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: Some(RAW_SECRET.to_string()),
                description: String::new(),
                confidence: Confidence::High,
            },
        ],
        last_success_at: Some(verified_time()),
        last_success_status: Some(200),
    }
}

fn verified_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-04-29T00:00:00Z")
        .expect("time")
        .with_timezone(&Utc)
}

fn read_all_files(root: &Path) -> Vec<String> {
    let mut contents = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                contents.push(fs::read_to_string(path).expect("read file"));
            }
        }
    }
    contents
}
