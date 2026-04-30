use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::{DateTime, Utc};
use firstcall::export::agent_package::{export_agent_package, is_agent_export_eligible};
use firstcall::export::agent_yaml::recipe_to_agent_yaml;
use firstcall::export::policy::recipe_to_policy_json;
use firstcall::export::verified_lock::recipe_to_verified_lock_json;
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, KeyValueField, Recipe, RuntimeSlot,
    SlotLocation,
};
use serde_json::Value;
use tempfile::tempdir;

const RAW_SECRET: &str = "sk_test_raw_secret_123";
const RAW_QUERY_SECRET: &str = "raw_secret_123";
const RAW_BASIC_USERNAME: &str = "raw_basic_username";
const RAW_BASIC_PASSWORD: &str = "raw_basic_password";

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
    assert!(yaml.contains("FIRSTCALL_BEARER_TOKEN"));
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

#[test]
fn url_placeholders_are_normalized_in_agent_artifacts() {
    let recipe = fake_recipe("POST", "https://api.example.com/users/{{user_id}}");
    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");

    let yaml = fs::read_to_string(out.path().join("recipe.yaml")).expect("yaml");
    let skill = fs::read_to_string(out.path().join("skill.md")).expect("skill");
    let server = fs::read_to_string(out.path().join("mcp-server/src/server.ts")).expect("server");
    let combined = read_all_files(out.path()).join("\n");

    assert!(yaml.contains("${user_id}"));
    assert!(skill.contains("https://api.example.com/users/${user_id}"));
    assert!(server.contains("${user_id}"));
    assert!(!combined.contains("{{user_id}}"));
    assert!(!combined.contains("%24%7Buser_id%7D"));
}

#[test]
fn url_secret_query_params_are_sanitized_without_percent_encoded_placeholders() {
    let mut recipe = fake_recipe(
        "GET",
        &format!("https://api.example.com/search?api_key={RAW_QUERY_SECRET}&q={{{{query}}}}"),
    );
    recipe.slots.push(RuntimeSlot {
        name: "query".to_string(),
        location: SlotLocation::Query,
        required: true,
        current_value: Some("alice".to_string()),
        description: "Search query".to_string(),
        confidence: Confidence::High,
    });
    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");
    let combined = read_all_files(out.path()).join("\n");

    assert!(!combined.contains(RAW_QUERY_SECRET));
    assert!(combined.contains("${FIRSTCALL_API_KEY}"));
    assert!(combined.contains("${query}"));
    assert!(!combined.contains("%24%7BFIRSTCALL_API_KEY%7D"));
    assert!(!combined.contains("%24%7Bquery%7D"));
}

#[test]
fn query_template_secret_params_are_sanitized_without_percent_encoded_placeholders() {
    let mut recipe = fake_recipe("GET", "https://api.example.com/search?q={{query}}");
    recipe.query_template.push(KeyValueField {
        key: "api_key".to_string(),
        value: RAW_QUERY_SECRET.to_string(),
        required: true,
        description: "API key query parameter".to_string(),
        confidence: Confidence::High,
    });
    recipe.slots.push(RuntimeSlot {
        name: "query".to_string(),
        location: SlotLocation::Query,
        required: true,
        current_value: Some("alice".to_string()),
        description: "Search query".to_string(),
        confidence: Confidence::High,
    });

    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");
    let combined = read_all_files(out.path()).join("\n");

    assert!(!combined.contains(RAW_QUERY_SECRET));
    assert!(combined.contains("${FIRSTCALL_API_KEY}"));
    assert!(!combined.contains("%24%7BFIRSTCALL_API_KEY%7D"));
}

#[test]
fn basic_auth_generated_server_encodes_env_credentials() {
    let recipe = basic_auth_recipe();
    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");
    let yaml = fs::read_to_string(out.path().join("recipe.yaml")).expect("yaml");
    let server = fs::read_to_string(out.path().join("mcp-server/src/server.ts")).expect("server");
    let combined = read_all_files(out.path()).join("\n");

    assert!(yaml.contains("type: basic"));
    assert!(yaml.contains("username_env: FIRSTCALL_USERNAME"));
    assert!(yaml.contains("password_env: FIRSTCALL_PASSWORD"));
    assert!(!yaml.contains("Basic ${FIRSTCALL_USERNAME}:${FIRSTCALL_PASSWORD}"));
    assert!(server.contains("Buffer.from"));
    assert!(server.contains("base64"));
    assert!(server.contains("FIRSTCALL_USERNAME"));
    assert!(server.contains("FIRSTCALL_PASSWORD"));
    assert!(
        !server
            .contains("\"Authorization\": \"Basic ${FIRSTCALL_USERNAME}:${FIRSTCALL_PASSWORD}\"")
    );
    assert!(!combined.contains(RAW_BASIC_USERNAME));
    assert!(!combined.contains(RAW_BASIC_PASSWORD));
}

#[test]
fn generated_server_template_has_stricter_types_and_header_defaulting() {
    let recipe = fake_recipe("POST", "https://api.example.com/users/{{user_id}}");
    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");
    let server = fs::read_to_string(out.path().join("mcp-server/src/server.ts")).expect("server");

    assert!(server.contains("type ToolArgs"));
    assert!(server.contains("Record<string, string>"));
    assert!(server.contains("RequestInit"));
    assert!(server.contains("setDefaultHeader"));
}

#[test]
fn cli_explain_fixture_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
        .args([
            "explain",
            "--recipe-json",
            "fixtures/verified-agent-recipe.json",
        ])
        .output()
        .expect("run cli");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("Eligible for agent export: true"));
}

#[test]
fn cli_explain_sanitizes_url_template_secrets() {
    let mut recipe = fake_recipe(
        "GET",
        &format!("https://api.example.com/search?api_key={RAW_QUERY_SECRET}&q={{{{query}}}}"),
    );
    recipe.slots.push(RuntimeSlot {
        name: "query".to_string(),
        location: SlotLocation::Query,
        required: true,
        current_value: Some("alice".to_string()),
        description: "Search query".to_string(),
        confidence: Confidence::High,
    });
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    fs::write(
        &recipe_path,
        serde_json::to_string_pretty(&recipe).expect("serialize recipe"),
    )
    .expect("write recipe");

    let output = Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
        .args([
            "explain",
            "--recipe-json",
            recipe_path.to_str().expect("recipe path"),
        ])
        .output()
        .expect("run cli");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(!stdout.contains(RAW_QUERY_SECRET));
    assert!(stdout.contains("${FIRSTCALL_API_KEY}"));
    assert!(stdout.contains("${query}"));
    assert!(!stdout.contains("%24%7BFIRSTCALL_API_KEY%7D"));
    assert!(!stdout.contains("%24%7Bquery%7D"));
}

#[test]
fn cli_package_fixture_creates_agent_package() {
    let out = tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
        .args([
            "package",
            "--recipe-json",
            "fixtures/verified-agent-recipe.json",
            "--out",
            out.path().to_str().expect("temp path"),
        ])
        .output()
        .expect("run cli");

    assert!(output.status.success());
    assert!(out.path().join("recipe.yaml").exists());
    assert!(out.path().join("mcp-server/src/server.ts").exists());
}

#[test]
fn text_only_golden_agent_package_uses_safe_templates() {
    let mut recipe = basic_auth_recipe();
    recipe.url_template =
        format!("https://api.example.com/users/{{{{user_id}}}}?api_key={RAW_QUERY_SECRET}");
    recipe.body_template = BodyTemplate::Json {
        template: r#"{"email":"{{email}}"}"#.to_string(),
    };
    recipe.slots.push(RuntimeSlot {
        name: "email".to_string(),
        location: SlotLocation::Body,
        required: true,
        current_value: Some("person@example.com".to_string()),
        description: "Customer email".to_string(),
        confidence: Confidence::High,
    });

    let out = tempdir().expect("tempdir");
    export_agent_package(&recipe, out.path()).expect("export");

    let yaml = fs::read_to_string(out.path().join("recipe.yaml")).expect("yaml");
    let skill = fs::read_to_string(out.path().join("skill.md")).expect("skill");
    let lock = fs::read_to_string(out.path().join("verified.lock.json")).expect("lock");
    let server = fs::read_to_string(out.path().join("mcp-server/src/server.ts")).expect("server");
    let readme = fs::read_to_string(out.path().join("mcp-server/README.md")).expect("readme");
    let combined = read_all_files(out.path()).join("\n");

    assert!(yaml.contains("${user_id}"));
    assert!(yaml.contains("${email}"));
    assert!(yaml.contains("${FIRSTCALL_API_KEY}"));
    assert!(
        skill.contains("https://api.example.com/users/${user_id}?api_key=${FIRSTCALL_API_KEY}")
    );
    assert!(!lock.contains(RAW_QUERY_SECRET));
    assert!(server.contains("type ToolArgs"));
    assert!(server.contains("RequestInit"));
    assert!(server.contains("setDefaultHeader"));
    assert!(server.contains("Buffer.from"));
    assert!(readme.contains("FIRSTCALL_API_KEY"));

    for secret in [
        RAW_SECRET,
        RAW_QUERY_SECRET,
        RAW_BASIC_USERNAME,
        RAW_BASIC_PASSWORD,
    ] {
        assert!(!combined.contains(secret), "leaked {secret}");
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
                name: "user_id".to_string(),
                location: SlotLocation::Path,
                required: true,
                current_value: Some("user_123".to_string()),
                description: "User identifier".to_string(),
                confidence: Confidence::High,
            },
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

fn basic_auth_recipe() -> Recipe {
    let mut recipe = fake_recipe("GET", "https://api.example.com/users/{{user_id}}");
    recipe.headers_template.clear();
    recipe.body_template = BodyTemplate::None;
    recipe.auth_style = AuthStyle::Basic {
        username_slot: "username".to_string(),
        password_slot: "password".to_string(),
    };
    recipe.slots = vec![
        RuntimeSlot {
            name: "user_id".to_string(),
            location: SlotLocation::Path,
            required: true,
            current_value: Some("user_123".to_string()),
            description: "User identifier".to_string(),
            confidence: Confidence::High,
        },
        RuntimeSlot {
            name: "username".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: Some(RAW_BASIC_USERNAME.to_string()),
            description: String::new(),
            confidence: Confidence::High,
        },
        RuntimeSlot {
            name: "password".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: Some(RAW_BASIC_PASSWORD.to_string()),
            description: String::new(),
            confidence: Confidence::High,
        },
    ];
    recipe
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
