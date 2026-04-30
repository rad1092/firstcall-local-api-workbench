use std::fs;
use std::process::Command;

use chrono::{DateTime, Utc};
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, Recipe, RuntimeSlot, SlotLocation,
};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_verify_raw_secret";

#[test]
fn verify_missing_auth_env_fails_before_network() {
    let recipe = bearer_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let combined = combined_output(&output);
    assert!(combined.contains("FIRSTCALL_BEARER_TOKEN"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_missing_non_auth_slot_env_fails_before_network() {
    let mut recipe = bearer_recipe("GET");
    recipe.auth_style = AuthStyle::None;
    recipe.headers_template.clear();
    recipe
        .slots
        .retain(|slot| slot.location != SlotLocation::Auth);
    recipe.slots[0].current_value = None;
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .env_remove("FIRSTCALL_SLOT_USER_ID")
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let combined = combined_output(&output);
    assert!(combined.contains("FIRSTCALL_SLOT_USER_ID"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_output_paths_are_not_written_on_preflight_failure() {
    let recipe = bearer_recipe("GET");
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    fs::write(
        &recipe_path,
        serde_json::to_string_pretty(&recipe).expect("recipe json"),
    )
    .expect("write recipe");

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    assert!(!out_path.exists());
    assert!(!lock_path.exists());
    assert!(!combined_output(&output).contains(RAW_SECRET));
}

#[test]
fn verify_mutating_method_requires_explicit_flag_before_env_resolution() {
    let recipe = bearer_recipe("POST");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let combined = combined_output(&output);
    assert!(combined.contains("--allow-mutating"));
    assert!(!combined.contains("FIRSTCALL_BEARER_TOKEN"));
    assert!(!combined.contains(RAW_SECRET));
}

fn bearer_recipe(method: &str) -> Recipe {
    Recipe {
        id: None,
        name: "Verify User".to_string(),
        method: method.to_string(),
        url_template: "https://api.example.com/users/{{user_id}}".to_string(),
        headers_template: vec![HeaderField {
            key: "Authorization".to_string(),
            value: format!("Bearer {RAW_SECRET}"),
            required: true,
            description: String::new(),
            confidence: Confidence::High,
        }],
        query_template: Vec::new(),
        body_template: BodyTemplate::None,
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
                description: String::new(),
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

fn write_recipe(recipe: &Recipe) -> (TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("recipe.json");
    fs::write(
        &path,
        serde_json::to_string_pretty(recipe).expect("recipe json"),
    )
    .expect("write recipe");
    (dir, path)
}

fn verify_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn verified_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-04-29T00:00:00Z")
        .expect("time")
        .with_timezone(&Utc)
}
