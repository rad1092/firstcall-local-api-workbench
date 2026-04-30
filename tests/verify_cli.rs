use std::fs;
use std::process::Command;

use chrono::{DateTime, Utc};
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, Recipe, RuntimeSlot, SlotLocation,
};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_verify_raw_secret";
const ENV_SECRET_MARKER: &str = "user_123_secretish_for_test";

#[test]
fn verify_dry_run_alias_reports_ready_without_network() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Mode: dry-run"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(combined.contains("Preflight status: ready"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_preflight_alias_reports_ready_without_network() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--preflight"])
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Mode: dry-run"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(combined.contains("Preflight status: ready"));
}

#[test]
fn verify_dry_run_rejects_output_paths_without_writing() {
    let recipe = no_auth_recipe("GET");
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
        .args(["--dry-run", "--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(!output.status.success());
    assert!(combined.contains("dry-run/preflight cannot write output files"));
    assert!(!out_path.exists());
    assert!(!lock_path.exists());
}

#[test]
fn verify_dry_run_missing_auth_env_reports_without_secret_leak() {
    let recipe = bearer_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(!output.status.success());
    assert!(combined.contains("FIRSTCALL_BEARER_TOKEN"));
    assert!(combined.contains("missing"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_dry_run_missing_required_slot_env_reports() {
    let mut recipe = no_auth_recipe("GET");
    recipe.slots[0].current_value = None;
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .env_remove("FIRSTCALL_SLOT_USER_ID")
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(!output.status.success());
    assert!(combined.contains("FIRSTCALL_SLOT_USER_ID"));
    assert!(combined.contains("missing"));
}

#[test]
fn verify_dry_run_slot_env_set_does_not_print_value() {
    let mut recipe = no_auth_recipe("GET");
    recipe.slots[0].current_value = None;
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .env("FIRSTCALL_SLOT_USER_ID", ENV_SECRET_MARKER)
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("FIRSTCALL_SLOT_USER_ID: set"));
    assert!(combined.contains("user_id (path, required): env"));
    assert!(!combined.contains(ENV_SECRET_MARKER));
}

#[test]
fn verify_dry_run_mutating_method_requires_allow_flag() {
    let recipe = no_auth_recipe("POST");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(!output.status.success());
    assert!(combined.contains("mutating method"));
    assert!(combined.contains("--allow-mutating"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_dry_run_mutating_method_with_allow_flag_can_be_ready() {
    let recipe = no_auth_recipe("POST");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run", "--allow-mutating"])
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Allow mutating: yes"));
    assert!(combined.contains("Preflight status: ready"));
    assert!(combined.contains("Would execute HTTP: no"));
}

#[test]
fn verify_dry_run_body_redacted_value_blocks_without_printing_body() {
    let mut recipe = no_auth_recipe("GET");
    recipe.body_template = BodyTemplate::Json {
        template: r#"{"password":"<redacted>"}"#.to_string(),
    };
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(!output.status.success());
    assert!(combined.contains("body template contains redacted values"));
    assert!(!combined.contains("password"));
}

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

fn no_auth_recipe(method: &str) -> Recipe {
    Recipe {
        id: None,
        name: "Verify User".to_string(),
        method: method.to_string(),
        url_template: "https://127.0.0.1:9/users/{{user_id}}".to_string(),
        headers_template: Vec::new(),
        query_template: Vec::new(),
        body_template: BodyTemplate::None,
        auth_style: AuthStyle::None,
        slots: vec![RuntimeSlot {
            name: "user_id".to_string(),
            location: SlotLocation::Path,
            required: true,
            current_value: Some("user_123".to_string()),
            description: String::new(),
            confidence: Confidence::High,
        }],
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
