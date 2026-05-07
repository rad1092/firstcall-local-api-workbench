use std::fs;
use std::path::PathBuf;
use std::process::Command;

use chrono::{DateTime, Utc};
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, Recipe, RuntimeSlot, SlotLocation,
};
use firstcall::store::db::{AppPaths, open_database};
use firstcall::store::repos::AppRepository;
use serde_json::Value;
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
fn verify_dry_run_json_reports_ready_without_network() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["product"], "FirstCall Agent Recipes");
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["recipe"], "Verify User");
    assert_eq!(report["method"], "GET");
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["preflight_status"], "ready");
    assert!(
        report["required_env"]
            .as_array()
            .expect("required env")
            .is_empty()
    );
    assert!(
        !report["required_slots"]
            .as_array()
            .expect("required slots")
            .is_empty()
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn verify_recipe_json_actual_json_reports_transport_failure() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--json"])
        .output()
        .expect("run cli");
    let combined = combined_output(&output);
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout json");

    assert!(!output.status.success());
    assert_eq!(report["mode"], "verify");
    assert_eq!(report["source"], "recipe-json");
    assert_eq!(report["success"], false);
    assert_eq!(report["wrote_recipe"], false);
    assert_eq!(report["wrote_lock"], false);
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn cli_help_includes_recipe_id_verify_usage() {
    let output = verify_command().output().expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains(
        "firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating]"
    ));
    assert!(combined.contains(
        "firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--dry-run|--preflight] [--json]"
    ));
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
fn verify_preflight_json_reports_ready_without_network() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--preflight", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["preflight_status"], "ready");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
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
fn verify_dry_run_json_missing_auth_env_reports_without_secret_leak() {
    let recipe = bearer_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run", "--json"])
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["preflight_status"], "blocked");
    assert!(
        report["required_env"]
            .as_array()
            .expect("required env")
            .iter()
            .any(|item| item["name"] == "FIRSTCALL_BEARER_TOKEN" && item["status"] == "missing")
    );
    assert!(!report["blockers"].as_array().expect("blockers").is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn verify_dry_run_json_set_auth_env_does_not_print_value() {
    let recipe = bearer_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run", "--json"])
        .env("FIRSTCALL_BEARER_TOKEN", RAW_SECRET)
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["preflight_status"], "ready");
    assert!(
        report["required_env"]
            .as_array()
            .expect("required env")
            .iter()
            .any(|item| item["name"] == "FIRSTCALL_BEARER_TOKEN" && item["status"] == "set")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
    assert!(!report.to_string().contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_dry_run_ready_from_storage() {
    let storage = store_recipe(&no_auth_recipe("GET"));

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run"])
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Mode: dry-run"));
    assert!(combined.contains("Preflight status: ready"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_dry_run_json_ready_from_storage() {
    let storage = store_recipe(&no_auth_recipe("GET"));

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["recipe_id"], storage.recipe_id);
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["preflight_status"], "ready");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_preflight_json_alias_from_storage() {
    let storage = store_recipe(&no_auth_recipe("GET"));

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--preflight", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["recipe_id"], storage.recipe_id);
    assert_eq!(report["would_execute_http"], false);
}

#[test]
fn verify_recipe_id_dry_run_json_blocks_on_missing_env() {
    let storage = store_recipe(&bearer_recipe("GET"));

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run", "--json"])
        .env_remove("FIRSTCALL_BEARER_TOKEN")
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["recipe_id"], storage.recipe_id);
    assert_eq!(report["preflight_status"], "blocked");
    assert_eq!(report["would_execute_http"], false);
    assert!(
        report["required_env"]
            .as_array()
            .expect("required env")
            .iter()
            .any(|item| item["name"] == "FIRSTCALL_BEARER_TOKEN" && item["status"] == "missing")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
    assert!(!report.to_string().contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_dry_run_json_set_env_does_not_print_value() {
    let storage = store_recipe(&bearer_recipe("GET"));

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run", "--json"])
        .env("FIRSTCALL_BEARER_TOKEN", RAW_SECRET)
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success());
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["recipe_id"], storage.recipe_id);
    assert_eq!(report["preflight_status"], "ready");
    assert_eq!(report["would_execute_http"], false);
    assert!(
        report["required_env"]
            .as_array()
            .expect("required env")
            .iter()
            .any(|item| item["name"] == "FIRSTCALL_BEARER_TOKEN" && item["status"] == "set")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
    assert!(!report.to_string().contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_missing_storage_json_reports_not_found_without_creating_db() {
    let storage = fresh_storage_paths();
    let recipe_id = 42;

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["status"], "not_found");
    assert!(report["recipe"].is_null());
    assert_eq!(report["recipe_id"], recipe_id);
    assert_eq!(report["would_execute_http"], false);
    assert!(!storage.paths.db_path.exists());
    assert!(!storage.data_dir.exists());
    assert!(!storage.config_dir.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_missing_storage_human_reports_not_found_without_creating_db() {
    let storage = fresh_storage_paths();
    let recipe_id = 42;

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run"])
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("Status: not_found") || combined.contains("recipe not found"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(!storage.paths.db_path.exists());
    assert!(!storage.data_dir.exists());
    assert!(!storage.config_dir.exists());
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn verify_recipe_id_missing_id_json_reports_not_found() {
    let storage = store_recipe(&no_auth_recipe("GET"));
    let missing_id = storage.recipe_id + 1000;

    let output = verify_command()
        .args(["verify", "--recipe-id"])
        .arg(missing_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--dry-run", "--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["source"], "recipe-id");
    assert_eq!(report["status"], "not_found");
    assert!(report["recipe"].is_null());
    assert_eq!(report["recipe_id"], missing_id);
    assert_eq!(report["would_execute_http"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn verify_input_source_validation_for_recipe_id() {
    let recipe = no_auth_recipe("GET");
    let (_dir, recipe_path) = write_recipe(&recipe);
    let temp = tempdir().expect("tempdir");

    let neither_output = verify_command()
        .args(["verify", "--dry-run"])
        .output()
        .expect("run cli");
    let neither_combined = combined_output(&neither_output);
    assert!(!neither_output.status.success());
    assert!(neither_combined.contains("exactly one of --recipe-json or --recipe-id is required"));
    assert!(!neither_combined.contains(RAW_SECRET));

    let both_output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--recipe-id", "1", "--dry-run"])
        .output()
        .expect("run cli");
    let both_combined = combined_output(&both_output);
    assert!(!both_output.status.success());
    assert!(both_combined.contains("provide only one of --recipe-json or --recipe-id"));
    assert!(!both_combined.contains(RAW_SECRET));

    let json_actual_output = verify_command()
        .args(["verify", "--recipe-id", "1", "--json", "--data-dir"])
        .arg(temp.path().join("missing-data"))
        .args(["--config-dir"])
        .arg(temp.path().join("missing-config"))
        .output()
        .expect("run cli");
    let json_actual_combined = combined_output(&json_actual_output);
    let json_actual_report: Value =
        serde_json::from_slice(&json_actual_output.stdout).expect("stdout json");
    assert!(!json_actual_output.status.success());
    assert_eq!(json_actual_report["mode"], "verify");
    assert_eq!(json_actual_report["source"], "recipe-id");
    assert_eq!(json_actual_report["status"], "not_found");
    assert_eq!(json_actual_report["would_execute_http"], false);
    assert!(!json_actual_combined.contains(RAW_SECRET));

    let data_only_output = verify_command()
        .args(["verify", "--recipe-id", "1", "--data-dir"])
        .arg(temp.path().join("data"))
        .args(["--dry-run"])
        .output()
        .expect("run cli");
    let data_only_combined = combined_output(&data_only_output);
    assert!(!data_only_output.status.success());
    assert!(data_only_combined.contains("--data-dir and --config-dir must be provided together"));
    assert!(!data_only_combined.contains(RAW_SECRET));

    let config_only_output = verify_command()
        .args(["verify", "--recipe-id", "1", "--config-dir"])
        .arg(temp.path().join("config"))
        .args(["--dry-run"])
        .output()
        .expect("run cli");
    let config_only_combined = combined_output(&config_only_output);
    assert!(!config_only_output.status.success());
    assert!(config_only_combined.contains("--data-dir and --config-dir must be provided together"));
    assert!(!config_only_combined.contains(RAW_SECRET));
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

struct StoredRecipe {
    _root: TempDir,
    data_dir: PathBuf,
    config_dir: PathBuf,
    recipe_id: i64,
}

struct FreshStorage {
    _root: TempDir,
    data_dir: PathBuf,
    config_dir: PathBuf,
    paths: AppPaths,
}

fn store_recipe(recipe: &Recipe) -> StoredRecipe {
    let root = tempdir().expect("tempdir");
    let data_dir = root.path().join("data");
    let config_dir = root.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");
    let repository = AppRepository::new(open_database(&paths).expect("db"));
    let recipe_id = repository.insert_recipe(recipe).expect("insert recipe");
    StoredRecipe {
        _root: root,
        data_dir,
        config_dir,
        recipe_id,
    }
}

fn fresh_storage_paths() -> FreshStorage {
    let root = tempdir().expect("tempdir");
    let data_dir = root.path().join("data");
    let config_dir = root.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");
    FreshStorage {
        _root: root,
        data_dir,
        config_dir,
        paths,
    }
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

fn stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout json")
}

fn verified_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-04-29T00:00:00Z")
        .expect("time")
        .with_timezone(&Utc)
}
