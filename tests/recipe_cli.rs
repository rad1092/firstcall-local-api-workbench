use std::path::PathBuf;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_import::import_agent_package_dir;
use firstcall::model::Recipe;
use firstcall::store::db::AppPaths;
use serde_json::Value;
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_raw_secret_123";

#[test]
fn recipe_list_human_output_shows_safe_imported_recipe() {
    let storage = import_fixture_package();

    let output = cli()
        .args(["recipe-list", "--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Mode: recipe-list"));
    assert!(combined.contains("example_update_user"));
    assert!(combined.contains("POST"));
    assert!(
        combined.contains("https://api.example.com/users/${user_id}?api_key=${FIRSTCALL_API_KEY}")
    );
    assert!(!combined.contains(RAW_SECRET));
    assert!(!combined.contains("current_value"));
    assert!(!combined.contains("user_123"));
}

#[test]
fn recipe_list_json_shows_safe_imported_recipe() {
    let storage = import_fixture_package();

    let output = cli()
        .args(["recipe-list", "--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["product"], "FirstCall Agent Recipes");
    assert_eq!(report["mode"], "recipe-list");
    let recipes = report["recipes"].as_array().expect("recipes");
    assert_eq!(recipes.len(), 1);
    let recipe = &recipes[0];
    assert!(recipe["id"].as_i64().is_some());
    assert_eq!(recipe["name"], "example_update_user");
    assert_eq!(recipe["method"], "POST");
    assert_eq!(recipe["requires_local_re_verification"], true);
    let url_template = recipe["url_template"].as_str().expect("url template");
    assert!(url_template.contains("${FIRSTCALL_API_KEY}"));
    assert!(!url_template.contains("{{FIRSTCALL_API_KEY}}"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn recipe_show_human_output_shows_slots_without_current_values() {
    let storage = import_fixture_package();

    let output = cli()
        .args(["recipe-show", "--id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Mode: recipe-show"));
    assert!(combined.contains("example_update_user"));
    assert!(combined.contains("user_id"));
    assert!(combined.contains("email"));
    assert!(!combined.contains("current_value"));
    assert!(!combined.contains("user_123"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn recipe_show_json_shows_slots_without_current_values() {
    let storage = import_fixture_package();

    let output = cli()
        .args(["recipe-show", "--id"])
        .arg(storage.recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["mode"], "recipe-show");
    let recipe = &report["recipe"];
    assert_eq!(recipe["id"], storage.recipe_id);
    assert_eq!(recipe["requires_local_re_verification"], true);
    let slots = recipe["slots"].as_array().expect("slots");
    assert!(!slots.is_empty());
    assert!(slots.iter().any(|slot| slot["name"] == "user_id"));
    assert!(slots.iter().all(|slot| slot.get("current_value").is_none()));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn recipe_show_json_missing_id_reports_not_found() {
    let storage = import_fixture_package();
    let missing_id = storage.recipe_id + 1000;

    let output = cli()
        .args(["recipe-show", "--id"])
        .arg(missing_id.to_string())
        .args(["--data-dir"])
        .arg(&storage.data_dir)
        .args(["--config-dir"])
        .arg(&storage.config_dir)
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "recipe-show");
    assert_eq!(report["status"], "not_found");
    assert!(report["recipe"].is_null());
    assert_eq!(report["recipe_id"], missing_id);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn recipe_storage_override_requires_data_and_config_dirs_together() {
    let temp = tempdir().expect("tempdir");

    let list_output = cli()
        .args(["recipe-list", "--data-dir"])
        .arg(temp.path().join("data"))
        .output()
        .expect("run cli");
    let list_combined = combined_output(&list_output);
    assert!(!list_output.status.success());
    assert!(list_combined.contains("--data-dir and --config-dir must be provided together"));
    assert!(!list_combined.contains(RAW_SECRET));

    let show_output = cli()
        .args(["recipe-show", "--id", "1", "--config-dir"])
        .arg(temp.path().join("config"))
        .output()
        .expect("run cli");
    let show_combined = combined_output(&show_output);
    assert!(!show_output.status.success());
    assert!(show_combined.contains("--data-dir and --config-dir must be provided together"));
    assert!(!show_combined.contains(RAW_SECRET));
}

#[test]
fn cli_help_includes_recipe_storage_usage_and_verify_json_boundary() {
    let output = cli().output().expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(
        combined.contains("firstcall-cli recipe-list [--data-dir PATH --config-dir PATH] [--json]")
    );
    assert!(combined.contains(
        "firstcall-cli recipe-show --id ID [--data-dir PATH --config-dir PATH] [--json]"
    ));
    assert!(combined.contains(
        "firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating]"
    ));
    assert!(combined.contains("firstcall-cli verify --recipe-json PATH [--allow-mutating] [--dry-run|--preflight] [--json]"));
    assert!(!combined.contains(RAW_SECRET));
}

struct ImportedStorage {
    _package: TempDir,
    _storage: TempDir,
    data_dir: PathBuf,
    config_dir: PathBuf,
    recipe_id: i64,
}

fn import_fixture_package() -> ImportedStorage {
    let package = generate_package();
    let storage = tempdir().expect("storage tempdir");
    let data_dir = storage.path().join("data");
    let config_dir = storage.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");
    let report = import_agent_package_dir(package.path(), &paths).expect("import report");
    assert!(report.imported(), "blockers: {:?}", report.blockers);
    let recipe_id = report.imported_recipe_id.expect("recipe id");
    ImportedStorage {
        _package: package,
        _storage: storage,
        data_dir,
        config_dir,
        recipe_id,
    }
}

fn generate_package() -> TempDir {
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json"))
            .expect("fixture recipe");
    let dir = tempdir().expect("tempdir");
    export_agent_package(&recipe, dir.path()).expect("export package");
    dir
}

fn cli() -> Command {
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
