use std::fs;
use std::path::Path;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_import::import_agent_package_dir;
use firstcall::model::{AuthStyle, BodyTemplate, Recipe};
use firstcall::store::db::{AppPaths, open_database};
use firstcall::store::repos::AppRepository;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_raw_secret_123";

#[test]
fn cli_import_package_imports_recipe_into_temp_sqlite() {
    let package = generate_package();
    let storage = tempdir().expect("storage tempdir");
    let data_dir = storage.path().join("data");
    let config_dir = storage.path().join("config");

    let output = import_command()
        .args(["import-package", "--dir"])
        .arg(package.path())
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["--config-dir"])
        .arg(&config_dir)
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Import status: imported"));
    assert!(combined.contains("App storage modified: yes"));
    assert!(combined.contains("Requires local re-verification: yes"));
    assert!(combined.contains("Secrets imported: no"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(combined.contains("Generated MCP server source of truth: no"));
    assert!(!combined.contains(RAW_SECRET));

    let imported = single_imported_recipe(&data_dir, &config_dir);
    assert_eq!(imported.name, "example_update_user");
    assert_eq!(imported.method, "POST");
    assert_eq!(
        imported.url_template,
        "https://api.example.com/users/{{user_id}}?api_key=${FIRSTCALL_API_KEY}"
    );
    assert!(imported.url_template.contains("${FIRSTCALL_API_KEY}"));
    assert!(!imported.url_template.contains("{{FIRSTCALL_API_KEY}}"));
    assert!(imported.url_template.contains("{{user_id}}"));
    assert_eq!(imported.last_success_at, None);
    assert_eq!(imported.last_success_status, None);
    assert!(
        imported
            .slots
            .iter()
            .all(|slot| slot.current_value.is_none())
    );
    assert!(imported.slots.iter().any(|slot| slot.name == "user_id"));
    assert!(imported.slots.iter().any(|slot| slot.name == "email"));
    assert!(matches!(imported.auth_style, AuthStyle::Bearer { .. }));
    assert_eq!(imported.headers_template.len(), 1);
    assert_eq!(imported.headers_template[0].key, "Content-Type");
    match &imported.body_template {
        BodyTemplate::Json { template } => assert_eq!(template, r#"{"email":"{{email}}"}"#),
        other => panic!("unexpected body template: {other:?}"),
    }
    assert!(
        !serde_json::to_string(&imported)
            .expect("recipe json")
            .contains(RAW_SECRET)
    );
}

#[test]
fn cli_help_includes_import_package_usage() {
    let output = import_command().output().expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(
        combined.contains(
            "firstcall-cli import-package --dir PATH [--data-dir PATH --config-dir PATH]"
        )
    );
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn missing_manifest_blocks_import_before_sqlite_write() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");
    let storage = tempdir().expect("storage tempdir");
    let data_dir = storage.path().join("data");
    let config_dir = storage.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(!report.imported());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("manifest"))
    );
    assert!(
        !paths.db_path.exists(),
        "blocked import should not create sqlite database"
    );
}

#[test]
fn cli_missing_manifest_blocks_without_sqlite_write() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");
    let storage = tempdir().expect("storage tempdir");
    let data_dir = storage.path().join("data");
    let config_dir = storage.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");

    let output = import_command()
        .args(["import-package", "--dir"])
        .arg(package.path())
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["--config-dir"])
        .arg(&config_dir)
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("Import status: blocked"));
    assert!(combined.contains("App storage modified: no"));
    assert!(combined.contains("package import blocked"));
    assert!(!combined.contains(RAW_SECRET));
    assert!(!paths.db_path.exists());
}

#[test]
fn malformed_recipe_yaml_blocks_import_without_sqlite_write() {
    let package = generate_package();
    fs::write(package.path().join("recipe.yaml"), ":\n:").expect("write malformed yaml");
    refresh_manifest_hash(package.path(), "recipe.yaml");
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");
    let debug = format!("{report:?}");

    assert!(!report.imported());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("recipe.yaml") || blocker.contains("conversion"))
    );
    assert!(!paths.db_path.exists());
    assert!(!debug.contains(RAW_SECRET));
}

#[test]
fn unsupported_auth_type_blocks_import_without_sqlite_write() {
    let package = generate_package();
    edit_recipe_yaml(package.path(), |recipe| {
        recipe["auth"]["type"] = Value::String("oauth_magic".to_string());
    });
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");
    let debug = format!("{report:?}");

    assert!(!report.imported());
    assert!(report.blockers.iter().any(|blocker| {
        blocker.contains("auth type is not supported")
            || blocker.contains("package recipe conversion failed")
    }));
    assert!(!paths.db_path.exists());
    assert!(!debug.contains(RAW_SECRET));
}

#[test]
fn recipe_policy_mismatch_blocks_import() {
    let package = generate_package();
    edit_json_file(package.path(), "policy.json", |policy| {
        policy["allowed_hosts"] = json!(["api.other.example"]);
    });
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(!report.imported());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("host"))
    );
    assert!(!paths.db_path.exists());
}

#[test]
fn invalid_request_fingerprint_blocks_import() {
    let package = generate_package();
    edit_json_file(package.path(), "verified.lock.json", |lock| {
        lock["request_fingerprint"] = json!("not-a-sha");
    });
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(!report.imported());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("request_fingerprint"))
    );
    assert!(!paths.db_path.exists());
}

#[test]
fn generated_mcp_tamper_with_refreshed_manifest_is_not_source_of_truth() {
    let package = generate_package();
    let server_path = package.path().join("mcp-server/src/server.ts");
    let mut server = fs::read_to_string(&server_path).expect("read server");
    server.push_str("\n// tampered generated artifact; recipe.yaml remains source of truth\n");
    fs::write(&server_path, server).expect("write server");
    refresh_manifest_hash(package.path(), "mcp-server/src/server.ts");

    let storage = tempdir().expect("storage tempdir");
    let data_dir = storage.path().join("data");
    let config_dir = storage.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");
    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(report.imported(), "blockers: {:?}", report.blockers);
    let imported = single_imported_recipe(&data_dir, &config_dir);
    assert_eq!(
        imported.url_template,
        "https://api.example.com/users/{{user_id}}?api_key=${FIRSTCALL_API_KEY}"
    );
}

#[test]
fn generated_mcp_tamper_manifest_mismatch_blocks_import() {
    let package = generate_package();
    fs::write(
        package.path().join("mcp-server/src/server.ts"),
        "tampered generated artifact",
    )
    .expect("write server");
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(!report.imported());
    assert!(!paths.db_path.exists());
    assert!(
        report
            .inspect_report
            .validation
            .errors
            .iter()
            .any(|error| error.contains("manifest hash mismatch"))
    );
}

#[test]
fn cli_import_requires_both_storage_override_dirs() {
    let package = generate_package();
    let storage = tempdir().expect("storage tempdir");

    let output = import_command()
        .args(["import-package", "--dir"])
        .arg(package.path())
        .args(["--data-dir"])
        .arg(storage.path().join("data"))
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("--data-dir and --config-dir must be provided together"));
    assert!(!combined.contains(RAW_SECRET));
}

fn generate_package() -> TempDir {
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json"))
            .expect("fixture recipe");
    let dir = tempdir().expect("tempdir");
    export_agent_package(&recipe, dir.path()).expect("export package");
    dir
}

fn import_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn single_imported_recipe(data_dir: &Path, config_dir: &Path) -> Recipe {
    let paths = AppPaths::from_root(data_dir, config_dir).expect("paths");
    let repository = AppRepository::new(open_database(&paths).expect("database"));
    let recipes = repository.list_recipes().expect("list recipes");
    assert_eq!(recipes.len(), 1);
    repository
        .get_recipe(recipes[0].id)
        .expect("get recipe")
        .expect("recipe")
}

fn edit_json_file(root: &Path, relative: &str, edit: impl FnOnce(&mut Value)) {
    let path = root.join(relative);
    let mut value = read_json(&path);
    edit(&mut value);
    fs::write(&path, serde_json::to_string_pretty(&value).expect("json")).expect("write json");
    refresh_manifest_hash(root, relative);
}

fn edit_recipe_yaml(root: &Path, edit: impl FnOnce(&mut Value)) {
    let path = root.join("recipe.yaml");
    let mut value: Value =
        yaml_serde::from_str(&fs::read_to_string(&path).expect("read recipe yaml"))
            .expect("parse recipe yaml");
    edit(&mut value);
    fs::write(&path, yaml_serde::to_string(&value).expect("recipe yaml")).expect("write yaml");
    refresh_manifest_hash(root, "recipe.yaml");
}

fn refresh_manifest_hash(root: &Path, relative: &str) {
    let manifest_path = root.join("package.manifest.json");
    let mut manifest = read_json(&manifest_path);
    let sha256 = sha256_file(root.join(relative));
    let files = manifest["files"].as_array_mut().expect("manifest files");
    let entry = files
        .iter_mut()
        .find(|entry| entry["path"] == relative)
        .expect("manifest entry");
    entry["sha256"] = json!(sha256);
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

fn sha256_file(path: impl AsRef<Path>) -> String {
    let bytes = fs::read(path).expect("read bytes");
    let digest = Sha256::digest(&bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
