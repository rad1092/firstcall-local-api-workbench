use std::fs;
use std::path::Path;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_import::import_agent_package_dir;
use firstcall::model::{AuthStyle, BodyTemplate, Confidence, KeyValueField, Recipe, SchemaSpec};
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
fn cli_import_package_json_imports_recipe_into_temp_sqlite() {
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
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["product"], "FirstCall Agent Recipes");
    assert_eq!(report["mode"], "import-package");
    assert_eq!(report["import_status"], "imported");
    assert!(report["imported_recipe_id"].as_i64().is_some());
    assert_eq!(report["app_storage_modified"], true);
    assert_eq!(report["requires_local_re_verification"], true);
    assert_eq!(report["secrets_imported"], false);
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["generated_mcp_server_source_of_truth"], false);
    assert_eq!(report["import_readiness"], "ready");
    assert!(
        report["url_template"]
            .as_str()
            .expect("url template")
            .contains("${FIRSTCALL_API_KEY}")
    );
    assert!(
        !report["url_template"]
            .as_str()
            .expect("url template")
            .contains("{{FIRSTCALL_API_KEY}}")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));

    let imported = single_imported_recipe(&data_dir, &config_dir);
    assert_eq!(imported.last_success_at, None);
    assert_eq!(imported.last_success_status, None);
}

#[test]
fn import_preserves_sanitized_response_schema_but_clears_verification() {
    let mut recipe = fixture_recipe();
    recipe.response_schema = Some(SchemaSpec {
        name: Some("response".to_string()),
        schema: json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "string" },
                "token": {
                    "type": "string",
                    "default": "must_not_be_exported",
                    "enum": ["must_not_be_exported"]
                }
            }
        }),
    });
    let package = package_for_recipe(&recipe);
    let storage = tempdir().expect("storage tempdir");

    let imported = import_single_recipe(package.path(), storage.path());

    assert!(imported.last_success_at.is_none());
    assert!(imported.last_success_status.is_none());
    let schema = imported.response_schema.expect("response schema");
    let serialized = serde_json::to_string(&schema).expect("schema json");
    assert!(serialized.contains("\"id\""));
    assert!(!serialized.contains("must_not_be_exported"));
}

#[test]
fn import_preserves_text_and_form_body_kinds() {
    let mut text_recipe = fixture_recipe();
    text_recipe.body_template = BodyTemplate::Text {
        text: "message={{email}}".to_string(),
    };
    let text_package = package_for_recipe(&text_recipe);
    let text_storage = tempdir().expect("text storage");
    let text_imported = import_single_recipe(text_package.path(), text_storage.path());
    match &text_imported.body_template {
        BodyTemplate::Text { text } => assert_eq!(text, "message={{email}}"),
        other => panic!("unexpected text body import: {other:?}"),
    }

    let mut form_recipe = fixture_recipe();
    form_recipe.body_template = BodyTemplate::Form {
        fields: vec![KeyValueField {
            key: "email".to_string(),
            value: "{{email}}".to_string(),
            required: true,
            description: "Email".to_string(),
            confidence: Confidence::High,
        }],
    };
    let form_package = package_for_recipe(&form_recipe);
    let form_storage = tempdir().expect("form storage");
    let form_imported = import_single_recipe(form_package.path(), form_storage.path());
    match &form_imported.body_template {
        BodyTemplate::Form { fields } => {
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].key, "email");
            assert_eq!(fields[0].value, "{{email}}");
        }
        other => panic!("unexpected form body import: {other:?}"),
    }
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
fn policy_v2_missing_npm_lock_and_manifest_entry_blocks_import() {
    let package = generate_package();
    fs::remove_file(package.path().join("mcp-server/package-lock.json"))
        .expect("remove package lock");
    let manifest_path = package.path().join("package.manifest.json");
    let mut manifest = read_json(&manifest_path);
    manifest["files"]
        .as_array_mut()
        .expect("manifest files")
        .retain(|entry| entry["path"] != "mcp-server/package-lock.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");
    let storage = tempdir().expect("storage tempdir");
    let paths = AppPaths::from_root(&storage.path().join("data"), &storage.path().join("config"))
        .expect("paths");

    let report = import_agent_package_dir(package.path(), &paths).expect("import report");

    assert!(!report.imported());
    assert!(
        report
            .inspect_report
            .validation
            .errors
            .iter()
            .any(|error| error.contains("package-lock.json"))
    );
    assert!(!paths.db_path.exists());
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
fn cli_import_package_json_missing_manifest_blocks_without_sqlite_write() {
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
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "import-package");
    assert_eq!(report["import_status"], "blocked");
    assert_eq!(report["app_storage_modified"], false);
    assert!(report["imported_recipe_id"].is_null());
    assert!(
        !report["import_blockers"]
            .as_array()
            .expect("blockers")
            .is_empty()
    );
    assert!(!paths.db_path.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
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
        blocker.contains("package validation has errors")
            || blocker.contains("package recipe conversion failed")
    }));
    assert!(
        report
            .inspect_report
            .validation
            .errors
            .iter()
            .any(|error| error.contains("auth type is not supported"))
    );
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
    package_for_recipe(&fixture_recipe())
}

fn fixture_recipe() -> Recipe {
    serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json"))
        .expect("fixture recipe")
}

fn package_for_recipe(recipe: &Recipe) -> TempDir {
    let dir = tempdir().expect("tempdir");
    export_agent_package(recipe, dir.path()).expect("export package");
    dir
}

fn import_single_recipe(package_dir: &Path, storage_root: &Path) -> Recipe {
    let data_dir = storage_root.join("data");
    let config_dir = storage_root.join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");
    let report = import_agent_package_dir(package_dir, &paths).expect("import report");
    assert!(report.imported(), "blockers: {:?}", report.blockers);
    single_imported_recipe(&data_dir, &config_dir)
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

fn stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout json")
}
