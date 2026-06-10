use std::fs;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_inspect::inspect_agent_package_dir;
use firstcall::export::package_validation::validate_agent_package_dir;
use firstcall::model::Recipe;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_raw_secret_123";

#[test]
fn inspect_package_valid_generated_package_is_ready() {
    let package = generate_package();

    let report = inspect_agent_package_dir(package.path());

    assert!(report.is_ready(), "blockers: {:?}", report.blockers);
    assert!(
        report.validation.is_valid(),
        "errors: {:?}",
        report.validation.errors
    );
    assert!(report.manifest_present);
}

#[test]
fn inspect_package_missing_manifest_blocks_even_when_validate_warns_only() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");

    let validation = validate_agent_package_dir(package.path());
    let report = inspect_agent_package_dir(package.path());

    assert!(validation.is_valid(), "errors: {:?}", validation.errors);
    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("package.manifest.json"))
    );
}

#[test]
fn cli_inspect_package_prints_static_safety_fields() {
    let package = generate_package();
    let output = inspect_command()
        .args(["inspect-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Import readiness: ready"));
    assert!(combined.contains("Would import: no"));
    assert!(combined.contains("Would execute HTTP: no"));
    assert!(combined.contains("Would write files: no"));
    assert!(combined.contains("Would modify app storage: no"));
    assert!(combined.contains("Requires local re-verification: yes"));
    assert!(combined.contains("Raw secrets imported: no"));
    assert!(combined.contains("Generated MCP server source of truth: no"));
    assert!(combined.contains("Request fingerprint recomputation: matched"));
}

#[test]
fn cli_inspect_package_json_ready_report() {
    let package = generate_package();
    let output = inspect_command()
        .args(["inspect-package", "--dir"])
        .arg(package.path())
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(output.status.success(), "{}", combined_output(&output));
    assert_eq!(report["product"], "FirstCall Agent Recipes");
    assert_eq!(report["mode"], "inspect-package");
    assert_eq!(report["import_readiness"], "ready");
    assert_eq!(report["would_import"], false);
    assert_eq!(report["would_execute_http"], false);
    assert_eq!(report["would_modify_app_storage"], false);
    assert_eq!(report["requires_local_re_verification"], true);
    assert_eq!(report["generated_mcp_server_source_of_truth"], false);
    assert_eq!(report["request_fingerprint_recomputation"], "matched");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn cli_help_includes_inspect_package_usage() {
    let output = inspect_command().output().expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("firstcall-cli inspect-package --dir PATH"));
}

#[test]
fn inspect_package_policy_method_mismatch_blocks() {
    let package = generate_package();
    edit_policy(package.path(), |policy| {
        policy["allowed_methods"] = json!(["GET"]);
    });

    let report = inspect_agent_package_dir(package.path());

    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("method"))
    );
}

#[test]
fn inspect_package_policy_host_mismatch_blocks() {
    let package = generate_package();
    edit_policy(package.path(), |policy| {
        policy["allowed_hosts"] = json!(["api.other.example"]);
    });

    let report = inspect_agent_package_dir(package.path());

    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("host"))
    );
}

#[test]
fn inspect_package_policy_path_mismatch_blocks() {
    let package = generate_package();
    edit_policy(package.path(), |policy| {
        policy["allowed_paths"] = json!(["/accounts/slot"]);
    });

    let report = inspect_agent_package_dir(package.path());

    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("path"))
    );
}

#[test]
fn inspect_package_unverified_or_non_2xx_lock_blocks() {
    let package = generate_package();
    edit_json_file(package.path(), "verified.lock.json", |lock| {
        lock["verified"] = json!(false);
        lock["last_success_status"] = json!(500);
    });

    let report = inspect_agent_package_dir(package.path());

    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("verified.lock.json"))
    );
}

#[test]
fn inspect_package_invalid_request_fingerprint_blocks() {
    let package = generate_package();
    edit_json_file(package.path(), "verified.lock.json", |lock| {
        lock["request_fingerprint"] = json!("not-a-sha");
    });

    let report = inspect_agent_package_dir(package.path());

    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("request_fingerprint"))
    );
}

#[test]
fn inspect_package_recipe_tamper_blocks_on_recomputed_fingerprint() {
    let package = generate_package();
    edit_recipe_yaml(package.path(), |recipe| {
        recipe["name"] = Value::String("tampered_recipe".to_string());
    });

    let report = inspect_agent_package_dir(package.path());

    assert_eq!(report.request_fingerprint_status.as_str(), "mismatched");
    assert!(!report.is_ready());
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("request_fingerprint"))
    );
}

#[test]
fn cli_inspect_package_missing_manifest_reports_legacy_blocked() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");

    let output = inspect_command()
        .args(["inspect-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("Manifest: missing"));
    assert!(combined.contains("Legacy package: yes"));
    assert!(combined.contains("Import readiness: blocked"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn cli_inspect_package_json_missing_manifest_blocks() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");

    let output = inspect_command()
        .args(["inspect-package", "--dir"])
        .arg(package.path())
        .args(["--json"])
        .output()
        .expect("run cli");
    let report = stdout_json(&output);

    assert!(!output.status.success());
    assert_eq!(report["mode"], "inspect-package");
    assert_eq!(report["import_readiness"], "blocked");
    assert_eq!(report["manifest"], "missing");
    assert_eq!(report["legacy_package"], true);
    assert!(
        !report["import_readiness_blockers"]
            .as_array()
            .expect("blockers")
            .is_empty()
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(RAW_SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RAW_SECRET));
}

#[test]
fn cli_inspect_package_raw_secret_validation_error_does_not_echo_secret() {
    let package = generate_package();
    fs::write(
        package.path().join("skill.md"),
        format!("agent note leaked {RAW_SECRET}"),
    )
    .expect("write leaked skill");

    let output = inspect_command()
        .args(["inspect-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("Import readiness: blocked"));
    assert!(combined.contains("raw secret") || combined.contains("secret marker"));
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

fn inspect_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn edit_policy(root: &std::path::Path, edit: impl FnOnce(&mut Value)) {
    edit_json_file(root, "policy.json", edit);
}

fn edit_json_file(root: &std::path::Path, relative: &str, edit: impl FnOnce(&mut Value)) {
    let path = root.join(relative);
    let mut value = read_json(&path);
    edit(&mut value);
    fs::write(&path, serde_json::to_string_pretty(&value).expect("json")).expect("write json");
    refresh_manifest_hash(root, relative);
}

fn edit_recipe_yaml(root: &std::path::Path, edit: impl FnOnce(&mut Value)) {
    let path = root.join("recipe.yaml");
    let mut value: Value =
        yaml_serde::from_str(&fs::read_to_string(&path).expect("read recipe yaml"))
            .expect("parse recipe yaml");
    edit(&mut value);
    fs::write(&path, yaml_serde::to_string(&value).expect("recipe yaml")).expect("write yaml");
    refresh_manifest_hash(root, "recipe.yaml");
}

fn refresh_manifest_hash(root: &std::path::Path, relative: &str) {
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

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

fn sha256_file(path: impl AsRef<std::path::Path>) -> String {
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
