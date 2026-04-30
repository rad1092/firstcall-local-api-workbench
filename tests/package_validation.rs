use std::fs;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_validation::validate_agent_package_dir;
use firstcall::model::Recipe;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_raw_secret_123";
const EXPECTED_MANIFEST_FILES: &[&str] = &[
    "recipe.yaml",
    "verified.lock.json",
    "skill.md",
    "policy.json",
    "mcp-server/package.json",
    "mcp-server/tsconfig.json",
    "mcp-server/src/server.ts",
    "mcp-server/README.md",
];

#[test]
fn validate_package_fixture_success() {
    let package = generate_package();
    let report = validate_agent_package_dir(package.path());

    assert!(report.is_valid(), "errors: {:?}", report.errors);
    assert!(
        report
            .checks_passed
            .iter()
            .any(|check| check.contains("recipe.yaml parses as YAML"))
    );
    assert!(
        report
            .checks_passed
            .iter()
            .any(|check| check.contains("verified.lock.json verified is true"))
    );
    assert!(
        report
            .checks_passed
            .iter()
            .any(|check| check.contains("manifest hash matches"))
    );
}

#[test]
fn cli_validate_package_success() {
    let package = generate_package();
    let output = validate_command()
        .args(["validate-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");

    assert!(output.status.success(), "{}", combined_output(&output));
    assert!(combined_output(&output).contains("Status: valid"));
}

#[test]
fn cli_validate_package_warnings_do_not_fail() {
    let package = generate_package();
    fs::write(package.path().join("notes.txt"), "extra local note").expect("write extra");

    let output = validate_command()
        .args(["validate-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");

    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Status: valid"));
    assert!(combined.contains("Warnings:"));
}

#[test]
fn export_creates_manifest_with_expected_files_and_hashes() {
    let package = generate_package();
    let manifest_text =
        fs::read_to_string(package.path().join("package.manifest.json")).expect("manifest");
    let manifest: Value = serde_json::from_str(&manifest_text).expect("manifest json");

    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["generator"], "firstcall");
    assert!(
        manifest["generated_at"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(!manifest_text.contains(RAW_SECRET));

    let files = manifest["files"].as_array().expect("manifest files");
    let paths = files
        .iter()
        .map(|entry| entry["path"].as_str().expect("path"))
        .collect::<Vec<_>>();
    assert_eq!(paths, EXPECTED_MANIFEST_FILES);
    assert!(!paths.contains(&"package.manifest.json"));

    for entry in files {
        let relative = entry["path"].as_str().expect("path");
        let sha256 = entry["sha256"].as_str().expect("sha256");
        assert!(is_sha256_hex(sha256), "bad sha256 for {relative}");
        assert_eq!(sha256, sha256_file(package.path().join(relative)));
    }
}

#[test]
fn validate_package_missing_manifest_warns_but_does_not_fail() {
    let package = generate_package();
    fs::remove_file(package.path().join("package.manifest.json")).expect("remove manifest");

    let report = validate_agent_package_dir(package.path());
    assert!(report.is_valid(), "errors: {:?}", report.errors);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("package.manifest.json missing"))
    );
}

#[test]
fn validate_package_missing_required_file_fails() {
    let package = generate_package();
    fs::remove_file(package.path().join("recipe.yaml")).expect("remove recipe");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("recipe.yaml"))
    );
}

#[test]
fn validate_package_hash_mismatch_fails_without_echoing_secret() {
    let package = generate_package();
    fs::write(package.path().join("skill.md"), "changed after manifest").expect("tamper skill");

    let report = validate_agent_package_dir(package.path());
    let errors = report.errors.join("\n");
    assert!(!report.is_valid());
    assert!(errors.contains("manifest hash mismatch: skill.md"));
    assert!(!errors.contains(RAW_SECRET));
}

#[test]
fn validate_package_manifest_missing_expected_entry_fails() {
    let package = generate_package();
    let manifest_path = package.path().join("package.manifest.json");
    let mut manifest = read_json(&manifest_path);
    let files = manifest["files"].as_array_mut().expect("files");
    files.retain(|entry| entry["path"] != "recipe.yaml");
    write_json(&manifest_path, &manifest);

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("manifest missing expected file: recipe.yaml"))
    );
}

#[test]
fn validate_package_unsafe_manifest_path_fails() {
    let package = generate_package();
    let manifest_path = package.path().join("package.manifest.json");
    let mut manifest = read_json(&manifest_path);
    manifest["files"]
        .as_array_mut()
        .expect("files")
        .push(json!({
            "path": "../evil.txt",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }));
    write_json(&manifest_path, &manifest);

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("manifest path is unsafe"))
    );
}

#[test]
fn validate_package_duplicate_manifest_path_fails() {
    let package = generate_package();
    let manifest_path = package.path().join("package.manifest.json");
    let mut manifest = read_json(&manifest_path);
    let duplicate = manifest["files"][0].clone();
    manifest["files"]
        .as_array_mut()
        .expect("files")
        .push(duplicate);
    write_json(&manifest_path, &manifest);

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("manifest duplicate path: recipe.yaml"))
    );
}

#[test]
fn validate_package_unverified_lock_fails() {
    let package = generate_package();
    let lock_path = package.path().join("verified.lock.json");
    let mut lock: Value = serde_json::from_str(&fs::read_to_string(&lock_path).expect("read lock"))
        .expect("parse lock");
    lock["verified"] = json!(false);
    fs::write(
        &lock_path,
        serde_json::to_string_pretty(&lock).expect("lock json"),
    )
    .expect("write lock");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("verified.lock.json verified must be true"))
    );
}

#[test]
fn validate_package_recipe_yaml_non_2xx_status_fails() {
    let package = generate_package();
    let recipe_path = package.path().join("recipe.yaml");
    let recipe_yaml = fs::read_to_string(&recipe_path).expect("read recipe yaml");
    fs::write(
        &recipe_path,
        recipe_yaml.replace("last_success_status: 200", "last_success_status: 500"),
    )
    .expect("tamper recipe yaml");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("recipe.yaml verified.last_success_status"))
    );
}

#[test]
fn validate_package_raw_secret_fails_without_echoing_secret() {
    let package = generate_package();
    fs::write(
        package.path().join("skill.md"),
        format!("leaked {RAW_SECRET}"),
    )
    .expect("inject secret");

    let report = validate_agent_package_dir(package.path());
    let errors = report.errors.join("\n");
    assert!(!report.is_valid());
    assert!(errors.contains("raw secret") || errors.contains("secret marker"));
    assert!(!errors.contains(RAW_SECRET));
}

#[test]
fn cli_validate_package_raw_secret_does_not_print_secret_value() {
    let package = generate_package();
    fs::write(
        package.path().join("mcp-server/src/server.ts"),
        format!("const token = \"Bearer {RAW_SECRET}\";"),
    )
    .expect("inject secret");

    let output = validate_command()
        .args(["validate-package", "--dir"])
        .arg(package.path())
        .output()
        .expect("run cli");
    let combined = combined_output(&output);

    assert!(!output.status.success());
    assert!(combined.contains("Status: invalid"));
    assert!(!combined.contains(RAW_SECRET));
}

#[test]
fn validate_package_percent_encoded_placeholder_fails() {
    let package = generate_package();
    fs::write(
        package.path().join("recipe.yaml"),
        "schema_version: 1\ngenerator: firstcall\nname: sample\nmethod: GET\nurl_template: https://api.example.com/%24%7Buser_id%7D\nauth: {}\nverified: {}\nsecurity:\n  secrets_stored: false\n  secret_source: env\n  redacted: true\n  environment_variables: []\n",
    )
    .expect("inject placeholder");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("percent-encoded placeholder"))
    );
}

#[test]
fn validate_package_mutating_policy_guard() {
    let package = generate_package();
    let policy_path = package.path().join("policy.json");
    let mut policy: Value =
        serde_json::from_str(&fs::read_to_string(&policy_path).expect("read policy"))
            .expect("parse policy");
    policy["allowed_methods"] = json!(["DELETE"]);
    policy["requires_confirmation"] = json!(false);
    fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).expect("policy json"),
    )
    .expect("write policy");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("requires_confirmation"))
    );
}

#[cfg(unix)]
#[test]
fn validate_package_symlink_required_file_fails() {
    use std::os::unix::fs::symlink;

    let package = generate_package();
    let recipe_path = package.path().join("recipe.yaml");
    fs::remove_file(&recipe_path).expect("remove recipe");
    symlink(package.path().join("skill.md"), &recipe_path).expect("symlink recipe");

    let report = validate_agent_package_dir(package.path());
    assert!(!report.is_valid());
    assert!(report.errors.iter().any(|error| error.contains("symlink")));
}

fn generate_package() -> TempDir {
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json"))
            .expect("fixture recipe");
    let dir = tempdir().expect("tempdir");
    export_agent_package(&recipe, dir.path()).expect("export package");
    dir
}

fn validate_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

fn write_json(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_string_pretty(value).expect("json")).expect("write json");
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn sha256_file(path: impl AsRef<std::path::Path>) -> String {
    let bytes = fs::read(path).expect("read bytes");
    let digest = Sha256::digest(&bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
