use std::fs;
use std::process::Command;

use firstcall::export::agent_package::export_agent_package;
use firstcall::export::package_validation::validate_agent_package_dir;
use firstcall::model::Recipe;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const RAW_SECRET: &str = "sk_test_raw_secret_123";

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
