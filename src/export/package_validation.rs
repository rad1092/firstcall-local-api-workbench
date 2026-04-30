use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use regex::Regex;
use serde_json::Value;

use super::agent_common::{GENERATOR, looks_destructive_path};
use super::package_manifest::{MANIFEST_FILE, MANIFESTED_FILES, sha256_file_hex};

const REQUIRED_DIRS: &[&str] = &["mcp-server", "mcp-server/src"];

const RAW_SECRET_MARKERS: &[&str] = &[
    "sk_test_raw_secret_123",
    "raw_secret_123",
    "raw_basic_username",
    "raw_basic_password",
    "sk_test_verify_raw_secret",
];

#[derive(Clone, Debug)]
pub struct PackageValidationReport {
    pub package_dir: PathBuf,
    pub checks_passed: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl PackageValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    fn pass(&mut self, message: impl Into<String>) {
        self.checks_passed.push(message.into());
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    fn error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }
}

pub fn validate_agent_package_dir(path: &Path) -> PackageValidationReport {
    let mut report = PackageValidationReport {
        package_dir: path.to_path_buf(),
        checks_passed: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    if !validate_package_root(path, &mut report) {
        return report;
    }

    validate_required_layout(path, &mut report);
    validate_extra_entries(path, &mut report);
    scan_expected_text_files(path, &mut report);
    validate_recipe_yaml(path, &mut report);
    validate_verified_lock(path, &mut report);
    validate_policy(path, &mut report);
    validate_mcp_server(path, &mut report);
    validate_package_json(path, &mut report);
    validate_tsconfig_json(path, &mut report);
    validate_package_manifest(path, &mut report);

    report
}

fn validate_package_root(path: &Path, report: &mut PackageValidationReport) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            report.error("package directory must not be a symlink");
            false
        }
        Ok(metadata) if metadata.is_dir() => {
            report.pass("package directory exists");
            true
        }
        Ok(_) => {
            report.error("package path is not a directory");
            false
        }
        Err(_) => {
            report.error("package directory does not exist");
            false
        }
    }
}

fn validate_required_layout(root: &Path, report: &mut PackageValidationReport) {
    for relative in REQUIRED_DIRS {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                report.error(format!("required directory is a symlink: {relative}"));
            }
            Ok(metadata) if metadata.is_dir() => {
                report.pass(format!("required directory exists: {relative}"));
            }
            Ok(metadata) if metadata.is_file() => {
                report.error(format!("required directory is a file: {relative}"));
            }
            Ok(_) => {
                report.error(format!(
                    "required directory has unsupported type: {relative}"
                ));
            }
            Err(_) => {
                report.error(format!("missing required directory: {relative}"));
            }
        }
    }

    for relative in MANIFESTED_FILES {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                report.error(format!("required file is a symlink: {relative}"));
            }
            Ok(metadata) if metadata.is_file() => {
                report.pass(format!("required file exists: {relative}"));
            }
            Ok(metadata) if metadata.is_dir() => {
                report.error(format!("required file is a directory: {relative}"));
            }
            Ok(_) => {
                report.error(format!("required file has unsupported type: {relative}"));
            }
            Err(_) => {
                report.error(format!("missing required file: {relative}"));
            }
        }
    }
}

fn validate_extra_entries(root: &Path, report: &mut PackageValidationReport) {
    warn_extra_entries(
        root,
        "",
        &[
            "recipe.yaml",
            "verified.lock.json",
            "skill.md",
            "policy.json",
            MANIFEST_FILE,
            "mcp-server",
        ],
        report,
    );
    warn_extra_entries(
        root,
        "mcp-server",
        &["package.json", "tsconfig.json", "README.md", "src"],
        report,
    );
    warn_extra_entries(root, "mcp-server/src", &["server.ts"], report);
}

fn warn_extra_entries(
    root: &Path,
    relative_dir: &str,
    expected_names: &[&str],
    report: &mut PackageValidationReport,
) {
    let dir = if relative_dir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative_dir)
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    let expected = expected_names.iter().copied().collect::<BTreeSet<_>>();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if expected.contains(name.as_str()) {
            continue;
        }
        let display = join_relative(relative_dir, &name);
        if matches!(name.as_str(), "node_modules" | "dist") {
            report.warn(format!("skipping generated directory: {display}"));
        } else {
            report.warn(format!("extra package entry: {display}"));
        }
    }
}

fn validate_recipe_yaml(root: &Path, report: &mut PackageValidationReport) {
    let Some(text) = read_expected_text(root, "recipe.yaml", report) else {
        return;
    };
    let value = match yaml_serde::from_str::<Value>(&text) {
        Ok(value) => value,
        Err(_) => {
            report.error("recipe.yaml is not valid YAML");
            return;
        }
    };
    let Some(object) = value.as_object() else {
        report.error("recipe.yaml root must be a mapping");
        return;
    };
    report.pass("recipe.yaml parses as YAML");

    check_u64_field(report, &value, "recipe.yaml", "schema_version", 1);
    check_string_field(report, &value, "recipe.yaml", "generator", Some(GENERATOR));

    for field in ["name", "method", "url_template"] {
        check_required_string(report, &value, "recipe.yaml", field);
    }
    for field in ["auth", "verified", "security"] {
        if object.contains_key(field) {
            report.pass(format!("recipe.yaml contains {field}"));
        } else {
            report.error(format!("recipe.yaml missing required field: {field}"));
        }
    }

    validate_recipe_method(&value, report);
    validate_recipe_url_template(&value, report);
    validate_recipe_verified(&value, report);
    validate_recipe_security(&value, report);
    validate_recipe_executable_redaction(&value, report);
    scan_structured_secretish_values(report, "recipe.yaml", &value);
}

fn validate_recipe_method(value: &Value, report: &mut PackageValidationReport) {
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return;
    };
    let trimmed = method.trim();
    if trimmed.is_empty() {
        report.error("recipe.yaml method must not be empty");
    } else if trimmed
        .chars()
        .all(|character| character.is_ascii_alphabetic())
    {
        report.pass("recipe.yaml method normalizes cleanly");
        if trimmed != trimmed.to_ascii_uppercase() {
            report.warn("recipe.yaml method is not uppercase");
        }
    } else {
        report.error("recipe.yaml method must be an HTTP method token");
    }
}

fn validate_recipe_url_template(value: &Value, report: &mut PackageValidationReport) {
    let Some(url_template) = value.get("url_template").and_then(Value::as_str) else {
        return;
    };
    if url_template.contains("<redacted>") {
        report.error("recipe.yaml url_template contains executable redacted value");
    } else {
        report.pass("recipe.yaml url_template has no redacted executable value");
    }
    if contains_percent_encoded_placeholder(url_template) {
        report.error("recipe.yaml url_template contains percent-encoded placeholder");
    } else {
        report.pass("recipe.yaml url_template placeholders are readable");
    }
}

fn validate_recipe_verified(value: &Value, report: &mut PackageValidationReport) {
    let Some(verified) = value.get("verified").and_then(Value::as_object) else {
        return;
    };
    match verified.get("last_success_at").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && value != "unverified" => {
            report.pass("recipe.yaml verified.last_success_at is present");
        }
        _ => report.error("recipe.yaml verified.last_success_at must be verified"),
    }
    match verified.get("last_success_status").and_then(Value::as_u64) {
        Some(200..=299) => report.pass("recipe.yaml verified.last_success_status is successful"),
        _ => report.error("recipe.yaml verified.last_success_status must be 200..=299"),
    }
}

fn validate_recipe_security(value: &Value, report: &mut PackageValidationReport) {
    let Some(security) = value.get("security").and_then(Value::as_object) else {
        return;
    };
    match security.get("secrets_stored").and_then(Value::as_bool) {
        Some(false) => report.pass("recipe.yaml security.secrets_stored is false"),
        _ => report.error("recipe.yaml security.secrets_stored must be false"),
    }
    match security.get("secret_source").and_then(Value::as_str) {
        Some("env") => report.pass("recipe.yaml security.secret_source is env"),
        _ => report.error("recipe.yaml security.secret_source must be env"),
    }
    match security.get("redacted").and_then(Value::as_bool) {
        Some(true) => report.pass("recipe.yaml security.redacted is true"),
        _ => report.error("recipe.yaml security.redacted must be true"),
    }
    match security
        .get("environment_variables")
        .and_then(Value::as_array)
    {
        Some(_) => report.pass("recipe.yaml security.environment_variables exists"),
        None => report.error("recipe.yaml security.environment_variables must exist"),
    }
}

fn validate_recipe_executable_redaction(value: &Value, report: &mut PackageValidationReport) {
    for field in ["headers", "query", "body_template"] {
        if value.get(field).is_some_and(value_contains_redacted) {
            report.error(format!(
                "recipe.yaml {field} contains executable redacted value"
            ));
        }
    }
}

fn validate_verified_lock(root: &Path, report: &mut PackageValidationReport) {
    let Some(value) = read_json(root, "verified.lock.json", report) else {
        return;
    };
    report.pass("verified.lock.json parses as JSON");

    check_u64_field(report, &value, "verified.lock.json", "schema_version", 1);
    check_string_field(
        report,
        &value,
        "verified.lock.json",
        "generator",
        Some(GENERATOR),
    );
    match value.get("verified").and_then(Value::as_bool) {
        Some(true) => report.pass("verified.lock.json verified is true"),
        _ => report.error("verified.lock.json verified must be true"),
    }
    check_required_string(report, &value, "verified.lock.json", "recipe_name");
    match value.get("last_success_at").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && value != "unverified" => {
            report.pass("verified.lock.json last_success_at is present");
        }
        _ => report.error("verified.lock.json last_success_at must be verified"),
    }
    match value.get("last_success_status").and_then(Value::as_u64) {
        Some(200..=299) => report.pass("verified.lock.json status is successful"),
        _ => report.error("verified.lock.json last_success_status must be 200..=299"),
    }
    for field in ["request_fingerprint", "response_schema_fingerprint"] {
        match value.get(field).and_then(Value::as_str) {
            Some(value) if is_sha256_hex(value) => {
                report.pass(format!("verified.lock.json {field} is SHA-256-shaped"));
            }
            _ => report.error(format!(
                "verified.lock.json {field} must be 64-character lowercase hex"
            )),
        }
    }
    if value.get("redaction_policy_version").is_some() {
        report.pass("verified.lock.json redaction_policy_version is present");
    } else {
        report.error("verified.lock.json redaction_policy_version is required");
    }
}

fn validate_policy(root: &Path, report: &mut PackageValidationReport) {
    let Some(value) = read_json(root, "policy.json", report) else {
        return;
    };
    report.pass("policy.json parses as JSON");

    check_u64_field(report, &value, "policy.json", "schema_version", 1);
    let methods = check_non_empty_string_array(report, &value, "policy.json", "allowed_methods");
    check_non_empty_string_array(report, &value, "policy.json", "allowed_hosts");
    let paths = check_non_empty_string_array(report, &value, "policy.json", "allowed_paths");
    let secret_headers = check_string_array(report, &value, "policy.json", "secret_headers");
    let secret_query_keys = check_string_array(report, &value, "policy.json", "secret_query_keys");
    let redact_response_keys =
        check_string_array(report, &value, "policy.json", "redact_response_keys");

    let requires_confirmation = match value.get("requires_confirmation").and_then(Value::as_bool) {
        Some(value) => {
            report.pass("policy.json requires_confirmation is boolean");
            Some(value)
        }
        None => {
            report.error("policy.json requires_confirmation must be boolean");
            None
        }
    };

    if let Some(headers) = secret_headers {
        if headers
            .iter()
            .any(|header| header.eq_ignore_ascii_case("authorization"))
        {
            report.pass("policy.json covers Authorization as a secret header");
        } else {
            report.warn("policy.json secret_headers should include Authorization");
        }
    }
    if let Some(keys) = secret_query_keys {
        for key in [
            "api_key",
            "token",
            "secret",
            "access_token",
            "refresh_token",
        ] {
            if keys.iter().any(|item| item.eq_ignore_ascii_case(key)) {
                report.pass(format!("policy.json covers secret query key: {key}"));
            } else {
                report.warn(format!(
                    "policy.json secret_query_keys should include {key}"
                ));
            }
        }
    }
    if let Some(keys) = redact_response_keys {
        for key in ["token", "secret", "password", "api_key"] {
            if keys.iter().any(|item| item.eq_ignore_ascii_case(key)) {
                report.pass(format!("policy.json redacts response key: {key}"));
            } else {
                report.warn(format!(
                    "policy.json redact_response_keys should include {key}"
                ));
            }
        }
    }

    if let (Some(methods), Some(requires_confirmation)) = (&methods, requires_confirmation) {
        let has_guarded_mutation = methods.iter().any(|method| {
            matches!(
                method.to_ascii_uppercase().as_str(),
                "DELETE" | "PUT" | "PATCH"
            )
        });
        if has_guarded_mutation && !requires_confirmation {
            report.error("policy.json mutating methods require requires_confirmation true");
        }
        if methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case("POST"))
            && !requires_confirmation
            && paths
                .as_ref()
                .is_some_and(|paths| paths.iter().any(|path| looks_destructive_path(path)))
        {
            report.error("policy.json destructive POST paths require confirmation");
        }
    }
}

fn validate_mcp_server(root: &Path, report: &mut PackageValidationReport) {
    let Some(text) = read_expected_text(root, "mcp-server/src/server.ts", report) else {
        return;
    };
    for marker in [
        "McpServer",
        "StdioServerTransport",
        "server.tool",
        "ToolArgs",
        "RequestInit",
        "setDefaultHeader",
        "applyAuth",
    ] {
        if text.contains(marker) {
            report.pass(format!("mcp-server/src/server.ts contains {marker}"));
        } else {
            report.error(format!("mcp-server/src/server.ts missing {marker}"));
        }
    }
    if contains_percent_encoded_placeholder(&text) {
        report.error("mcp-server/src/server.ts contains percent-encoded placeholder");
    }
    validate_tool_name(&text, report);
}

fn validate_tool_name(text: &str, report: &mut PackageValidationReport) {
    let regex = Regex::new(r#"const TOOL_NAME\s*=\s*"([^"]+)""#).expect("valid tool name regex");
    let Some(captures) = regex.captures(text) else {
        report.warn("could not extract generated MCP tool name");
        return;
    };
    let tool_name = captures.get(1).map_or("", |capture| capture.as_str());
    if (1..=128).contains(&tool_name.len())
        && tool_name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        report.pass("generated MCP tool name is valid");
    } else {
        report.error("generated MCP tool name must be 1..=128 safe ASCII characters");
    }
}

fn validate_package_json(root: &Path, report: &mut PackageValidationReport) {
    let Some(value) = read_json(root, "mcp-server/package.json", report) else {
        return;
    };
    report.pass("mcp-server/package.json parses as JSON");
    check_required_string(report, &value, "mcp-server/package.json", "name");
    check_string_field(
        report,
        &value,
        "mcp-server/package.json",
        "type",
        Some("module"),
    );
    check_nested_string(
        report,
        &value,
        "mcp-server/package.json",
        &["scripts", "build"],
    );
    check_nested_string(
        report,
        &value,
        "mcp-server/package.json",
        &["scripts", "start"],
    );
    check_object_contains(
        report,
        &value,
        "mcp-server/package.json",
        "dependencies",
        "@modelcontextprotocol/sdk",
    );
    check_object_contains(
        report,
        &value,
        "mcp-server/package.json",
        "dependencies",
        "zod",
    );
    check_object_contains(
        report,
        &value,
        "mcp-server/package.json",
        "devDependencies",
        "typescript",
    );
    check_object_contains(
        report,
        &value,
        "mcp-server/package.json",
        "devDependencies",
        "@types/node",
    );
}

fn validate_tsconfig_json(root: &Path, report: &mut PackageValidationReport) {
    let Some(value) = read_json(root, "mcp-server/tsconfig.json", report) else {
        return;
    };
    report.pass("mcp-server/tsconfig.json parses as JSON");
    let Some(options) = value.get("compilerOptions").and_then(Value::as_object) else {
        report.error("mcp-server/tsconfig.json compilerOptions must exist");
        return;
    };
    report.pass("mcp-server/tsconfig.json compilerOptions exists");

    let node_next = options
        .get("module")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "NodeNext")
        || options
            .get("moduleResolution")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "NodeNext");
    if node_next {
        report.pass("mcp-server/tsconfig.json uses NodeNext");
    } else {
        report.error("mcp-server/tsconfig.json module or moduleResolution should be NodeNext");
    }
    for field in ["outDir", "rootDir"] {
        match options.get(field).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => {
                report.pass(format!("mcp-server/tsconfig.json {field} exists"));
            }
            _ => report.error(format!("mcp-server/tsconfig.json {field} must exist")),
        }
    }
}

fn validate_package_manifest(root: &Path, report: &mut PackageValidationReport) {
    let manifest_path = root.join(MANIFEST_FILE);
    match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            report.error(format!("{MANIFEST_FILE} must not be a symlink"));
            return;
        }
        Ok(metadata) if metadata.is_file() => {}
        Ok(metadata) if metadata.is_dir() => {
            report.error(format!("{MANIFEST_FILE} must be a regular file"));
            return;
        }
        Ok(_) => {
            report.error(format!("{MANIFEST_FILE} has unsupported file type"));
            return;
        }
        Err(_) => {
            report.warn(format!("{MANIFEST_FILE} missing; integrity check skipped"));
            return;
        }
    }

    let Some(value) = read_json(root, MANIFEST_FILE, report) else {
        return;
    };
    report.pass(format!("{MANIFEST_FILE} parses as JSON"));
    check_u64_field(report, &value, MANIFEST_FILE, "schema_version", 1);
    check_string_field(report, &value, MANIFEST_FILE, "generator", Some(GENERATOR));
    validate_manifest_generated_at(&value, report);
    validate_manifest_files(root, &value, report);
}

fn validate_manifest_generated_at(value: &Value, report: &mut PackageValidationReport) {
    match value.get("generated_at").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && DateTime::parse_from_rfc3339(value).is_ok() => {
            report.pass(format!("{MANIFEST_FILE} generated_at is RFC3339"));
        }
        Some(value) if !value.trim().is_empty() => {
            report.error(format!("{MANIFEST_FILE} generated_at must be RFC3339"));
        }
        _ => report.error(format!("{MANIFEST_FILE} generated_at must be present")),
    }
}

fn validate_manifest_files(root: &Path, value: &Value, report: &mut PackageValidationReport) {
    let Some(files) = value.get("files").and_then(Value::as_array) else {
        report.error(format!("{MANIFEST_FILE} files must be an array"));
        return;
    };
    if files.is_empty() {
        report.error(format!("{MANIFEST_FILE} files must not be empty"));
        return;
    }
    report.pass(format!("{MANIFEST_FILE} files is non-empty"));

    let mut entries = BTreeMap::<String, String>::new();
    let mut duplicate_paths = BTreeSet::<String>::new();
    for item in files {
        let Some(object) = item.as_object() else {
            report.error(format!("{MANIFEST_FILE} file entries must be objects"));
            continue;
        };
        let Some(path) = object.get("path").and_then(Value::as_str) else {
            report.error(format!("{MANIFEST_FILE} file entry path must be a string"));
            continue;
        };
        let Some(sha256) = object.get("sha256").and_then(Value::as_str) else {
            report.error(format!(
                "{MANIFEST_FILE} file entry sha256 must be a string: {path}"
            ));
            continue;
        };
        if !is_safe_manifest_path(path) {
            report.error(format!("manifest path is unsafe: {path}"));
            continue;
        }
        if !is_sha256_hex(sha256) {
            report.error(format!("manifest sha256 must be lowercase hex: {path}"));
            continue;
        }
        if entries
            .insert(path.to_string(), sha256.to_string())
            .is_some()
        {
            duplicate_paths.insert(path.to_string());
        }
    }
    for path in duplicate_paths {
        report.error(format!("manifest duplicate path: {path}"));
    }

    for expected in MANIFESTED_FILES {
        if entries.contains_key(*expected) {
            report.pass(format!("manifest includes expected file: {expected}"));
        } else {
            report.error(format!("manifest missing expected file: {expected}"));
        }
    }

    for (relative, expected_sha256) in entries {
        validate_manifest_file_hash(root, &relative, &expected_sha256, report);
    }
}

fn validate_manifest_file_hash(
    root: &Path,
    relative: &str,
    expected_sha256: &str,
    report: &mut PackageValidationReport,
) {
    let target = root.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            report.error(format!("manifest target is a symlink: {relative}"));
            return;
        }
        Ok(metadata) if metadata.is_file() => {}
        Ok(metadata) if metadata.is_dir() => {
            report.error(format!("manifest target is a directory: {relative}"));
            return;
        }
        Ok(_) => {
            report.error(format!("manifest target has unsupported type: {relative}"));
            return;
        }
        Err(_) => {
            report.error(format!("manifest target missing: {relative}"));
            return;
        }
    }

    let Ok(actual_sha256) = sha256_file_hex(&target) else {
        report.error(format!("manifest target could not be read: {relative}"));
        return;
    };
    if actual_sha256 == expected_sha256 {
        if MANIFESTED_FILES.contains(&relative) {
            report.pass(format!("manifest hash matches: {relative}"));
        } else {
            report.warn(format!("manifest includes unexpected file: {relative}"));
        }
    } else {
        report.error(format!("manifest hash mismatch: {relative}"));
    }
}

fn scan_expected_text_files(root: &Path, report: &mut PackageValidationReport) {
    for relative in MANIFESTED_FILES {
        let Some(text) = read_expected_text(root, relative, report) else {
            continue;
        };
        scan_text_for_secrets(report, relative, &text);
    }
    if let Some(text) = read_expected_text(root, MANIFEST_FILE, report) {
        scan_text_for_secrets(report, MANIFEST_FILE, &text);
    }
}

fn scan_text_for_secrets(report: &mut PackageValidationReport, relative: &str, text: &str) {
    for marker in RAW_SECRET_MARKERS {
        if text.contains(marker) {
            report.error(format!("known raw secret marker found in {relative}"));
        }
    }
    if contains_percent_encoded_placeholder(text) {
        report.error(format!("percent-encoded placeholder found in {relative}"));
    }

    let bearer_regex =
        Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{8,})").expect("valid bearer regex");
    for captures in bearer_regex.captures_iter(text) {
        let value = captures.get(1).map_or("", |capture| capture.as_str());
        if !is_safe_secret_reference(value) {
            report.error(format!("raw bearer-like token found in {relative}"));
        }
    }

    let key_value_regex =
        Regex::new(r#"(?i)\b(api_key|access_token|password)\b\s*[=:]\s*["']?([^&\s"',]+)"#)
            .expect("valid secret key-value regex");
    for captures in key_value_regex.captures_iter(text) {
        let key = captures.get(1).map_or("secret", |capture| capture.as_str());
        let value = captures.get(2).map_or("", |capture| capture.as_str());
        if !is_safe_secret_reference(value) {
            report.error(format!(
                "raw {}-like value found in {relative}",
                key.to_ascii_lowercase()
            ));
        }
    }
}

fn scan_structured_secretish_values(
    report: &mut PackageValidationReport,
    relative: &str,
    value: &Value,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if let Some(text) = value.as_str()
                    && is_secretish_key(key)
                    && !is_safe_secret_reference(text)
                {
                    report.error(format!(
                        "raw {}-like value found in {relative}",
                        secret_category(key)
                    ));
                }
                scan_structured_secretish_values(report, relative, value);
            }
        }
        Value::Array(items) => {
            for item in items {
                scan_structured_secretish_values(report, relative, item);
            }
        }
        _ => {}
    }
}

fn read_json(root: &Path, relative: &str, report: &mut PackageValidationReport) -> Option<Value> {
    let text = read_expected_text(root, relative, report)?;
    match serde_json::from_str(&text) {
        Ok(value) => Some(value),
        Err(_) => {
            report.error(format!("{relative} is not valid JSON"));
            None
        }
    }
}

fn read_expected_text(
    root: &Path,
    relative: &str,
    report: &mut PackageValidationReport,
) -> Option<String> {
    let path = root.join(relative);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            match fs::read_to_string(&path) {
                Ok(text) => Some(text),
                Err(_) => {
                    report.error(format!("could not read required text file: {relative}"));
                    None
                }
            }
        }
        _ => None,
    }
}

fn check_u64_field(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    field: &str,
    expected: u64,
) {
    match value.get(field).and_then(Value::as_u64) {
        Some(value) if value == expected => {
            report.pass(format!("{relative} {field} is {expected}"));
        }
        _ => report.error(format!("{relative} {field} must be {expected}")),
    }
}

fn check_string_field(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    field: &str,
    expected: Option<&str>,
) {
    match (value.get(field).and_then(Value::as_str), expected) {
        (Some(value), Some(expected)) if value == expected => {
            report.pass(format!("{relative} {field} is {expected}"));
        }
        (Some(value), None) if !value.trim().is_empty() => {
            report.pass(format!("{relative} {field} is present"));
        }
        _ if expected.is_some() => {
            report.error(format!(
                "{relative} {field} must be {}",
                expected.unwrap_or_default()
            ));
        }
        _ => report.error(format!("{relative} {field} must be a non-empty string")),
    }
}

fn check_required_string(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    field: &str,
) {
    check_string_field(report, value, relative, field, None);
}

fn check_nested_string(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    path: &[&str],
) {
    let mut current = value;
    for key in path {
        let Some(next) = current.get(*key) else {
            report.error(format!("{relative} {} must exist", path.join(".")));
            return;
        };
        current = next;
    }
    match current.as_str() {
        Some(value) if !value.trim().is_empty() => {
            report.pass(format!("{relative} {} is present", path.join(".")));
        }
        _ => report.error(format!("{relative} {} must be a string", path.join("."))),
    }
}

fn check_object_contains(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    object_field: &str,
    key: &str,
) {
    match value.get(object_field).and_then(Value::as_object) {
        Some(object) if object.contains_key(key) => {
            report.pass(format!("{relative} {object_field} includes {key}"));
        }
        Some(_) => report.error(format!("{relative} {object_field} must include {key}")),
        None => report.error(format!("{relative} {object_field} must be an object")),
    }
}

fn check_non_empty_string_array(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    field: &str,
) -> Option<Vec<String>> {
    let values = check_string_array(report, value, relative, field)?;
    if values.is_empty() {
        report.error(format!("{relative} {field} must not be empty"));
        None
    } else {
        report.pass(format!("{relative} {field} is non-empty"));
        Some(values)
    }
}

fn check_string_array(
    report: &mut PackageValidationReport,
    value: &Value,
    relative: &str,
    field: &str,
) -> Option<Vec<String>> {
    let Some(items) = value.get(field).and_then(Value::as_array) else {
        report.error(format!("{relative} {field} must be an array"));
        return None;
    };
    let mut values = Vec::new();
    for item in items {
        match item.as_str() {
            Some(value) => values.push(value.to_string()),
            None => {
                report.error(format!("{relative} {field} must contain only strings"));
                return None;
            }
        }
    }
    report.pass(format!("{relative} {field} is a string array"));
    Some(values)
}

fn value_contains_redacted(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains("<redacted>"),
        Value::Array(items) => items.iter().any(value_contains_redacted),
        Value::Object(object) => object.values().any(value_contains_redacted),
        _ => false,
    }
}

fn contains_percent_encoded_placeholder(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("%24%7b") || lower.contains("%7d")
}

fn is_safe_manifest_path(path: &str) -> bool {
    !path.trim().is_empty()
        && path == path.trim()
        && path != MANIFEST_FILE
        && !path.contains('\\')
        && !path.contains(':')
        && !path.starts_with('/')
        && !path.contains("//")
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn is_secretish_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "api_key"
            | "token"
            | "secret"
            | "access_token"
            | "refresh_token"
            | "password"
            | "authorization"
            | "x-api-key"
    ) || lower.ends_with("_token")
        || lower.ends_with("_secret")
        || lower.ends_with("_password")
}

fn secret_category(key: &str) -> &'static str {
    let lower = key.to_ascii_lowercase();
    if lower.contains("authorization") || lower.contains("token") {
        "token"
    } else if lower.contains("password") {
        "password"
    } else if lower.contains("api") {
        "api_key"
    } else {
        "secret"
    }
}

fn is_safe_secret_reference(value: &str) -> bool {
    let trimmed = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches(',')
        .trim_matches(';');
    trimmed.is_empty()
        || trimmed == "..."
        || trimmed.contains("FIRSTCALL_")
        || trimmed.contains("${")
        || trimmed.contains("process.env")
        || trimmed.contains("envValue")
        || trimmed.contains("<redacted>")
}

fn join_relative(relative_dir: &str, name: &str) -> String {
    if relative_dir.is_empty() {
        name.to_string()
    } else {
        format!("{relative_dir}/{name}")
    }
}
