use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::agent_common::parse_url_template;
use super::package_manifest::MANIFEST_FILE;
use super::package_validation::{PackageValidationReport, validate_agent_package_dir};

#[derive(Clone, Debug)]
pub struct PackageInspectReport {
    pub package_dir: PathBuf,
    pub validation: PackageValidationReport,
    pub manifest_present: bool,
    pub blockers: Vec<String>,
}

impl PackageInspectReport {
    pub fn is_ready(&self) -> bool {
        self.validation.is_valid() && self.blockers.is_empty()
    }

    pub fn validation_status(&self) -> &'static str {
        if self.validation.is_valid() {
            "valid"
        } else {
            "invalid"
        }
    }

    pub fn readiness_status(&self) -> &'static str {
        if self.is_ready() { "ready" } else { "blocked" }
    }

    pub fn manifest_status(&self) -> &'static str {
        if self.manifest_present {
            "present"
        } else {
            "missing"
        }
    }

    pub fn legacy_package(&self) -> bool {
        !self.manifest_present
    }
}

pub fn inspect_agent_package_dir(path: &Path) -> PackageInspectReport {
    let validation = validate_agent_package_dir(path);
    let manifest_present = path.join(MANIFEST_FILE).symlink_metadata().is_ok();
    let mut blockers = Vec::new();

    if !validation.is_valid() {
        blockers.push("package validation has errors".to_string());
    }
    if !manifest_present {
        blockers.push("package.manifest.json is required for import readiness".to_string());
    }

    inspect_recipe_policy_reconciliation(path, &mut blockers);
    inspect_verified_lock(path, &mut blockers);

    PackageInspectReport {
        package_dir: path.to_path_buf(),
        validation,
        manifest_present,
        blockers,
    }
}

fn inspect_recipe_policy_reconciliation(root: &Path, blockers: &mut Vec<String>) {
    let Some(recipe) = read_yaml(root, "recipe.yaml", blockers) else {
        return;
    };
    let Some(policy) = read_json(root, "policy.json", blockers) else {
        return;
    };

    let method = match recipe.get("method").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_ascii_uppercase(),
        _ => {
            blockers.push("recipe.yaml method is required for import readiness".to_string());
            return;
        }
    };
    let Some(url_template) = recipe.get("url_template").and_then(Value::as_str) else {
        blockers.push("recipe.yaml url_template is required for import readiness".to_string());
        return;
    };
    let (host, path) = match parse_url_template(url_template) {
        Ok(parts) => parts,
        Err(_) => {
            blockers
                .push("recipe.yaml url_template must be a valid absolute URL template".to_string());
            return;
        }
    };

    if !string_array(&policy, "allowed_methods")
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&method))
    {
        blockers.push("recipe.yaml method is not allowed by policy.json".to_string());
    }

    if !string_array(&policy, "allowed_hosts")
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        blockers.push("recipe.yaml host is not allowed by policy.json".to_string());
    }

    if !string_array(&policy, "allowed_paths")
        .iter()
        .any(|allowed| allowed == &path)
    {
        blockers.push("recipe.yaml path is not allowed by policy.json".to_string());
    }
}

fn inspect_verified_lock(root: &Path, blockers: &mut Vec<String>) {
    let Some(lock) = read_json(root, "verified.lock.json", blockers) else {
        return;
    };

    if lock.get("verified").and_then(Value::as_bool) != Some(true) {
        blockers.push("verified.lock.json verified must be true for import readiness".to_string());
    }
    match lock.get("last_success_status").and_then(Value::as_u64) {
        Some(200..=299) => {}
        _ => blockers.push(
            "verified.lock.json last_success_status must be 200..=299 for import readiness"
                .to_string(),
        ),
    }
    match lock.get("request_fingerprint").and_then(Value::as_str) {
        Some(value) if is_sha256_hex(value) => {}
        _ => blockers.push(
            "verified.lock.json request_fingerprint must be 64-character lowercase hex".to_string(),
        ),
    }
}

fn read_yaml(root: &Path, relative: &str, blockers: &mut Vec<String>) -> Option<Value> {
    let text = read_text(root, relative, blockers)?;
    match yaml_serde::from_str::<Value>(&text) {
        Ok(value) => Some(value),
        Err(_) => {
            blockers.push(format!(
                "{relative} could not be parsed for import readiness"
            ));
            None
        }
    }
}

fn read_json(root: &Path, relative: &str, blockers: &mut Vec<String>) -> Option<Value> {
    let text = read_text(root, relative, blockers)?;
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => Some(value),
        Err(_) => {
            blockers.push(format!(
                "{relative} could not be parsed for import readiness"
            ));
            None
        }
    }
}

fn read_text(root: &Path, relative: &str, blockers: &mut Vec<String>) -> Option<String> {
    match fs::read_to_string(root.join(relative)) {
        Ok(text) => Some(text),
        Err(_) => {
            blockers.push(format!("{relative} could not be read for import readiness"));
            None
        }
    }
}

fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}
