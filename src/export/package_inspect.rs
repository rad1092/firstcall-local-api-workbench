use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::agent_common::parse_url_template;
use super::package_manifest::MANIFEST_FILE;
use super::package_validation::{PackageValidationReport, validate_agent_package_dir};
use super::verified_lock::{
    request_fingerprint_for_agent_recipe_yaml, response_schema_fingerprint_for_agent_recipe_yaml,
};

#[derive(Clone, Debug)]
pub struct PackageInspectReport {
    pub package_dir: PathBuf,
    pub validation: PackageValidationReport,
    pub manifest_present: bool,
    pub request_fingerprint_status: RequestFingerprintStatus,
    pub blockers: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFingerprintStatus {
    Matched,
    Mismatched,
    Unavailable,
}

impl RequestFingerprintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatched => "mismatched",
            Self::Unavailable => "unavailable",
        }
    }
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
    inspect_agent_package_for_import(path).0
}

pub(crate) fn inspect_agent_package_for_import(
    path: &Path,
) -> (PackageInspectReport, Option<Value>) {
    let validation = validate_agent_package_dir(path);
    let manifest_present = path.join(MANIFEST_FILE).symlink_metadata().is_ok();
    let mut blockers = Vec::new();

    if !validation.is_valid() {
        blockers.push("package validation has errors".to_string());
    }
    if !manifest_present {
        blockers.push("package.manifest.json is required for import readiness".to_string());
    }

    let recipe_snapshot = read_yaml_snapshot(path, "recipe.yaml", &mut blockers);
    if let Some((bytes, _)) = &recipe_snapshot {
        inspect_recipe_snapshot_manifest_hash(path, bytes, &mut blockers);
    }
    let recipe = recipe_snapshot.as_ref().map(|(_, recipe)| recipe);
    inspect_recipe_policy_reconciliation(path, recipe, &mut blockers);
    let mut request_fingerprint_status = RequestFingerprintStatus::Unavailable;
    inspect_verified_lock(path, recipe, &mut blockers, &mut request_fingerprint_status);

    (
        PackageInspectReport {
            package_dir: path.to_path_buf(),
            validation,
            manifest_present,
            request_fingerprint_status,
            blockers,
        },
        recipe_snapshot.map(|(_, recipe)| recipe),
    )
}

fn inspect_recipe_policy_reconciliation(
    root: &Path,
    recipe: Option<&Value>,
    blockers: &mut Vec<String>,
) {
    let Some(recipe) = recipe else {
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

fn inspect_verified_lock(
    root: &Path,
    recipe: Option<&Value>,
    blockers: &mut Vec<String>,
    request_fingerprint_status: &mut RequestFingerprintStatus,
) {
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
    let request_fingerprint = lock.get("request_fingerprint").and_then(Value::as_str);
    match request_fingerprint {
        Some(value) if is_sha256_hex(value) => {}
        _ => blockers.push(
            "verified.lock.json request_fingerprint must be 64-character lowercase hex".to_string(),
        ),
    }
    let Some(request_fingerprint) = request_fingerprint else {
        return;
    };
    if !is_sha256_hex(request_fingerprint) {
        return;
    }
    let Some(recipe) = recipe else {
        return;
    };
    match request_fingerprint_for_agent_recipe_yaml(recipe) {
        Ok(expected) if expected == request_fingerprint => {
            *request_fingerprint_status = RequestFingerprintStatus::Matched;
        }
        Ok(_) => {
            *request_fingerprint_status = RequestFingerprintStatus::Mismatched;
            blockers.push(
                "verified.lock.json request_fingerprint does not match recipe.yaml".to_string(),
            );
        }
        Err(_) => {
            *request_fingerprint_status = RequestFingerprintStatus::Unavailable;
            blockers
                .push("verified.lock.json request_fingerprint could not be recomputed".to_string());
        }
    }

    let response_fingerprint = lock
        .get("response_schema_fingerprint")
        .and_then(Value::as_str);
    match response_fingerprint {
        Some(value) if is_sha256_hex(value) => {
            match response_schema_fingerprint_for_agent_recipe_yaml(recipe) {
                Ok(expected) if expected == value => {}
                Ok(_) => blockers.push(
                    "verified.lock.json response_schema_fingerprint does not match recipe.yaml"
                        .to_string(),
                ),
                Err(_) => blockers.push(
                    "verified.lock.json response_schema_fingerprint could not be recomputed"
                        .to_string(),
                ),
            }
        }
        _ => blockers.push(
            "verified.lock.json response_schema_fingerprint must be 64-character lowercase hex"
                .to_string(),
        ),
    }
}

fn read_yaml_snapshot(
    root: &Path,
    relative: &str,
    blockers: &mut Vec<String>,
) -> Option<(Vec<u8>, Value)> {
    let bytes = match fs::read(root.join(relative)) {
        Ok(bytes) => bytes,
        Err(_) => {
            blockers.push(format!("{relative} could not be read for import readiness"));
            return None;
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            blockers.push(format!("{relative} must be UTF-8 for import readiness"));
            return None;
        }
    };
    match yaml_serde::from_str::<Value>(text) {
        Ok(value) => Some((bytes, value)),
        Err(_) => {
            blockers.push(format!(
                "{relative} could not be parsed for import readiness"
            ));
            None
        }
    }
}

fn inspect_recipe_snapshot_manifest_hash(
    root: &Path,
    recipe_bytes: &[u8],
    blockers: &mut Vec<String>,
) {
    let Some(manifest) = read_json(root, MANIFEST_FILE, blockers) else {
        return;
    };
    let expected = manifest
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| {
            files.iter().find_map(|entry| {
                (entry.get("path").and_then(Value::as_str) == Some("recipe.yaml"))
                    .then(|| entry.get("sha256").and_then(Value::as_str))
                    .flatten()
            })
        });
    let Some(expected) = expected else {
        blockers.push("package manifest does not cover the recipe snapshot".to_string());
        return;
    };
    let digest = Sha256::digest(recipe_bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        blockers.push("recipe snapshot does not match package manifest".to_string());
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
