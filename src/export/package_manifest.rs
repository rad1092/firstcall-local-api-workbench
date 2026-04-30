use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::agent_common::GENERATOR;

pub(crate) const MANIFEST_FILE: &str = "package.manifest.json";

pub(crate) const MANIFESTED_FILES: &[&str] = &[
    "recipe.yaml",
    "verified.lock.json",
    "skill.md",
    "policy.json",
    "mcp-server/package.json",
    "mcp-server/tsconfig.json",
    "mcp-server/src/server.ts",
    "mcp-server/README.md",
];

#[derive(Serialize)]
struct PackageManifest {
    schema_version: u8,
    generator: String,
    generated_at: String,
    files: Vec<ManifestFile>,
}

#[derive(Serialize)]
struct ManifestFile {
    path: String,
    sha256: String,
}

pub(crate) fn write_package_manifest(out_dir: &Path) -> Result<()> {
    let manifest = package_manifest(out_dir)?;
    let text = serde_json::to_string_pretty(&manifest)?;
    fs::write(out_dir.join(MANIFEST_FILE), text)
        .with_context(|| format!("Could not write {MANIFEST_FILE}"))?;
    Ok(())
}

pub(crate) fn sha256_file_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Could not read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn package_manifest(out_dir: &Path) -> Result<PackageManifest> {
    let files = MANIFESTED_FILES
        .iter()
        .map(|relative| {
            let sha256 = sha256_file_hex(&out_dir.join(relative))?;
            Ok(ManifestFile {
                path: (*relative).to_string(),
                sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PackageManifest {
        schema_version: 1,
        generator: GENERATOR.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        files,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
