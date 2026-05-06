use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use firstcall::export::agent_package::{
    export_agent_package, is_agent_export_eligible, sanitized_agent_url_template,
};
use firstcall::export::package_import::{PackageImportReport, import_agent_package_dir};
use firstcall::export::package_inspect::{PackageInspectReport, inspect_agent_package_dir};
use firstcall::export::package_validation::{PackageValidationReport, validate_agent_package_dir};
use firstcall::export::verified_lock::recipe_to_verified_lock_json;
use firstcall::model::Recipe;
use firstcall::store::db::AppPaths;
use firstcall::verify::{
    VerifyOptions, VerifyPreflightReport, VerifyReport, verify_recipe_preflight_with_process_env,
    verify_recipe_with_process_env,
};
use serde_json::{Value, json};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        bail!("missing command");
    };
    match command {
        "version" => {
            println!("firstcall-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "explain" => {
            let recipe_json = required_path_arg(&args[1..], "--recipe-json")?;
            let recipe = read_recipe_json(&recipe_json)?;
            print_recipe_summary(&recipe);
            Ok(())
        }
        "package" => {
            let recipe_json = required_path_arg(&args[1..], "--recipe-json")?;
            let out_dir = required_path_arg(&args[1..], "--out")?;
            let recipe = read_recipe_json(&recipe_json)?;
            export_agent_package(&recipe, &out_dir)?;
            println!("Exported agent package to {}", out_dir.display());
            Ok(())
        }
        "verify" => {
            let recipe_json = required_path_arg(&args[1..], "--recipe-json")?;
            let out_path = optional_path_arg(&args[1..], "--out");
            let lock_out_path = optional_path_arg(&args[1..], "--lock-out");
            let allow_mutating = has_flag(&args[1..], "--allow-mutating");
            let dry_run = has_flag(&args[1..], "--dry-run") || has_flag(&args[1..], "--preflight");
            let json_output = has_flag(&args[1..], "--json");
            if json_output && !dry_run {
                bail!("--json is only supported with verify --dry-run/--preflight");
            }
            if dry_run && (out_path.is_some() || lock_out_path.is_some()) {
                bail!("dry-run/preflight cannot write output files");
            }
            let recipe = read_recipe_json(&recipe_json)?;
            if dry_run {
                let report = verify_recipe_preflight_with_process_env(
                    &recipe,
                    VerifyOptions { allow_mutating },
                );
                if json_output {
                    print_verify_preflight_json(&report)?;
                } else {
                    print_verify_preflight_report(&report);
                }
                if report.ready() {
                    return Ok(());
                }
                bail!("verification preflight failed");
            }
            match verify_recipe_with_process_env(&recipe, VerifyOptions { allow_mutating }) {
                Ok(report) => {
                    print_verify_summary(&report);
                    if !report.success() {
                        bail!("verification failed");
                    }
                    if let Some(path) = out_path {
                        fs::write(&path, serde_json::to_string_pretty(&report.updated_recipe)?)
                            .with_context(|| {
                                format!("Could not write verified recipe {}", path.display())
                            })?;
                        println!("Wrote verified recipe: {}", path.display());
                    }
                    if let Some(path) = lock_out_path {
                        fs::write(&path, recipe_to_verified_lock_json(&report.updated_recipe)?)
                            .with_context(|| {
                                format!("Could not write verified lock {}", path.display())
                            })?;
                        println!("Wrote verified lock: {}", path.display());
                    }
                    Ok(())
                }
                Err(error) => {
                    print_verify_preflight_failure(&recipe, &error);
                    bail!("verification preflight failed");
                }
            }
        }
        "validate-package" => {
            let package_dir = required_path_arg(&args[1..], "--dir")?;
            let json_output = has_flag(&args[1..], "--json");
            let report = validate_agent_package_dir(&package_dir);
            if json_output {
                print_package_validation_json(&report)?;
            } else {
                print_package_validation_report(&report);
            }
            if report.is_valid() {
                Ok(())
            } else {
                bail!("package validation failed")
            }
        }
        "inspect-package" => {
            let package_dir = required_path_arg(&args[1..], "--dir")?;
            let json_output = has_flag(&args[1..], "--json");
            let report = inspect_agent_package_dir(&package_dir);
            if json_output {
                print_package_inspect_json(&report)?;
            } else {
                print_package_inspect_report(&report);
            }
            if report.is_ready() {
                Ok(())
            } else {
                bail!("package import readiness blocked")
            }
        }
        "import-package" => {
            let package_dir = required_path_arg(&args[1..], "--dir")?;
            let data_dir = optional_path_arg(&args[1..], "--data-dir");
            let config_dir = optional_path_arg(&args[1..], "--config-dir");
            let json_output = has_flag(&args[1..], "--json");
            let paths = match (data_dir, config_dir) {
                (Some(data_dir), Some(config_dir)) => AppPaths::from_root(&data_dir, &config_dir)?,
                (None, None) => AppPaths::discover()?,
                _ => bail!("--data-dir and --config-dir must be provided together"),
            };
            let report = import_agent_package_dir(&package_dir, &paths)?;
            if json_output {
                print_package_import_json(&report)?;
            } else {
                print_package_import_report(&report);
            }
            if report.imported() {
                Ok(())
            } else {
                bail!("package import blocked")
            }
        }
        _ => {
            print_help();
            bail!("unknown command: {command}");
        }
    }
}

fn read_recipe_json(path: &Path) -> Result<Recipe> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Could not read recipe JSON {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("Could not parse recipe JSON {}", path.display()))
}

fn print_recipe_summary(recipe: &Recipe) {
    println!("Product: FirstCall Agent Recipes");
    println!("Tagline: Verified API tool recipes for AI agents.");
    println!("Recipe: {}", recipe.name);
    println!("Method: {}", recipe.method);
    println!("URL template: {}", sanitized_agent_url_template(recipe));
    println!("Auth style: {}", recipe.auth_style.label());
    println!("Required slots:");
    let required_slots = recipe
        .slots
        .iter()
        .filter(|slot| slot.required)
        .collect::<Vec<_>>();
    if required_slots.is_empty() {
        println!("- none");
    } else {
        for slot in required_slots {
            println!("- {} ({})", slot.name, slot.location.label());
        }
    }
    println!(
        "Last successful verification status: {}",
        recipe
            .last_success_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "Last successful verification time: {}",
        recipe
            .last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "Eligible for agent export: {}",
        is_agent_export_eligible(recipe)
    );
}

fn print_verify_summary(report: &VerifyReport) {
    println!("Recipe: {}", report.recipe_name);
    println!("Method: {}", report.method);
    println!("URL template: {}", report.sanitized_url_template);
    println!(
        "HTTP status: {}",
        report
            .status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!("Outcome: {}", report.outcome.label());
    println!(
        "Blocker: {}",
        report
            .blocker
            .as_ref()
            .map(|blocker| blocker.label())
            .unwrap_or("none")
    );
    println!(
        "Updated verification time: {}",
        report
            .verified_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "n/a".to_string())
    );
}

fn print_verify_preflight_failure(recipe: &Recipe, error: &anyhow::Error) {
    println!("Recipe: {}", recipe.name);
    println!("Method: {}", recipe.method.to_ascii_uppercase());
    println!("URL template: {}", sanitized_agent_url_template(recipe));
    println!("Outcome: failure");
    println!("Blocker: preflight");
    println!("Error: {error}");
}

fn print_verify_preflight_report(report: &VerifyPreflightReport) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: dry-run");
    println!("Recipe: {}", report.recipe_name);
    println!("Method: {}", report.method);
    println!("URL template: {}", report.sanitized_url_template);
    println!("Auth style: {}", report.auth_style);
    println!("Body kind: {}", report.body_kind);
    println!("Mutating method: {}", yes_no(report.mutating_method));
    println!("Allow mutating: {}", yes_no(report.allow_mutating));
    println!("Would execute HTTP: {}", yes_no(report.would_execute_http));
    println!(
        "Preflight status: {}",
        if report.ready() { "ready" } else { "blocked" }
    );
    println!("Required environment variables:");
    if report.required_env.is_empty() {
        println!("- none");
    } else {
        for item in &report.required_env {
            println!("- {}: {}", item.name, item.status.label());
        }
    }
    println!("Required slots:");
    if report.required_slots.is_empty() {
        println!("- none");
    } else {
        for slot in &report.required_slots {
            println!(
                "- {} ({}, {}): {}",
                slot.name,
                slot.location,
                if slot.required {
                    "required"
                } else {
                    "optional"
                },
                slot.source.label()
            );
        }
    }
    println!("Blockers:");
    if report.blockers.is_empty() {
        println!("- none");
    } else {
        for blocker in &report.blockers {
            println!("- {blocker}");
        }
    }
}

fn print_verify_preflight_json(report: &VerifyPreflightReport) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "dry-run",
        "recipe": report.recipe_name,
        "method": report.method,
        "url_template": report.sanitized_url_template,
        "auth_style": report.auth_style,
        "body_kind": report.body_kind,
        "mutating_method": report.mutating_method,
        "allow_mutating": report.allow_mutating,
        "would_execute_http": report.would_execute_http,
        "preflight_status": if report.ready() { "ready" } else { "blocked" },
        "required_env": report.required_env.iter().map(|item| json!({
            "name": item.name,
            "status": item.status.label(),
        })).collect::<Vec<_>>(),
        "required_slots": report.required_slots.iter().map(|slot| json!({
            "name": slot.name,
            "location": slot.location,
            "required": slot.required,
            "source": slot.source.label(),
        })).collect::<Vec<_>>(),
        "blockers": report.blockers,
    }))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn print_package_validation_report(report: &PackageValidationReport) {
    println!("Package: {}", report.package_dir.display());
    println!(
        "Status: {}",
        if report.is_valid() {
            "valid"
        } else {
            "invalid"
        }
    );
    println!("Checks passed: {}", report.checks_passed.len());
    println!("Warnings: {}", report.warnings.len());
    println!("Errors: {}", report.errors.len());
    if !report.warnings.is_empty() {
        println!("Warnings:");
        for warning in &report.warnings {
            println!("- {warning}");
        }
    }
    if !report.errors.is_empty() {
        println!("Errors:");
        for error in &report.errors {
            println!("- {error}");
        }
    }
}

fn print_package_validation_json(report: &PackageValidationReport) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "validate-package",
        "package_dir": report.package_dir.display().to_string(),
        "status": if report.is_valid() { "valid" } else { "invalid" },
        "checks_passed": report.checks_passed,
        "warnings": report.warnings,
        "errors": report.errors,
    }))
}

fn print_package_inspect_report(report: &PackageInspectReport) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: inspect-package");
    println!("Package: {}", report.package_dir.display());
    println!("Validation status: {}", report.validation_status());
    println!("Import readiness: {}", report.readiness_status());
    println!("Manifest: {}", report.manifest_status());
    println!("Legacy package: {}", yes_no(report.legacy_package()));
    println!("Would import: no");
    println!("Would execute HTTP: no");
    println!("Would write files: no");
    println!("Would modify app storage: no");
    println!("Requires local re-verification: yes");
    println!("Raw secrets imported: no");
    println!("Generated MCP server source of truth: no");
    println!("Request fingerprint recomputation: deferred");
    println!(
        "Validation checks passed: {}",
        report.validation.checks_passed.len()
    );
    println!("Validation warnings: {}", report.validation.warnings.len());
    if report.validation.warnings.is_empty() {
        println!("- none");
    } else {
        for warning in &report.validation.warnings {
            println!("- {warning}");
        }
    }
    println!("Validation errors: {}", report.validation.errors.len());
    if report.validation.errors.is_empty() {
        println!("- none");
    } else {
        for error in &report.validation.errors {
            println!("- {error}");
        }
    }
    println!("Import-readiness blockers:");
    if report.blockers.is_empty() {
        println!("- none");
    } else {
        for blocker in &report.blockers {
            println!("- {blocker}");
        }
    }
}

fn print_package_inspect_json(report: &PackageInspectReport) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "inspect-package",
        "package_dir": report.package_dir.display().to_string(),
        "validation_status": report.validation_status(),
        "import_readiness": report.readiness_status(),
        "manifest": report.manifest_status(),
        "legacy_package": report.legacy_package(),
        "would_import": false,
        "would_execute_http": false,
        "would_write_files": false,
        "would_modify_app_storage": false,
        "requires_local_re_verification": true,
        "raw_secrets_imported": false,
        "generated_mcp_server_source_of_truth": false,
        "request_fingerprint_recomputation": "deferred",
        "validation": {
            "checks_passed": report.validation.checks_passed,
            "warnings": report.validation.warnings,
            "errors": report.validation.errors,
        },
        "import_readiness_blockers": report.blockers,
    }))
}

fn print_package_import_report(report: &PackageImportReport) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: import-package");
    println!("Package: {}", report.package_dir.display());
    println!("Import status: {}", report.status_label());
    println!(
        "Imported recipe id: {}",
        report
            .imported_recipe_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!("Recipe: {}", report.recipe_name.as_deref().unwrap_or("n/a"));
    println!("Method: {}", report.method.as_deref().unwrap_or("n/a"));
    println!(
        "URL template: {}",
        report.safe_url_template.as_deref().unwrap_or("n/a")
    );
    println!("Preserved verified status: no");
    println!("Requires local re-verification: yes");
    println!("Secrets imported: no");
    println!("Would execute HTTP: no");
    println!("Generated MCP server source of truth: no");
    println!(
        "App storage modified: {}",
        if report.imported() { "yes" } else { "no" }
    );
    println!(
        "Validation status: {}",
        report.inspect_report.validation_status()
    );
    println!(
        "Import readiness: {}",
        report.inspect_report.readiness_status()
    );
    println!("Import blockers:");
    if report.blockers.is_empty() {
        println!("- none");
    } else {
        for blocker in &report.blockers {
            println!("- {blocker}");
        }
    }
}

fn print_package_import_json(report: &PackageImportReport) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "import-package",
        "package_dir": report.package_dir.display().to_string(),
        "import_status": report.status_label(),
        "imported_recipe_id": report.imported_recipe_id,
        "recipe": report.recipe_name,
        "method": report.method,
        "url_template": report.safe_url_template,
        "preserved_verified_status": false,
        "requires_local_re_verification": true,
        "secrets_imported": false,
        "would_execute_http": false,
        "generated_mcp_server_source_of_truth": false,
        "app_storage_modified": report.imported(),
        "validation_status": report.inspect_report.validation_status(),
        "import_readiness": report.inspect_report.readiness_status(),
        "import_blockers": report.blockers,
    }))
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn required_path_arg(args: &[String], flag: &str) -> Result<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .with_context(|| format!("missing required argument {flag}"))
}

fn optional_path_arg(args: &[String], flag: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn print_help() {
    eprintln!(
        "Usage:
  firstcall-cli version
  firstcall-cli explain --recipe-json PATH
  firstcall-cli package --recipe-json PATH --out DIR
  firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating] [--dry-run|--preflight] [--json]
  firstcall-cli validate-package --dir PATH [--json]
  firstcall-cli inspect-package --dir PATH [--json]
  firstcall-cli import-package --dir PATH [--data-dir PATH --config-dir PATH] [--json]"
    );
}
