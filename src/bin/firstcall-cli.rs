use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use firstcall::exec::redact::redact_free_text;
use firstcall::export::agent_package::{
    export_agent_package, is_agent_export_eligible, sanitized_agent_url_template,
};
use firstcall::export::package_import::{PackageImportReport, import_agent_package_dir};
use firstcall::export::package_inspect::{PackageInspectReport, inspect_agent_package_dir};
use firstcall::export::package_validation::{
    PackageValidationOptions, PackageValidationReport, validate_agent_package_dir,
    validate_agent_package_dir_with_options,
};
use firstcall::export::verified_lock::recipe_to_verified_lock_json;
use firstcall::model::Recipe;
use firstcall::store::db::AppPaths;
use firstcall::store::repos::AppRepository;
use firstcall::verify::{
    VerifyOptions, VerifyPreflightReport, VerifyReport, verify_recipe_preflight_with_process_env,
    verify_recipe_with_process_env,
};
use rusqlite::{Connection, OpenFlags};
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
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" => {
            println!("firstcall-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "serve" => {
            let mut package = None;
            let mut allow_mutating = false;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--package" if package.is_none() => {
                        index += 1;
                        let value = args.get(index).context("--package requires a directory")?;
                        if value.starts_with("--") {
                            bail!("--package requires a directory");
                        }
                        package = Some(PathBuf::from(value));
                    }
                    "--allow-mutating" if !allow_mutating => allow_mutating = true,
                    _ => bail!("serve accepts --package DIR and optional --allow-mutating"),
                }
                index += 1;
            }
            firstcall::mcp::serve_stdio(
                &package.context("serve requires --package DIR")?,
                firstcall::mcp::ServeOptions { allow_mutating },
            )
        }
        "explain" => {
            let recipe_json = required_path_arg(&args[1..], "--recipe-json")?;
            let recipe = read_recipe_json(&recipe_json)?;
            print_recipe_summary(&recipe);
            Ok(())
        }
        "package" => {
            let recipe_json = optional_path_arg(&args[1..], "--recipe-json");
            let recipe_id = optional_i64_arg(&args[1..], "--recipe-id")?;
            let out_dir = required_path_arg(&args[1..], "--out")?;
            let source = match (recipe_json, recipe_id) {
                (Some(path), None) => PackageSource::RecipeJson(path),
                (None, Some(id)) => PackageSource::RecipeId(id),
                (None, None) => bail!("exactly one of --recipe-json or --recipe-id is required"),
                (Some(_), Some(_)) => bail!("provide only one of --recipe-json or --recipe-id"),
            };
            let recipe = match source {
                PackageSource::RecipeJson(recipe_json) => read_recipe_json(&recipe_json)?,
                PackageSource::RecipeId(recipe_id) => {
                    let paths = storage_paths_from_args(&args[1..])?;
                    let Some(repository) = open_existing_recipe_repository(&paths)? else {
                        bail!("recipe not found: {recipe_id}");
                    };
                    repository
                        .get_recipe(recipe_id)?
                        .with_context(|| format!("recipe not found: {recipe_id}"))?
                }
            };
            export_agent_package(&recipe, &out_dir)?;
            println!("Exported agent package to {}", out_dir.display());
            Ok(())
        }
        "verify" => {
            let recipe_json = optional_path_arg(&args[1..], "--recipe-json");
            let recipe_id = optional_i64_arg(&args[1..], "--recipe-id")?;
            let out_path = optional_path_arg(&args[1..], "--out");
            let lock_out_path = optional_path_arg(&args[1..], "--lock-out");
            let allow_mutating = has_flag(&args[1..], "--allow-mutating");
            let dry_run = has_flag(&args[1..], "--dry-run") || has_flag(&args[1..], "--preflight");
            let json_output = has_flag(&args[1..], "--json");
            let source = match (recipe_json, recipe_id) {
                (Some(path), None) => VerifySource::RecipeJson(path),
                (None, Some(id)) => VerifySource::RecipeId(id),
                (None, None) => bail!("exactly one of --recipe-json or --recipe-id is required"),
                (Some(_), Some(_)) => bail!("provide only one of --recipe-json or --recipe-id"),
            };
            if matches!(source, VerifySource::RecipeId(_))
                && (out_path.is_some() || lock_out_path.is_some())
            {
                bail!("verify --recipe-id does not support --out or --lock-out");
            }
            if dry_run && (out_path.is_some() || lock_out_path.is_some()) {
                bail!("dry-run/preflight cannot write output files");
            }
            match source {
                VerifySource::RecipeJson(recipe_json) => {
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
                    match verify_recipe_with_process_env(&recipe, VerifyOptions { allow_mutating })
                    {
                        Ok(report) => {
                            let mut wrote_recipe = false;
                            let mut wrote_lock = false;
                            if !json_output {
                                print_verify_summary(&report);
                            }
                            if !report.success() {
                                if json_output {
                                    print_verify_json_for_recipe_json(
                                        &report,
                                        wrote_recipe,
                                        wrote_lock,
                                        &[],
                                    )?;
                                }
                                bail!("verification failed");
                            }
                            if let Some(path) = &out_path {
                                fs::write(
                                    path,
                                    serde_json::to_string_pretty(&report.updated_recipe)?,
                                )
                                .with_context(|| {
                                    format!("Could not write verified recipe {}", path.display())
                                })?;
                                wrote_recipe = true;
                                if !json_output {
                                    println!("Wrote verified recipe: {}", path.display());
                                }
                            }
                            if let Some(path) = &lock_out_path {
                                fs::write(
                                    path,
                                    recipe_to_verified_lock_json(&report.updated_recipe)?,
                                )
                                .with_context(|| {
                                    format!("Could not write verified lock {}", path.display())
                                })?;
                                wrote_lock = true;
                                if !json_output {
                                    println!("Wrote verified lock: {}", path.display());
                                }
                            }
                            if json_output {
                                print_verify_json_for_recipe_json(
                                    &report,
                                    wrote_recipe,
                                    wrote_lock,
                                    &[],
                                )?;
                            }
                            Ok(())
                        }
                        Err(error) => {
                            if json_output {
                                print_verify_error_json_for_recipe_json(&recipe, &error)?;
                            } else {
                                print_verify_preflight_failure(&recipe, &error);
                            }
                            bail!("verification preflight failed");
                        }
                    }
                }
                VerifySource::RecipeId(recipe_id) => {
                    let paths = storage_paths_from_args(&args[1..])?;
                    if dry_run {
                        let recipe = match open_existing_recipe_repository(&paths)? {
                            Some(repository) => repository.get_recipe(recipe_id)?,
                            None => None,
                        };
                        let Some(recipe) = recipe else {
                            if json_output {
                                print_verify_recipe_id_not_found_json(recipe_id)?;
                            } else {
                                print_verify_recipe_id_not_found_report(recipe_id, "dry-run");
                            }
                            bail!("recipe not found: {recipe_id}");
                        };
                        let report = verify_recipe_preflight_with_process_env(
                            &recipe,
                            VerifyOptions { allow_mutating },
                        );
                        if json_output {
                            print_verify_preflight_json_for_recipe_id(&report, recipe_id)?;
                        } else {
                            print_verify_preflight_report(&report);
                        }
                        if report.ready() {
                            Ok(())
                        } else {
                            bail!("verification preflight failed")
                        }
                    } else {
                        let Some(repository) = open_existing_recipe_repository_for_update(&paths)?
                        else {
                            if json_output {
                                print_verify_recipe_id_not_found_json_for_verify(recipe_id)?;
                            } else {
                                print_verify_recipe_id_not_found_report(recipe_id, "verify");
                            }
                            bail!("recipe not found: {recipe_id}");
                        };
                        let Some(recipe) = repository.get_recipe(recipe_id)? else {
                            if json_output {
                                print_verify_recipe_id_not_found_json_for_verify(recipe_id)?;
                            } else {
                                print_verify_recipe_id_not_found_report(recipe_id, "verify");
                            }
                            bail!("recipe not found: {recipe_id}");
                        };
                        match verify_recipe_with_process_env(
                            &recipe,
                            VerifyOptions { allow_mutating },
                        ) {
                            Ok(report) => {
                                if !json_output {
                                    print_verify_summary(&report);
                                }
                                if !report.success() {
                                    if json_output {
                                        print_verify_json_for_recipe_id(
                                            &report,
                                            recipe_id,
                                            false,
                                            &[],
                                        )?;
                                    }
                                    bail!("verification failed");
                                }
                                repository.update_recipe_verification(
                                    recipe_id,
                                    &report.updated_recipe,
                                )?;
                                if json_output {
                                    print_verify_json_for_recipe_id(&report, recipe_id, true, &[])?;
                                } else {
                                    println!("Updated stored recipe verification: {recipe_id}");
                                }
                                Ok(())
                            }
                            Err(error) => {
                                if json_output {
                                    print_verify_error_json_for_recipe_id(
                                        &recipe, recipe_id, &error,
                                    )?;
                                } else {
                                    print_verify_preflight_failure(&recipe, &error);
                                }
                                bail!("verification preflight failed");
                            }
                        }
                    }
                }
            }
        }
        "validate-package" => {
            let package_dir = required_path_arg(&args[1..], "--dir")?;
            let json_output = has_flag(&args[1..], "--json");
            let mcp_compile_smoke = has_flag(&args[1..], "--mcp-compile-smoke");
            let report = if mcp_compile_smoke {
                validate_agent_package_dir_with_options(
                    &package_dir,
                    PackageValidationOptions {
                        mcp_compile_smoke: true,
                    },
                )
            } else {
                validate_agent_package_dir(&package_dir)
            };
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
            let json_output = has_flag(&args[1..], "--json");
            let paths = storage_paths_from_args(&args[1..])?;
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
        "recipe-list" => {
            let json_output = has_flag(&args[1..], "--json");
            let paths = storage_paths_from_args(&args[1..])?;
            let recipes = match open_existing_recipe_repository(&paths)? {
                Some(repository) => recipe_summaries(&repository)?,
                None => Vec::new(),
            };
            if json_output {
                print_recipe_list_json(&recipes)?;
            } else {
                print_recipe_list_report(&recipes);
            }
            Ok(())
        }
        "recipe-show" => {
            let recipe_id = required_i64_arg(&args[1..], "--id")?;
            let json_output = has_flag(&args[1..], "--json");
            let paths = storage_paths_from_args(&args[1..])?;
            let recipe = match open_existing_recipe_repository(&paths)? {
                Some(repository) => repository.get_recipe(recipe_id)?,
                None => None,
            };
            if let Some(recipe) = recipe {
                let summary = recipe_summary(recipe_id, &recipe);
                if json_output {
                    print_recipe_show_json(Some(&summary), recipe_id)?;
                } else {
                    print_recipe_show_report(Some(&summary), recipe_id);
                }
                Ok(())
            } else {
                if json_output {
                    print_recipe_show_json(None, recipe_id)?;
                } else {
                    print_recipe_show_report(None, recipe_id);
                }
                bail!("recipe not found: {recipe_id}")
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

fn print_verify_json_for_recipe_json(
    report: &VerifyReport,
    wrote_recipe: bool,
    wrote_lock: bool,
    errors: &[String],
) -> Result<()> {
    let mut value = verify_json_value(report, "recipe-json", errors);
    if let Value::Object(object) = &mut value {
        object.insert("wrote_recipe".to_string(), json!(wrote_recipe));
        object.insert("wrote_lock".to_string(), json!(wrote_lock));
    }
    print_json(&value)
}

fn print_verify_json_for_recipe_id(
    report: &VerifyReport,
    recipe_id: i64,
    updated_stored_recipe_verification: bool,
    errors: &[String],
) -> Result<()> {
    let mut value = verify_json_value(report, "recipe-id", errors);
    if let Value::Object(object) = &mut value {
        object.insert("recipe_id".to_string(), json!(recipe_id));
        object.insert(
            "updated_stored_recipe_verification".to_string(),
            json!(updated_stored_recipe_verification),
        );
    }
    print_json(&value)
}

fn verify_json_value(report: &VerifyReport, source: &str, errors: &[String]) -> Value {
    json!({
        "product": "FirstCall Agent Recipes",
        "mode": "verify",
        "source": source,
        "recipe": report.recipe_name,
        "method": report.method,
        "url_template": report.sanitized_url_template,
        "http_status": report.status,
        "outcome": report.outcome.label(),
        "blocker": report.blocker.as_ref().map(|blocker| blocker.label()),
        "success": report.success(),
        "verified_at": report.verified_at.map(|value| value.to_rfc3339()),
        "blockers": report.blocker.as_ref().map(|blocker| vec![blocker.label().to_string()]).unwrap_or_default(),
        "errors": errors,
    })
}

fn print_verify_error_json_for_recipe_json(recipe: &Recipe, error: &anyhow::Error) -> Result<()> {
    print_json(&verify_error_json_value(
        recipe,
        "recipe-json",
        None,
        &[safe_error_text(error)],
    ))
}

fn print_verify_error_json_for_recipe_id(
    recipe: &Recipe,
    recipe_id: i64,
    error: &anyhow::Error,
) -> Result<()> {
    print_json(&verify_error_json_value(
        recipe,
        "recipe-id",
        Some(recipe_id),
        &[safe_error_text(error)],
    ))
}

fn verify_error_json_value(
    recipe: &Recipe,
    source: &str,
    recipe_id: Option<i64>,
    errors: &[String],
) -> Value {
    let mut value = json!({
        "product": "FirstCall Agent Recipes",
        "mode": "verify",
        "source": source,
        "recipe": recipe.name,
        "method": recipe.method.to_ascii_uppercase(),
        "url_template": sanitized_agent_url_template(recipe),
        "http_status": null,
        "outcome": "failure",
        "blocker": "preflight",
        "success": false,
        "verified_at": null,
        "blockers": ["preflight"],
        "errors": errors,
    });
    if let Value::Object(object) = &mut value {
        match recipe_id {
            Some(recipe_id) => {
                object.insert("recipe_id".to_string(), json!(recipe_id));
                object.insert(
                    "updated_stored_recipe_verification".to_string(),
                    json!(false),
                );
            }
            None => {
                object.insert("wrote_recipe".to_string(), json!(false));
                object.insert("wrote_lock".to_string(), json!(false));
            }
        }
    }
    value
}

fn safe_error_text(error: &anyhow::Error) -> String {
    redact_free_text(&error.to_string())
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
    print_json(&verify_preflight_json_value(report))
}

fn print_verify_preflight_json_for_recipe_id(
    report: &VerifyPreflightReport,
    recipe_id: i64,
) -> Result<()> {
    let mut value = verify_preflight_json_value(report);
    if let Value::Object(object) = &mut value {
        object.insert("source".to_string(), json!("recipe-id"));
        object.insert("recipe_id".to_string(), json!(recipe_id));
    }
    print_json(&value)
}

fn verify_preflight_json_value(report: &VerifyPreflightReport) -> Value {
    json!({
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
    })
}

fn print_verify_recipe_id_not_found_report(recipe_id: i64, mode: &str) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: {mode}");
    println!("Source: recipe-id");
    println!("Recipe id: {recipe_id}");
    println!("Status: not_found");
    println!("Recipe: n/a");
    println!("Would execute HTTP: no");
}

fn print_verify_recipe_id_not_found_json(recipe_id: i64) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "dry-run",
        "source": "recipe-id",
        "recipe_id": recipe_id,
        "status": "not_found",
        "recipe": null,
        "would_execute_http": false,
    }))
}

fn print_verify_recipe_id_not_found_json_for_verify(recipe_id: i64) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "verify",
        "source": "recipe-id",
        "recipe_id": recipe_id,
        "status": "not_found",
        "recipe": null,
        "would_execute_http": false,
        "success": false,
        "updated_stored_recipe_verification": false,
        "blockers": ["not_found"],
        "errors": [format!("recipe not found: {recipe_id}")],
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
    println!(
        "MCP compile smoke: {}",
        report.mcp_compile_smoke.status.as_str()
    );
    if report.mcp_compile_smoke.requested && !report.mcp_compile_smoke.messages.is_empty() {
        println!("MCP compile smoke messages:");
        for message in &report.mcp_compile_smoke.messages {
            println!("- {message}");
        }
    }
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
        "mcp_compile_smoke": {
            "requested": report.mcp_compile_smoke.requested,
            "status": report.mcp_compile_smoke.status.as_str(),
            "messages": report.mcp_compile_smoke.messages,
        },
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
    println!(
        "Request fingerprint recomputation: {}",
        report.request_fingerprint_status.as_str()
    );
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
        "request_fingerprint_recomputation": report.request_fingerprint_status.as_str(),
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

#[derive(Clone, Debug)]
struct RecipeSummary {
    id: i64,
    name: String,
    method: String,
    url_template: String,
    auth_style: String,
    last_success_status: Option<u16>,
    last_success_at: Option<String>,
    requires_local_re_verification: bool,
    slots: Vec<SlotSummary>,
}

#[derive(Clone, Debug)]
struct SlotSummary {
    name: String,
    location: String,
    required: bool,
    description: String,
    confidence: String,
}

fn recipe_summaries(repository: &AppRepository) -> Result<Vec<RecipeSummary>> {
    repository
        .list_recipes()?
        .into_iter()
        .map(|item| {
            let recipe = repository
                .get_recipe(item.id)?
                .with_context(|| format!("Recipe payload missing for id {}", item.id))?;
            Ok(recipe_summary(item.id, &recipe))
        })
        .collect()
}

fn open_existing_recipe_repository(paths: &AppPaths) -> Result<Option<AppRepository>> {
    if !paths.db_path.exists() {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(
        &paths.db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| {
        format!(
            "Could not open existing recipe database {}",
            paths.db_path.display()
        )
    })?;
    Ok(Some(AppRepository::new(connection)))
}

fn open_existing_recipe_repository_for_update(paths: &AppPaths) -> Result<Option<AppRepository>> {
    if !paths.db_path.exists() {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(
        &paths.db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| {
        format!(
            "Could not open existing recipe database for update {}",
            paths.db_path.display()
        )
    })?;
    Ok(Some(AppRepository::new(connection)))
}

fn recipe_summary(id: i64, recipe: &Recipe) -> RecipeSummary {
    RecipeSummary {
        id,
        name: recipe.name.clone(),
        method: recipe.method.to_ascii_uppercase(),
        url_template: sanitized_agent_url_template(recipe),
        auth_style: recipe.auth_style.label().to_string(),
        last_success_status: recipe.last_success_status,
        last_success_at: recipe.last_success_at.map(|value| value.to_rfc3339()),
        requires_local_re_verification: !has_successful_verification_fields(
            recipe.last_success_at.is_some(),
            recipe.last_success_status,
        ),
        slots: recipe
            .slots
            .iter()
            .map(|slot| SlotSummary {
                name: slot.name.clone(),
                location: slot.location.label().to_string(),
                required: slot.required,
                description: slot.description.clone(),
                confidence: slot.confidence.label().to_string(),
            })
            .collect(),
    }
}

fn has_successful_verification_fields(has_last_success_at: bool, status: Option<u16>) -> bool {
    has_last_success_at && matches!(status, Some(200..=299))
}

fn print_recipe_list_report(recipes: &[RecipeSummary]) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: recipe-list");
    println!("Recipes: {}", recipes.len());
    for recipe in recipes {
        println!("- ID: {}", recipe.id);
        println!("  Recipe: {}", recipe.name);
        println!("  Method: {}", recipe.method);
        println!("  URL template: {}", recipe.url_template);
        println!("  Auth style: {}", recipe.auth_style);
        println!(
            "  Last successful verification status: {}",
            optional_status(recipe.last_success_status)
        );
        println!(
            "  Last successful verification time: {}",
            recipe.last_success_at.as_deref().unwrap_or("n/a")
        );
        println!(
            "  Requires local re-verification: {}",
            yes_no(recipe.requires_local_re_verification)
        );
    }
}

fn print_recipe_list_json(recipes: &[RecipeSummary]) -> Result<()> {
    print_json(&json!({
        "product": "FirstCall Agent Recipes",
        "mode": "recipe-list",
        "recipes": recipes.iter().map(|recipe| json!({
            "id": recipe.id,
            "name": recipe.name,
            "method": recipe.method,
            "url_template": recipe.url_template,
            "auth_style": recipe.auth_style,
            "last_success_status": recipe.last_success_status,
            "last_success_at": recipe.last_success_at,
            "requires_local_re_verification": recipe.requires_local_re_verification,
        })).collect::<Vec<_>>(),
    }))
}

fn print_recipe_show_report(recipe: Option<&RecipeSummary>, recipe_id: i64) {
    println!("Product: FirstCall Agent Recipes");
    println!("Mode: recipe-show");
    println!("Recipe id: {recipe_id}");
    let Some(recipe) = recipe else {
        println!("Status: not_found");
        return;
    };
    println!("Recipe: {}", recipe.name);
    println!("Method: {}", recipe.method);
    println!("URL template: {}", recipe.url_template);
    println!("Auth style: {}", recipe.auth_style);
    println!(
        "Last successful verification status: {}",
        optional_status(recipe.last_success_status)
    );
    println!(
        "Last successful verification time: {}",
        recipe.last_success_at.as_deref().unwrap_or("n/a")
    );
    println!(
        "Requires local re-verification: {}",
        yes_no(recipe.requires_local_re_verification)
    );
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
            println!(
                "- {} ({}, {})",
                slot.name,
                slot.location,
                if slot.required {
                    "required"
                } else {
                    "optional"
                }
            );
        }
    }
}

fn print_recipe_show_json(recipe: Option<&RecipeSummary>, recipe_id: i64) -> Result<()> {
    if let Some(recipe) = recipe {
        print_json(&json!({
            "product": "FirstCall Agent Recipes",
            "mode": "recipe-show",
            "recipe": {
                "id": recipe.id,
                "name": recipe.name,
                "method": recipe.method,
                "url_template": recipe.url_template,
                "auth_style": recipe.auth_style,
                "last_success_status": recipe.last_success_status,
                "last_success_at": recipe.last_success_at,
                "requires_local_re_verification": recipe.requires_local_re_verification,
                "slots": recipe.slots.iter().map(|slot| json!({
                    "name": slot.name,
                    "location": slot.location,
                    "required": slot.required,
                    "description": slot.description,
                    "confidence": slot.confidence,
                })).collect::<Vec<_>>(),
            },
        }))
    } else {
        print_json(&json!({
            "product": "FirstCall Agent Recipes",
            "mode": "recipe-show",
            "recipe": null,
            "status": "not_found",
            "recipe_id": recipe_id,
        }))
    }
}

fn optional_status(status: Option<u16>) -> String {
    status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string())
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

fn required_i64_arg(args: &[String], flag: &str) -> Result<i64> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].parse::<i64>())
        .transpose()
        .with_context(|| format!("invalid value for {flag}"))?
        .with_context(|| format!("missing required argument {flag}"))
}

fn optional_i64_arg(args: &[String], flag: &str) -> Result<Option<i64>> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].parse::<i64>())
        .transpose()
        .with_context(|| format!("invalid value for {flag}"))
}

fn storage_paths_from_args(args: &[String]) -> Result<AppPaths> {
    let data_dir = optional_path_arg(args, "--data-dir");
    let config_dir = optional_path_arg(args, "--config-dir");
    match (data_dir, config_dir) {
        (Some(data_dir), Some(config_dir)) => AppPaths::from_root(&data_dir, &config_dir),
        (None, None) => AppPaths::discover(),
        _ => bail!("--data-dir and --config-dir must be provided together"),
    }
}

fn print_help() {
    eprintln!(
        "Usage:
  firstcall-cli version
  firstcall-cli explain --recipe-json PATH
  firstcall-cli package --recipe-json PATH --out DIR
  firstcall-cli serve --package DIR [--allow-mutating]
  firstcall-cli package --recipe-id ID --out DIR [--data-dir PATH --config-dir PATH]
  firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating] [--json]
  firstcall-cli verify --recipe-json PATH [--allow-mutating] [--dry-run|--preflight] [--json]
  firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--json]
  firstcall-cli verify --recipe-id ID [--data-dir PATH --config-dir PATH] [--allow-mutating] [--dry-run|--preflight] [--json]
  firstcall-cli validate-package --dir PATH [--json] [--mcp-compile-smoke]
  firstcall-cli inspect-package --dir PATH [--json]
  firstcall-cli import-package --dir PATH [--data-dir PATH --config-dir PATH] [--json]
  firstcall-cli recipe-list [--data-dir PATH --config-dir PATH] [--json]
  firstcall-cli recipe-show --id ID [--data-dir PATH --config-dir PATH] [--json]"
    );
}

enum PackageSource {
    RecipeJson(PathBuf),
    RecipeId(i64),
}

enum VerifySource {
    RecipeJson(PathBuf),
    RecipeId(i64),
}
