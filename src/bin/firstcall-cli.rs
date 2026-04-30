use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use firstcall::export::agent_package::{
    export_agent_package, is_agent_export_eligible, sanitized_agent_url_template,
};
use firstcall::export::package_validation::{PackageValidationReport, validate_agent_package_dir};
use firstcall::export::verified_lock::recipe_to_verified_lock_json;
use firstcall::model::Recipe;
use firstcall::verify::{VerifyOptions, VerifyReport, verify_recipe_with_process_env};

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
            let recipe = read_recipe_json(&recipe_json)?;
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
            let report = validate_agent_package_dir(&package_dir);
            print_package_validation_report(&report);
            if report.is_valid() {
                Ok(())
            } else {
                bail!("package validation failed")
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
  firstcall-cli verify --recipe-json PATH [--out PATH] [--lock-out PATH] [--allow-mutating]
  firstcall-cli validate-package --dir PATH"
    );
}
