use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use firstcall::export::agent_package::{export_agent_package, is_agent_export_eligible};
use firstcall::model::Recipe;

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
    println!("URL template: {}", recipe.url_template);
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

fn required_path_arg(args: &[String], flag: &str) -> Result<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .with_context(|| format!("missing required argument {flag}"))
}

fn print_help() {
    eprintln!(
        "Usage:
  firstcall-cli version
  firstcall-cli explain --recipe-json PATH
  firstcall-cli package --recipe-json PATH --out DIR"
    );
}
