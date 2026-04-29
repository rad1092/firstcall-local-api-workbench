use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::model::Recipe;

use super::agent_yaml::recipe_to_agent_yaml;
use super::mcp_ts::write_mcp_server_package;
use super::policy::recipe_to_policy_json;
use super::skill::recipe_to_skill_markdown;
use super::verified_lock::recipe_to_verified_lock_json;

pub fn is_agent_export_eligible(recipe: &Recipe) -> bool {
    recipe.last_success_at.is_some() && recipe.last_success_status.is_some()
}

pub fn export_agent_package(recipe: &Recipe, out_dir: &Path) -> Result<()> {
    if !is_agent_export_eligible(recipe) {
        bail!("Recipe is not eligible for agent export because it has no successful verification");
    }
    fs::create_dir_all(out_dir)
        .with_context(|| format!("Could not create output directory {}", out_dir.display()))?;
    fs::write(out_dir.join("recipe.yaml"), recipe_to_agent_yaml(recipe)?)?;
    fs::write(
        out_dir.join("verified.lock.json"),
        recipe_to_verified_lock_json(recipe)?,
    )?;
    fs::write(out_dir.join("skill.md"), recipe_to_skill_markdown(recipe))?;
    fs::write(out_dir.join("policy.json"), recipe_to_policy_json(recipe)?)?;
    write_mcp_server_package(recipe, out_dir)?;
    Ok(())
}
