use anyhow::Result;

use crate::model::Recipe;

pub fn recipe_to_json(recipe: &Recipe) -> Result<String> {
    serde_json::to_string_pretty(recipe).map_err(anyhow::Error::from)
}
