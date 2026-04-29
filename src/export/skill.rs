use crate::model::{BodyTemplate, Recipe};

use super::agent_common::{
    PRODUCT_LABEL, TAGLINE, all_env_requirements, destructive_method, export_slots,
};

pub fn recipe_to_skill_markdown(recipe: &Recipe) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# Tool: {}", recipe.name));
    lines.push(String::new());
    lines.push(format!("This is a verified {PRODUCT_LABEL} API recipe."));
    lines.push(TAGLINE.to_string());
    lines.push(String::new());
    lines.push("## When to use".to_string());
    lines.push(format!(
        "Use this tool when an agent needs to call `{}`.",
        recipe.name
    ));
    lines.push(String::new());
    lines.push("## Inputs".to_string());
    let slots = export_slots(&recipe.slots);
    if slots.is_empty() {
        lines.push("- none".to_string());
    } else {
        for slot in slots {
            lines.push(format!(
                "- {}: {}, {}",
                slot.name,
                if slot.required {
                    "required"
                } else {
                    "optional"
                },
                slot.location
            ));
        }
    }
    lines.push(String::new());
    lines.push("## Environment variables".to_string());
    let env_requirements = all_env_requirements(recipe);
    if env_requirements.is_empty() {
        lines.push("- none".to_string());
    } else {
        for item in env_requirements {
            lines.push(format!("- {}: required, {}", item.name, item.description));
        }
    }
    lines.push(String::new());
    lines.push("## Request".to_string());
    lines.push(format!("- Method: {}", recipe.method.to_ascii_uppercase()));
    lines.push(format!("- URL: {}", recipe.url_template));
    lines.push(format!("- Body: {}", body_label(&recipe.body_template)));
    lines.push(String::new());
    lines.push("## Safety rules".to_string());
    lines.push("- Do not log raw secrets.".to_string());
    lines.push("- Do not call endpoints outside the recipe URL template.".to_string());
    lines.push("- Do not mutate fields not listed in the recipe body template.".to_string());
    if destructive_method(&recipe.method) {
        lines.push("- Ask for confirmation before running this mutating request.".to_string());
    } else {
        lines.push(
            "- Ask for confirmation before destructive operations or changed targets.".to_string(),
        );
    }
    lines.push(String::new());
    lines.push("## Last verification".to_string());
    lines.push(format!(
        "- Status: {}",
        recipe
            .last_success_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unverified".to_string())
    ));
    lines.push(format!(
        "- Time: {}",
        recipe
            .last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "unverified".to_string())
    ));
    lines.join("\n")
}

fn body_label(body: &BodyTemplate) -> &'static str {
    match body {
        BodyTemplate::None => "none",
        BodyTemplate::Json { .. } => "json",
        BodyTemplate::Text { .. } => "text",
        BodyTemplate::Form { .. } => "form",
        BodyTemplate::Multipart { .. } => "multipart",
    }
}
