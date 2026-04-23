use crate::model::{BodyTemplate, Recipe};

pub fn recipe_to_markdown(recipe: &Recipe) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# {}", recipe.name));
    lines.push(String::new());
    lines.push(format!("Method: `{}`", recipe.method));
    lines.push(format!("URL Template: `{}`", recipe.url_template));
    lines.push(format!("Auth Style: `{}`", recipe.auth_style.label()));
    lines.push(String::new());
    lines.push("## Required Slots".to_string());
    if recipe.slots.is_empty() {
        lines.push("- none".to_string());
    } else {
        for slot in &recipe.slots {
            lines.push(format!(
                "- `{}` ({}, required: {})",
                slot.name,
                slot.location.label(),
                slot.required
            ));
        }
    }
    lines.push(String::new());
    lines.push("## Headers".to_string());
    if recipe.headers_template.is_empty() {
        lines.push("- none".to_string());
    } else {
        for header in &recipe.headers_template {
            lines.push(format!("- `{}`: `{}`", header.key, header.value));
        }
    }
    lines.push(String::new());
    lines.push("## Body Template".to_string());
    match &recipe.body_template {
        BodyTemplate::None => lines.push("`none`".to_string()),
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            lines.push("```".to_string());
            lines.push(template.clone());
            lines.push("```".to_string());
        }
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            for field in fields {
                lines.push(format!("- `{}` = `{}`", field.key, field.value));
            }
        }
    }
    lines.push(String::new());
    lines.push("## Last Success".to_string());
    lines.push(format!(
        "- Timestamp: {}",
        recipe
            .last_success_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "never".to_string())
    ));
    lines.push(format!(
        "- Status: {}",
        recipe
            .last_success_status
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    lines.join("\n")
}
