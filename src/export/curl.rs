use anyhow::Result;

use crate::model::{AuthStyle, BodyTemplate, HeaderField, KeyValueField, Recipe};

pub fn recipe_to_curl(recipe: &Recipe) -> Result<String> {
    let mut parts = vec!["curl".to_string(), recipe.url_template.clone()];
    parts.push("-X".to_string());
    parts.push(recipe.method.clone());

    for header in &recipe.headers_template {
        parts.push("-H".to_string());
        parts.push(format!("{}: {}", header.key, header.value));
    }

    match &recipe.auth_style {
        AuthStyle::Bearer { token_slot, .. } => {
            parts.push("-H".to_string());
            parts.push(format!("Authorization: Bearer {{{{{token_slot}}}}}"));
        }
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => {
            parts.push("-u".to_string());
            parts.push(format!("{{{{{username_slot}}}}}:{{{{{password_slot}}}}}"));
        }
        AuthStyle::HeaderApiKey {
            header_name,
            slot_name,
        } => {
            parts.push("-H".to_string());
            parts.push(format!("{header_name}: {{{{{slot_name}}}}}"));
        }
        AuthStyle::QueryApiKey {
            param_name,
            slot_name,
        } => {
            let separator = if recipe.url_template.contains('?') {
                "&"
            } else {
                "?"
            };
            parts[1] = format!(
                "{}{}{}={{{{{}}}}}",
                recipe.url_template, separator, param_name, slot_name
            );
        }
        AuthStyle::None => {}
    }

    if !recipe.query_template.is_empty() {
        let query_text = render_query(&recipe.query_template);
        let separator = if parts[1].contains('?') { "&" } else { "?" };
        parts[1] = format!("{}{}{}", parts[1], separator, query_text);
    }

    match &recipe.body_template {
        BodyTemplate::None => {}
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            parts.push("-d".to_string());
            parts.push(template.clone());
        }
        BodyTemplate::Form { fields } => {
            parts.push("-d".to_string());
            parts.push(render_query(fields));
        }
        BodyTemplate::Multipart { fields } => {
            for field in fields {
                parts.push("--form".to_string());
                parts.push(format!("{}={}", field.key, field.value));
            }
        }
    }

    shlex::try_join(parts.iter().map(String::as_str)).map_err(anyhow::Error::from)
}

fn render_query(query: &[KeyValueField]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for item in query {
        serializer.append_pair(&item.key, &item.value);
    }
    serializer.finish()
}

#[allow(dead_code)]
fn render_headers(headers: &[HeaderField]) -> Vec<String> {
    headers
        .iter()
        .map(|header| format!("{}: {}", header.key, header.value))
        .collect()
}
