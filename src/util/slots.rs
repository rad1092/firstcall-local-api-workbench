use std::collections::{BTreeSet, HashMap};

use once_cell::sync::Lazy;
use regex::Regex;

static SLOT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\{\{\s*([a-zA-Z0-9_\-]+)\s*\}\}").expect("slot regex"));

pub fn slot_token(name: &str) -> String {
    format!("{{{{{}}}}}", name)
}

pub fn extract_slot_names(text: &str) -> Vec<String> {
    let mut slots = BTreeSet::new();
    for captures in SLOT_PATTERN.captures_iter(text) {
        if let Some(name) = captures.get(1) {
            slots.insert(name.as_str().trim().to_string());
        }
    }
    slots.into_iter().collect()
}

pub fn replace_slots(text: &str, values: &HashMap<String, String>) -> (String, Vec<String>) {
    let mut missing = Vec::new();
    let rendered = SLOT_PATTERN
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let key = captures[1].trim().to_string();
            match values.get(&key) {
                Some(value) if !value.trim().is_empty() => value.to_string(),
                _ => {
                    missing.push(key.clone());
                    captures[0].to_string()
                }
            }
        })
        .to_string();
    (rendered, missing)
}

pub fn looks_like_slot_value(value: &str) -> bool {
    SLOT_PATTERN.is_match(value)
}

pub fn normalize_method(method: &str) -> String {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        "GET".to_string()
    } else {
        trimmed.to_uppercase()
    }
}
