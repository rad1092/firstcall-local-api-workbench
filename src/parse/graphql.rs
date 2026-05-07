use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Value, json};

use crate::exec::redact::{REDACTED, is_secret_key, redact_free_text};
use crate::model::{
    BodyTemplate, Confidence, EvidenceItem, RequestDraft, RuntimeSlot, SlotLocation, SourceKind,
};
use crate::util::{extract_slot_names, slot_token};

static SECRET_VARIABLE_DEFAULT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        (
            \$
            (?:token|secret|password|api[_-]?key|access[_-]?token|refresh[_-]?token)
            \s*:\s*
            [^=),]+
            \s*=\s*
        )
        "([^"]*)"
        "#,
    )
    .expect("graphql secret default regex")
});

pub fn is_graphql_json_body(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("query"))
        .and_then(Value::as_str)
        .is_some_and(|query| !query.trim().is_empty())
}

pub fn is_graphql_mutation_query(query: &str) -> bool {
    first_graphql_operation_line(query)
        .map(|line| line.to_ascii_lowercase().starts_with("mutation"))
        .unwrap_or(false)
}

pub fn annotate_graphql_draft(draft: &mut RequestDraft) -> bool {
    let BodyTemplate::Json { template } = &draft.body else {
        return false;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(template) else {
        return false;
    };
    if !is_graphql_json_body(&value) {
        return false;
    }

    let is_mutation = value
        .as_object()
        .and_then(|object| object.get("query"))
        .and_then(Value::as_str)
        .map(is_graphql_mutation_query)
        .unwrap_or(false);

    let mut added_slots = Vec::new();
    sanitize_graphql_json_value(&mut value, &mut added_slots, SlotLocation::Body);
    if let Ok(template) = serde_json::to_string(&value) {
        draft.body = BodyTemplate::Json { template };
    }
    draft.slots.extend(added_slots);
    dedupe_slots(&mut draft.slots);

    if !draft.source_kinds.contains(&SourceKind::Graphql) {
        draft.source_kinds.push(SourceKind::Graphql);
    }
    if !draft
        .evidence
        .iter()
        .any(|item| item.source_kind == SourceKind::Graphql)
    {
        draft.evidence.push(EvidenceItem {
            source_kind: SourceKind::Graphql,
            label: "graphql request".to_string(),
            detail: "Detected GraphQL-over-HTTP JSON request body".to_string(),
            confidence: Confidence::Medium,
        });
    }

    append_note(
        &mut draft.confidence.notes,
        "Detected GraphQL-over-HTTP JSON request body",
    );
    if is_mutation {
        append_note(
            &mut draft.confidence.notes,
            "GraphQL operation appears to be a mutation; HTTP method guard behavior is unchanged",
        );
    }
    true
}

fn sanitize_graphql_json_value(
    value: &mut Value,
    slots: &mut Vec<RuntimeSlot>,
    location: SlotLocation,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if key == "query" && child.is_string() {
                    if let Some(query) = child.as_str() {
                        let safe_query = sanitize_graphql_query_text(query, slots);
                        *child = Value::String(safe_query);
                    }
                    continue;
                }

                if is_secret_key(key) {
                    let slot_name = child
                        .as_str()
                        .and_then(|value| extract_slot_names(value).into_iter().next())
                        .unwrap_or_else(|| safe_slot_name(key));
                    add_slot(
                        slots,
                        &slot_name,
                        location.clone(),
                        true,
                        "GraphQL secret-like variable",
                    );
                    *child = json!(slot_token(&slot_name));
                } else {
                    sanitize_graphql_json_value(child, slots, location.clone());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_graphql_json_value(item, slots, location.clone());
            }
        }
        Value::String(text) => {
            for name in extract_slot_names(text) {
                add_slot(
                    slots,
                    &name,
                    location.clone(),
                    true,
                    "GraphQL JSON placeholder",
                );
            }
        }
        _ => {}
    }
}

fn sanitize_graphql_query_text(query: &str, slots: &mut Vec<RuntimeSlot>) -> String {
    let redacted = SECRET_VARIABLE_DEFAULT_RE
        .replace_all(query, |captures: &regex::Captures<'_>| {
            format!(
                "{}\"{}\"",
                captures.get(1).map(|value| value.as_str()).unwrap_or(""),
                REDACTED
            )
        })
        .to_string();
    let redacted = redact_free_text(&redacted);
    for name in extract_slot_names(&redacted) {
        add_slot(
            slots,
            &name,
            SlotLocation::Body,
            true,
            "GraphQL query placeholder",
        );
    }
    redacted
}

fn first_graphql_operation_line(query: &str) -> Option<&str> {
    query
        .lines()
        .map(str::trim_start)
        .find(|line| !line.trim().is_empty() && !line.starts_with('#'))
}

fn append_note(notes: &mut String, note: &str) {
    if notes.contains(note) {
        return;
    }
    if !notes.trim().is_empty() {
        notes.push_str("; ");
    }
    notes.push_str(note);
}

fn add_slot(
    slots: &mut Vec<RuntimeSlot>,
    name: &str,
    location: SlotLocation,
    required: bool,
    description: &str,
) {
    slots.push(RuntimeSlot {
        name: name.to_string(),
        location,
        required,
        current_value: None,
        description: description.to_string(),
        confidence: Confidence::Medium,
    });
}

fn safe_slot_name(key: &str) -> String {
    let sanitized = key
        .trim()
        .trim_matches(|character: char| !character.is_ascii_alphanumeric())
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if sanitized.is_empty() {
        "graphql_value".to_string()
    } else {
        sanitized
    }
}

fn dedupe_slots(slots: &mut Vec<RuntimeSlot>) {
    let mut unique = Vec::<RuntimeSlot>::new();
    for slot in slots.drain(..) {
        if !unique
            .iter()
            .any(|existing| existing.name == slot.name && existing.location == slot.location)
        {
            unique.push(slot);
        }
    }
    *slots = unique;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{annotate_graphql_draft, is_graphql_json_body, is_graphql_mutation_query};
    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, FieldConfidence, RequestDraft, SourceKind,
    };

    const BEARER_SECRET: &str = "graphql_bearer_secret_should_not_leak";
    const VARIABLE_SECRET: &str = "graphql_variable_secret_should_not_leak";
    const BODY_SECRET: &str = "graphql_body_secret_should_not_leak";
    const QUERY_SECRET: &str = "graphql_query_secret_should_not_leak";
    const RESPONSE_SECRET: &str = "graphql_response_secret_should_not_leak";

    #[test]
    fn detects_graphql_json_body_with_query() {
        assert!(is_graphql_json_body(&json!({
            "query": "query GetUser { user { id } }"
        })));
    }

    #[test]
    fn detects_graphql_json_body_with_variables_and_operation_name() {
        assert!(is_graphql_json_body(&json!({
            "query": "query GetUser($id: ID!) { user(id: $id) { id } }",
            "variables": { "id": "{{user_id}}" },
            "operationName": "GetUser"
        })));
    }

    #[test]
    fn does_not_detect_unrelated_json_body() {
        assert!(!is_graphql_json_body(&json!({
            "name": "Ada",
            "variables": { "id": "{{user_id}}" }
        })));
    }

    #[test]
    fn detects_mutation_looking_query_only() {
        assert!(is_graphql_mutation_query(
            "# comment\n mutation CreateUser($name: String!) { createUser(name: $name) { id } }"
        ));
        assert!(!is_graphql_mutation_query(
            "query GetUser($id: ID!) { user(id: $id) { id } }"
        ));
    }

    #[test]
    fn annotation_adds_graphql_evidence_and_mutation_note() {
        let mut draft = draft(json!({
            "query": "mutation CreateUser($name: String!) { createUser(name: $name) { id } }",
            "variables": { "name": "{{name}}" }
        }));

        assert!(annotate_graphql_draft(&mut draft));
        assert!(draft.source_kinds.contains(&SourceKind::Graphql));
        assert!(
            draft
                .evidence
                .iter()
                .any(|item| item.source_kind == SourceKind::Graphql)
        );
        assert!(draft.confidence.notes.contains("mutation"));
        assert!(draft.slots.iter().any(|slot| slot.name == "name"));
        assert_all_slots_unresolved(&draft);
    }

    #[test]
    fn query_placeholders_and_nested_variable_placeholders_become_slots() {
        let mut draft = draft(json!({
            "query": "query GetUser { user(id: \"{{query_user_id}}\") { id } }",
            "variables": {
                "id": "{{user_id}}",
                "filter": {
                    "tag": "{{tag}}",
                    "nested": ["{{nested_id}}"]
                }
            },
            "operationName": "GetUser"
        }));

        assert!(annotate_graphql_draft(&mut draft));
        for expected in ["query_user_id", "user_id", "tag", "nested_id"] {
            assert!(
                draft.slots.iter().any(|slot| slot.name == expected),
                "missing slot {expected}"
            );
        }
        assert_all_slots_unresolved(&draft);
    }

    #[test]
    fn secret_variable_keys_are_redacted_or_converted_to_slots() {
        let mut draft = draft(json!({
            "query": format!(
                "query Login($password: String = \"{QUERY_SECRET}\") {{ login(password: $password) {{ id }} }}"
            ),
            "variables": {
                "token": BEARER_SECRET,
                "password": VARIABLE_SECRET,
                "secret": BODY_SECRET,
                "refresh_token": RESPONSE_SECRET,
                "name": "{{name}}"
            }
        }));

        assert!(annotate_graphql_draft(&mut draft));
        let serialized = serde_json::to_string(&draft).expect("serialize draft");
        for canary in [
            BEARER_SECRET,
            VARIABLE_SECRET,
            BODY_SECRET,
            QUERY_SECRET,
            RESPONSE_SECRET,
        ] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
        for expected in ["token", "password", "secret", "refresh_token", "name"] {
            assert!(
                draft.slots.iter().any(|slot| slot.name == expected),
                "missing slot {expected}"
            );
        }
        assert_all_slots_unresolved(&draft);
    }

    fn draft(body: serde_json::Value) -> RequestDraft {
        RequestDraft {
            operation_id: "test".to_string(),
            name: "test".to_string(),
            method: "POST".to_string(),
            base_url: Some("https://api.example.com".to_string()),
            path: "/graphql".to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: BodyTemplate::Json {
                template: serde_json::to_string(&body).expect("body json"),
            },
            auth: AuthStyle::None,
            slots: Vec::new(),
            evidence: Vec::new(),
            confidence: FieldConfidence {
                overall: Confidence::Medium,
                notes: "test".to_string(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: vec![SourceKind::HttpFile],
        }
    }

    fn assert_all_slots_unresolved(draft: &RequestDraft) {
        for slot in &draft.slots {
            assert_eq!(slot.current_value, None);
        }
    }
}
