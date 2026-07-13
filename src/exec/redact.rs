use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashSet, VecDeque};

use serde_json::{Map, Value};

use crate::model::{
    BodyTemplate, HeaderField, KeyValueField, RenderedHeader, RenderedRequest, RequestDraft,
    ResponseSnapshot, RuntimeSlot, SchemaSpec,
};

static SECRET_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(token|secret|password|api[_-]?key|access[_-]?token|refresh[_-]?token)")
        .expect("secret key regex")
});

pub const REDACTED: &str = "<redacted>";

pub fn is_secret_key(key: &str) -> bool {
    SECRET_KEY_RE.is_match(key)
        || matches!(
            key.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
        )
}

pub fn redact_header_value(key: &str, value: &str) -> String {
    if key.eq_ignore_ascii_case("authorization") {
        if let Some((scheme, _)) = value.split_once(' ') {
            return format!("{scheme} {REDACTED}");
        }
        return REDACTED.to_string();
    }
    if is_secret_key(key) {
        return REDACTED.to_string();
    }
    value.to_string()
}

pub fn redact_json_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = Map::new();
            for (key, value) in object {
                if is_secret_key(key) {
                    redacted.insert(key.clone(), Value::String(REDACTED.to_string()));
                } else {
                    redacted.insert(key.clone(), redact_json_value(value));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json_value).collect()),
        _ => value.clone(),
    }
}

pub fn sanitize_response_schema(schema: &SchemaSpec) -> SchemaSpec {
    let secret_ref_targets = secret_local_ref_targets(&schema.schema);
    let mut sanitized_schema = sanitize_schema_node(&schema.schema, false);
    for pointer in secret_ref_targets {
        if let Some(target) = sanitized_schema.pointer_mut(&pointer) {
            remove_secret_exact_values(target);
        }
    }
    SchemaSpec {
        name: schema.name.clone(),
        schema: sanitized_schema,
    }
}

fn secret_local_ref_targets(root: &Value) -> HashSet<String> {
    let mut targets = HashSet::new();
    collect_secret_local_refs(root, false, &mut targets);

    let mut pending = targets.iter().cloned().collect::<VecDeque<_>>();
    while let Some(pointer) = pending.pop_front() {
        let Some(target) = root.pointer(&pointer) else {
            continue;
        };
        let mut transitive = HashSet::new();
        collect_all_local_refs(target, &mut transitive);
        for pointer in transitive {
            if targets.insert(pointer.clone()) {
                pending.push_back(pointer);
            }
        }
    }
    targets
}

fn collect_secret_local_refs(value: &Value, secret_property: bool, refs: &mut HashSet<String>) {
    let Value::Object(object) = value else {
        if let Value::Array(items) = value {
            for item in items {
                collect_secret_local_refs(item, secret_property, refs);
            }
        }
        return;
    };

    if secret_property
        && let Some(pointer) = object
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(local_json_pointer)
    {
        refs.insert(pointer.to_string());
    }

    for (keyword, child) in object {
        match keyword.as_str() {
            "properties" | "patternProperties" | "$defs" | "definitions" => {
                if let Some(children) = child.as_object() {
                    for (name, schema) in children {
                        collect_secret_local_refs(
                            schema,
                            secret_property || is_secret_key(name),
                            refs,
                        );
                    }
                }
            }
            _ => collect_secret_local_refs(child, secret_property, refs),
        }
    }
}

fn collect_all_local_refs(value: &Value, refs: &mut HashSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(pointer) = object
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(local_json_pointer)
            {
                refs.insert(pointer.to_string());
            }
            for child in object.values() {
                collect_all_local_refs(child, refs);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_all_local_refs(item, refs);
            }
        }
        _ => {}
    }
}

fn local_json_pointer(reference: &str) -> Option<&str> {
    reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
}

fn remove_secret_exact_values(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("const");
            object.remove("enum");
            for child in object.values_mut() {
                remove_secret_exact_values(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_secret_exact_values(item);
            }
        }
        _ => {}
    }
}

fn sanitize_schema_node(value: &Value, secret_property: bool) -> Value {
    let Value::Object(object) = value else {
        return value.clone();
    };

    let mut sanitized = Map::new();
    for (key, value) in object {
        match key.as_str() {
            "example" | "examples" | "default" | "$comment" => {}
            "const" | "enum" if secret_property => {}
            "description" => {
                let value = value
                    .as_str()
                    .map(redact_free_text)
                    .map(Value::String)
                    .unwrap_or_else(|| value.clone());
                sanitized.insert(key.clone(), value);
            }
            "properties" | "patternProperties" => {
                sanitized.insert(
                    key.clone(),
                    sanitize_schema_map(value, secret_property, true),
                );
            }
            "$defs" | "definitions" => {
                sanitized.insert(
                    key.clone(),
                    sanitize_schema_map(value, secret_property, true),
                );
            }
            "dependentSchemas" => {
                sanitized.insert(
                    key.clone(),
                    sanitize_schema_map(value, secret_property, false),
                );
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                sanitized.insert(key.clone(), sanitize_schema_array(value, secret_property));
            }
            "items" => {
                let value = match value {
                    Value::Array(_) => sanitize_schema_array(value, secret_property),
                    Value::Object(_) => sanitize_schema_node(value, secret_property),
                    _ => value.clone(),
                };
                sanitized.insert(key.clone(), value);
            }
            "additionalProperties"
            | "unevaluatedProperties"
            | "propertyNames"
            | "contains"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contentSchema" => {
                let value = if value.is_object() {
                    sanitize_schema_node(value, secret_property)
                } else {
                    value.clone()
                };
                sanitized.insert(key.clone(), value);
            }
            _ => {
                sanitized.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(sanitized)
}

fn sanitize_schema_map(value: &Value, secret_property: bool, detect_secret_names: bool) -> Value {
    let Value::Object(object) = value else {
        return value.clone();
    };
    Value::Object(
        object
            .iter()
            .map(|(name, schema)| {
                let secret_property =
                    secret_property || (detect_secret_names && is_secret_key(name));
                (name.clone(), sanitize_schema_node(schema, secret_property))
            })
            .collect(),
    )
}

fn sanitize_schema_array(value: &Value, secret_property: bool) -> Value {
    let Value::Array(items) = value else {
        return value.clone();
    };
    Value::Array(
        items
            .iter()
            .map(|schema| sanitize_schema_node(schema, secret_property))
            .collect(),
    )
}

pub fn redact_request(request: &RenderedRequest) -> RenderedRequest {
    let headers: Vec<RenderedHeader> = request
        .headers
        .iter()
        .map(|header| RenderedHeader {
            key: header.key.clone(),
            value: redact_header_value(&header.key, &header.value),
        })
        .collect();
    let content_type = headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.clone());
    RenderedRequest {
        method: request.method.clone(),
        url: redact_url(&request.url),
        headers,
        body_preview: request
            .body_preview
            .as_deref()
            .map(|body| redact_body(body, content_type.as_deref())),
    }
}

pub fn redact_response(response: &ResponseSnapshot) -> ResponseSnapshot {
    let headers: Vec<RenderedHeader> = response
        .headers
        .iter()
        .map(|header| RenderedHeader {
            key: header.key.clone(),
            value: redact_header_value(&header.key, &header.value),
        })
        .collect();
    let content_type = headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.clone());

    ResponseSnapshot {
        status: response.status,
        headers,
        body_preview: redact_body(&response.body_preview, content_type.as_deref()),
        body_truncated: response.body_truncated,
        bytes_read: response.bytes_read,
        elapsed_ms: response.elapsed_ms,
        validation_errors: response.validation_errors.clone(),
        transport_error: response.transport_error.clone(),
    }
}

pub fn redact_draft_for_storage(draft: &RequestDraft) -> RequestDraft {
    let mut redacted = draft.clone();
    redacted.headers = draft.headers.iter().map(redact_header_field).collect();
    redacted.query = draft.query.iter().map(redact_key_value).collect();
    redacted.body = redact_body_template(&draft.body);
    redacted.slots = draft.slots.iter().map(redact_slot).collect();
    redacted.response_schema = draft.response_schema.as_ref().map(sanitize_response_schema);
    redacted
}

fn redact_slot(slot: &RuntimeSlot) -> RuntimeSlot {
    let mut slot = slot.clone();
    if (slot.location == crate::model::SlotLocation::Auth || is_secret_key(&slot.name))
        && slot.current_value.is_some()
    {
        slot.current_value = Some(REDACTED.to_string());
    }
    slot
}

fn redact_body_template(body: &BodyTemplate) -> BodyTemplate {
    match body {
        BodyTemplate::None => BodyTemplate::None,
        BodyTemplate::Json { template } => BodyTemplate::Json {
            template: redact_body(template, Some("application/json")),
        },
        BodyTemplate::Text { text } => BodyTemplate::Text {
            text: redact_body(text, None),
        },
        BodyTemplate::Form { fields } => BodyTemplate::Form {
            fields: fields.iter().map(redact_key_value).collect(),
        },
        BodyTemplate::Multipart { fields } => BodyTemplate::Multipart {
            fields: fields.iter().map(redact_key_value).collect(),
        },
    }
}

fn redact_key_value(field: &KeyValueField) -> KeyValueField {
    let mut field = field.clone();
    if is_secret_key(&field.key) {
        field.value = REDACTED.to_string();
    }
    field
}

fn redact_header_field(field: &HeaderField) -> HeaderField {
    let mut field = field.clone();
    field.value = redact_header_value(&field.key, &field.value);
    field
}

pub fn redact_body(body: &str, content_type: Option<&str>) -> String {
    let looks_like_json = content_type
        .map(|value| value.to_ascii_lowercase().contains("json"))
        .unwrap_or(false)
        || serde_json::from_str::<Value>(body).is_ok();
    if looks_like_json && let Ok(value) = serde_json::from_str::<Value>(body) {
        return serde_json::to_string_pretty(&redact_json_value(&value))
            .unwrap_or_else(|_| body.to_string());
    }

    if body.contains('=')
        && (body.contains('&') || content_type.unwrap_or_default().contains("form"))
    {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(key, value)| {
                if is_secret_key(&key) {
                    (key.to_string(), REDACTED.to_string())
                } else {
                    (key.to_string(), value.to_string())
                }
            })
            .collect();
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            serializer.append_pair(&key, &value);
        }
        return serializer.finish();
    }

    let pair_regex = Regex::new(
        r#"(?i)("?(token|secret|password|api[_-]?key|access[_-]?token|refresh[_-]?token)"?\s*[:=]\s*)"([^"]+)"|(?i)\b(token|secret|password|api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*([^\s,&]+)"#,
    )
    .expect("pair regex");
    pair_regex
        .replace_all(body, |captures: &regex::Captures<'_>| {
            if captures.get(1).is_some() {
                format!(
                    "{}\"{}\"",
                    captures.get(1).map(|v| v.as_str()).unwrap_or_default(),
                    REDACTED
                )
            } else {
                let key = captures.get(4).map(|v| v.as_str()).unwrap_or_default();
                format!("{key}={REDACTED}")
            }
        })
        .to_string()
}

pub fn redact_free_text(text: &str) -> String {
    let text = redact_body(text, None);
    let header_regex = Regex::new(
        r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*(.+)$",
    )
    .expect("header regex");
    header_regex
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            let key = captures
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            format!(
                "{key}: {}",
                redact_header_value(
                    key,
                    captures
                        .get(2)
                        .map(|value| value.as_str())
                        .unwrap_or_default()
                )
            )
        })
        .to_string()
}

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(key, value)| {
                if is_secret_key(&key) {
                    (key.to_string(), REDACTED.to_string())
                } else {
                    (key.to_string(), value.to_string())
                }
            })
            .collect();
        parsed.set_query(None);
        if !pairs.is_empty() {
            let query = pairs
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("&");
            let mut rendered = parsed.to_string();
            rendered.push('?');
            rendered.push_str(&query);
            return rendered;
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        REDACTED, redact_body, redact_json_value, redact_request, sanitize_response_schema,
    };
    use crate::model::{RenderedHeader, RenderedRequest, SchemaSpec};

    #[test]
    fn redacts_secret_json_fields() {
        let redacted = redact_json_value(&json!({
            "name": "Ada",
            "token": "abc",
            "nested": { "password": "p" }
        }));
        assert_eq!(redacted["token"], REDACTED);
        assert_eq!(redacted["nested"]["password"], REDACTED);
    }

    #[test]
    fn redacts_authorization_header_and_body() {
        let request = RenderedRequest {
            method: "POST".to_string(),
            url: "https://api.example.com?api_key=secret".to_string(),
            headers: vec![
                RenderedHeader {
                    key: "Authorization".to_string(),
                    value: "Bearer secret".to_string(),
                },
                RenderedHeader {
                    key: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
            ],
            body_preview: Some("{\"password\":\"1234\"}".to_string()),
        };
        let redacted = redact_request(&request);
        assert_eq!(redacted.headers[0].value, "Bearer <redacted>");
        assert!(redacted.url.contains("<redacted>"));
        assert!(redacted.body_preview.unwrap().contains(REDACTED));
        assert!(redact_body("token=abc", None).contains(REDACTED));
    }

    #[test]
    fn sanitizes_response_schema_annotations_and_secret_exact_values() {
        let schema = SchemaSpec {
            name: Some("response".to_string()),
            schema: json!({
                "type": "object",
                "description": "Authorization: Bearer description_secret_123",
                "default": { "api_key": "default_secret_123" },
                "examples": [{ "api_key": "example_secret_123" }],
                "$comment": "comment_secret_123",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "const": "const_secret_123",
                        "enum": ["enum_secret_123"],
                        "description": "token=description_secret_456"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["ok", "failed"],
                        "const": { "default": "literal-key-is-not-an-annotation-here" }
                    }
                },
                "$defs": {
                    "access_token": {
                        "type": "string",
                        "enum": ["definition_secret_123"]
                    }
                }
            }),
        };

        let sanitized = sanitize_response_schema(&schema);
        let root = sanitized.schema.as_object().expect("schema object");
        assert!(!root.contains_key("default"));
        assert!(!root.contains_key("examples"));
        assert!(!root.contains_key("$comment"));
        assert_eq!(
            sanitized.schema["description"],
            "Authorization: Bearer <redacted>"
        );

        let api_key = &sanitized.schema["properties"]["api_key"];
        assert!(api_key.get("const").is_none());
        assert!(api_key.get("enum").is_none());
        assert!(api_key["description"].as_str().unwrap().contains(REDACTED));

        assert_eq!(
            sanitized.schema["properties"]["status"]["enum"],
            json!(["ok", "failed"])
        );
        assert_eq!(
            sanitized.schema["properties"]["status"]["const"]["default"],
            "literal-key-is-not-an-annotation-here"
        );
        assert!(
            sanitized.schema["$defs"]["access_token"]
                .get("enum")
                .is_none()
        );
    }

    #[test]
    fn sanitizes_secret_local_ref_targets_transitively_without_touching_public_enums() {
        let schema = SchemaSpec {
            name: Some("response".to_string()),
            schema: json!({
                "type": "object",
                "properties": {
                    "api_key": { "$ref": "#/$defs/Credential" },
                    "status": { "$ref": "#/definitions/PublicStatus" }
                },
                "$defs": {
                    "Credential": {
                        "allOf": [
                            { "$ref": "#/definitions/SecretLeaf" },
                            { "type": "string", "enum": ["direct-secret"] }
                        ]
                    }
                },
                "definitions": {
                    "SecretLeaf": {
                        "type": "string",
                        "const": "transitive-secret",
                        "enum": ["transitive-secret"]
                    },
                    "PublicStatus": {
                        "type": "string",
                        "enum": ["ok", "failed"]
                    }
                }
            }),
        };

        let sanitized = sanitize_response_schema(&schema);

        assert!(
            sanitized.schema["$defs"]["Credential"]["allOf"][1]
                .get("enum")
                .is_none()
        );
        assert!(
            sanitized.schema["definitions"]["SecretLeaf"]
                .get("const")
                .is_none()
        );
        assert!(
            sanitized.schema["definitions"]["SecretLeaf"]
                .get("enum")
                .is_none()
        );
        assert_eq!(
            sanitized.schema["definitions"]["PublicStatus"]["enum"],
            json!(["ok", "failed"])
        );
    }
}
