use serde_json::{Map, Value, json};

use crate::exec::redact::{is_secret_key, redact_body};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::parse::graphql::annotate_graphql_draft;
use crate::util::{extract_slot_names, normalize_method, slot_token};

pub fn parse_postman_collection_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::PostmanCollection,
        raw_text: raw_text.to_string(),
    };
    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    let value: Value = match serde_json::from_str(raw_text) {
        Ok(value) => value,
        Err(error) => {
            notes.push(format!("Postman collection is not valid JSON: {error}"));
            return ParsedSource {
                source,
                candidates,
                notes,
            };
        }
    };

    let collection_name = value
        .pointer("/info/name")
        .and_then(Value::as_str)
        .unwrap_or("Postman Collection");
    if has_events(&value) {
        notes.push("Ignored collection-level Postman scripts/tests".to_string());
    }
    let inherited_auth = value.get("auth");
    if let Some(items) = value.get("item").and_then(Value::as_array) {
        visit_items(
            items,
            collection_name,
            &mut Vec::new(),
            inherited_auth,
            &mut candidates,
            &mut notes,
        );
    } else {
        notes.push("Postman collection does not contain an item array".to_string());
    }

    if candidates.is_empty() {
        notes.push("Postman collection did not contain any supported HTTP requests".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

fn visit_items(
    items: &[Value],
    collection_name: &str,
    path: &mut Vec<String>,
    inherited_auth: Option<&Value>,
    candidates: &mut Vec<RequestDraft>,
    notes: &mut Vec<String>,
) {
    for item in items {
        let item_name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Unnamed request")
            .to_string();
        if has_events(item) {
            notes.push(format!(
                "Ignored Postman scripts/tests for {}",
                safe_note_name(&item_name)
            ));
        }
        let item_auth = item.get("auth").or(inherited_auth);

        if let Some(children) = item.get("item").and_then(Value::as_array) {
            path.push(item_name);
            visit_items(
                children,
                collection_name,
                path,
                item_auth,
                candidates,
                notes,
            );
            path.pop();
            continue;
        }

        if let Some(request) = item.get("request") {
            match request_to_draft(collection_name, path, &item_name, request, item_auth, notes) {
                Some(draft) => candidates.push(draft),
                None => notes.push(format!(
                    "Skipped unsupported Postman request {}",
                    safe_note_name(&item_name)
                )),
            }
        }
    }
}

fn request_to_draft(
    collection_name: &str,
    folder_path: &[String],
    item_name: &str,
    request: &Value,
    inherited_auth: Option<&Value>,
    notes: &mut Vec<String>,
) -> Option<RequestDraft> {
    let request_object = request.as_object();
    let method = request_object
        .and_then(|object| object.get("method"))
        .and_then(Value::as_str)
        .map(normalize_method)
        .unwrap_or_else(|| "GET".to_string());
    let url_value = request_object
        .and_then(|object| object.get("url"))
        .or_else(|| {
            if request.is_string() {
                Some(request)
            } else {
                None
            }
        })?;
    let (base_url, path, mut query) = parse_url_value(url_value, notes);
    let mut slots = Vec::new();
    if let Some(base_url) = &base_url {
        collect_slots_from_template(&mut slots, base_url, SlotLocation::Path, true, "Base URL");
    }
    collect_slots_from_template(&mut slots, &path, SlotLocation::Path, true, "URL path");
    for item in &query {
        collect_slots_from_template(
            &mut slots,
            &item.value,
            SlotLocation::Query,
            item.required,
            &item.description,
        );
    }

    let auth_value = request_object
        .and_then(|object| object.get("auth"))
        .or(inherited_auth);
    let (mut auth, mut auth_slots) = parse_auth(auth_value, notes);
    slots.append(&mut auth_slots);

    let mut headers = request_object
        .and_then(|object| object.get("header"))
        .map(|value| parse_headers(value, &mut auth, &mut slots, notes))
        .unwrap_or_default();

    query = query
        .into_iter()
        .filter_map(|item| sanitize_query_field(item, &mut auth, &mut slots))
        .collect();
    headers.retain(|header| !is_auth_generated_header(&auth, &header.key));
    query.retain(|item| !is_auth_generated_query_param(&auth, &item.key));

    let body = request_object
        .and_then(|object| object.get("body"))
        .map(|value| parse_body(value, &mut slots, notes))
        .unwrap_or(BodyTemplate::None);

    collect_body_slots(&mut slots, &body);
    dedupe_slots(&mut slots);

    let mut draft = RequestDraft {
        operation_id: format!("postman-{}", uuid::Uuid::new_v4()),
        name: request_name(collection_name, folder_path, item_name),
        method,
        base_url,
        path,
        headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::PostmanCollection,
            label: "postman request".to_string(),
            detail: format!(
                "Parsed request {} from Postman Collection v2.1",
                safe_note_name(item_name)
            ),
            confidence: Confidence::Medium,
        }],
        confidence: FieldConfidence {
            overall: Confidence::Medium,
            notes: "Built by the limited static Postman Collection parser".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![SourceKind::PostmanCollection],
    };
    annotate_graphql_draft(&mut draft);
    Some(draft)
}

fn parse_url_value(
    value: &Value,
    notes: &mut Vec<String>,
) -> (Option<String>, String, Vec<KeyValueField>) {
    if let Some(raw) = value.as_str() {
        return parse_url_string(raw);
    }
    let Some(object) = value.as_object() else {
        notes.push("Skipped unsupported Postman URL shape".to_string());
        return (None, "/".to_string(), Vec::new());
    };
    let mut parsed = object
        .get("raw")
        .and_then(Value::as_str)
        .filter(|raw| !raw.trim().is_empty())
        .map(parse_url_string)
        .unwrap_or_else(|| build_url_from_object(object));
    parsed.2.extend(parse_query_array(object.get("query")));
    parsed
}

fn parse_url_string(raw: &str) -> (Option<String>, String, Vec<KeyValueField>) {
    let (without_query, query) = raw
        .split_once('?')
        .map_or((raw, ""), |(base, query)| (base, query));
    let query = parse_query_string(query);
    if let Some(scheme_end) = without_query.find("://") {
        let authority_start = scheme_end + 3;
        let rest_start = without_query[authority_start..]
            .find('/')
            .map(|index| authority_start + index)
            .unwrap_or(without_query.len());
        let base_url = without_query[..rest_start].to_string();
        let path = without_query
            .get(rest_start..)
            .filter(|path| !path.is_empty())
            .unwrap_or("/")
            .to_string();
        return (Some(base_url), path, query);
    }
    if let Some(end) = without_query
        .strip_prefix("{{")
        .and_then(|value| value.find("}}"))
    {
        let token_end = end + 4;
        let base_url = without_query[..token_end].to_string();
        let path = without_query[token_end..]
            .strip_prefix('/')
            .map(|path| format!("/{path}"))
            .unwrap_or_else(|| "/".to_string());
        return (Some(base_url), path, query);
    }
    let path = if without_query.starts_with('/') {
        without_query.to_string()
    } else {
        format!("/{without_query}")
    };
    (None, path, query)
}

fn build_url_from_object(
    object: &Map<String, Value>,
) -> (Option<String>, String, Vec<KeyValueField>) {
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let host = object
        .get("host")
        .map(join_postman_segments)
        .filter(|value| !value.trim().is_empty());
    let base_url = host.map(|host| {
        if let Some(protocol) = protocol {
            format!("{protocol}://{host}")
        } else {
            host
        }
    });
    let path = object
        .get("path")
        .map(join_postman_path)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/".to_string());
    (base_url, path, parse_query_array(object.get("query")))
}

fn join_postman_segments(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default()
}

fn join_postman_path(value: &Value) -> String {
    let path = if let Some(text) = value.as_str() {
        text.to_string()
    } else {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_default()
    };
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn parse_query_string(query: &str) -> Vec<KeyValueField> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part
                .split_once('=')
                .map_or((part, ""), |(key, value)| (key, value));
            key_value_field(
                key,
                value,
                "Postman URL query parameter",
                Confidence::Medium,
            )
        })
        .collect()
}

fn parse_query_array(value: Option<&Value>) -> Vec<KeyValueField> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| !is_disabled(item))
                .filter_map(|item| {
                    let key = item.get("key").and_then(Value::as_str)?;
                    let value = item
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some(key_value_field(
                        key,
                        value,
                        "Postman URL query parameter",
                        Confidence::High,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_headers(
    value: &Value,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
    _notes: &mut Vec<String>,
) -> Vec<HeaderField> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| !is_disabled(item))
                .filter_map(|item| {
                    let key = item.get("key").and_then(Value::as_str)?;
                    let value = item
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if key.eq_ignore_ascii_case("authorization")
                        && value.to_ascii_lowercase().starts_with("bearer ")
                    {
                        if matches!(auth, AuthStyle::None) {
                            *auth = AuthStyle::Bearer {
                                token_slot: "bearer_token".to_string(),
                                header_name: key.to_string(),
                            };
                            add_slot(
                                slots,
                                "bearer_token",
                                SlotLocation::Auth,
                                true,
                                "Postman bearer auth",
                            );
                        }
                        return None;
                    }
                    if is_secret_key(key) {
                        if key.eq_ignore_ascii_case("x-api-key") && matches!(auth, AuthStyle::None)
                        {
                            *auth = AuthStyle::HeaderApiKey {
                                header_name: key.to_string(),
                                slot_name: "api_key".to_string(),
                            };
                            add_slot(
                                slots,
                                "api_key",
                                SlotLocation::Auth,
                                true,
                                "Postman header API key",
                            );
                            return None;
                        }
                        let slot_name = safe_slot_name(key);
                        add_slot(
                            slots,
                            &slot_name,
                            SlotLocation::Header,
                            true,
                            "Postman secret-like header",
                        );
                        return Some(header_field(
                            key,
                            &slot_token(&slot_name),
                            "Postman header",
                            Confidence::Medium,
                        ));
                    }
                    Some(header_field(key, value, "Postman header", Confidence::High))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sanitize_query_field(
    item: KeyValueField,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) -> Option<KeyValueField> {
    if is_secret_key(&item.key) {
        if matches!(auth, AuthStyle::None) && item.key.to_ascii_lowercase().contains("api") {
            *auth = AuthStyle::QueryApiKey {
                param_name: item.key.clone(),
                slot_name: "api_key".to_string(),
            };
            add_slot(
                slots,
                "api_key",
                SlotLocation::Auth,
                true,
                "Postman query API key",
            );
            return None;
        }
        let slot_name = safe_slot_name(&item.key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Query,
            true,
            "Postman secret-like query parameter",
        );
        return Some(KeyValueField {
            value: slot_token(&slot_name),
            ..item
        });
    }
    Some(item)
}

fn parse_auth(value: Option<&Value>, notes: &mut Vec<String>) -> (AuthStyle, Vec<RuntimeSlot>) {
    let Some(auth) = value else {
        return (AuthStyle::None, Vec::new());
    };
    let Some(auth_type) = auth.get("type").and_then(Value::as_str) else {
        return (AuthStyle::None, Vec::new());
    };
    let mut slots = Vec::new();
    match auth_type {
        "noauth" => (AuthStyle::None, slots),
        "bearer" => {
            add_slot(
                &mut slots,
                "bearer_token",
                SlotLocation::Auth,
                true,
                "Postman bearer auth",
            );
            (
                AuthStyle::Bearer {
                    token_slot: "bearer_token".to_string(),
                    header_name: "Authorization".to_string(),
                },
                slots,
            )
        }
        "basic" => {
            add_slot(
                &mut slots,
                "username",
                SlotLocation::Auth,
                true,
                "Postman basic auth username",
            );
            add_slot(
                &mut slots,
                "password",
                SlotLocation::Auth,
                true,
                "Postman basic auth password",
            );
            (
                AuthStyle::Basic {
                    username_slot: "username".to_string(),
                    password_slot: "password".to_string(),
                },
                slots,
            )
        }
        "apikey" | "apiKey" => {
            add_slot(
                &mut slots,
                "api_key",
                SlotLocation::Auth,
                true,
                "Postman API key auth",
            );
            let key_name = auth_attribute(auth, "key").unwrap_or_else(|| "x-api-key".to_string());
            let location = auth_attribute(auth, "in").unwrap_or_else(|| "header".to_string());
            if location.eq_ignore_ascii_case("query") {
                (
                    AuthStyle::QueryApiKey {
                        param_name: key_name,
                        slot_name: "api_key".to_string(),
                    },
                    slots,
                )
            } else {
                (
                    AuthStyle::HeaderApiKey {
                        header_name: key_name,
                        slot_name: "api_key".to_string(),
                    },
                    slots,
                )
            }
        }
        other => {
            notes.push(format!(
                "Unsupported Postman auth type `{}` was ignored",
                safe_note_name(other)
            ));
            (AuthStyle::None, slots)
        }
    }
}

fn auth_attribute(auth: &Value, name: &str) -> Option<String> {
    auth.as_object()?.values().find_map(|value| {
        value.as_array()?.iter().find_map(|item| {
            if item.get("key").and_then(Value::as_str)? == name {
                item.get("value")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            } else {
                None
            }
        })
    })
}

fn parse_body(
    value: &Value,
    slots: &mut Vec<RuntimeSlot>,
    notes: &mut Vec<String>,
) -> BodyTemplate {
    let Some(object) = value.as_object() else {
        notes.push("Skipped unsupported Postman body shape".to_string());
        return BodyTemplate::None;
    };
    match object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "raw" => {
            let raw = object
                .get("raw")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if raw.trim().is_empty() {
                return BodyTemplate::None;
            }
            if let Ok(json_body) = serde_json::from_str::<Value>(raw) {
                let safe_body = sanitize_json_value(json_body, slots, SlotLocation::Body);
                return BodyTemplate::Json {
                    template: serde_json::to_string(&safe_body)
                        .unwrap_or_else(|_| redact_body(raw, Some("application/json"))),
                };
            }
            BodyTemplate::Text {
                text: redact_body(raw, None),
            }
        }
        "urlencoded" => BodyTemplate::Form {
            fields: parse_body_fields(object.get("urlencoded"), slots, SlotLocation::Body, notes),
        },
        "formdata" => BodyTemplate::Multipart {
            fields: parse_body_fields(object.get("formdata"), slots, SlotLocation::Body, notes),
        },
        "" => BodyTemplate::None,
        other => {
            notes.push(format!(
                "Unsupported Postman body mode `{}` was ignored",
                safe_note_name(other)
            ));
            BodyTemplate::None
        }
    }
}

fn parse_body_fields(
    value: Option<&Value>,
    slots: &mut Vec<RuntimeSlot>,
    location: SlotLocation,
    notes: &mut Vec<String>,
) -> Vec<KeyValueField> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| !is_disabled(item))
                .filter_map(|item| {
                    let key = item.get("key").and_then(Value::as_str)?;
                    if item.get("type").and_then(Value::as_str) == Some("file")
                        || item.get("src").is_some()
                    {
                        notes.push(format!(
                            "Skipped Postman file formdata field `{}`",
                            safe_note_name(key)
                        ));
                        return None;
                    }
                    let value = item
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if is_secret_key(key) {
                        let slot_name = safe_slot_name(key);
                        add_slot(
                            slots,
                            &slot_name,
                            location.clone(),
                            true,
                            "Postman secret-like body field",
                        );
                        return Some(key_value_field(
                            key,
                            &slot_token(&slot_name),
                            "Postman body field",
                            Confidence::Medium,
                        ));
                    }
                    Some(key_value_field(
                        key,
                        value,
                        "Postman body field",
                        Confidence::High,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sanitize_json_value(
    value: Value,
    slots: &mut Vec<RuntimeSlot>,
    location: SlotLocation,
) -> Value {
    match value {
        Value::Object(object) => {
            let mut safe = Map::new();
            for (key, value) in object {
                if is_secret_key(&key) {
                    let slot_name = safe_slot_name(&key);
                    add_slot(
                        slots,
                        &slot_name,
                        location.clone(),
                        true,
                        "Postman secret-like JSON field",
                    );
                    safe.insert(key, json!(slot_token(&slot_name)));
                } else {
                    safe.insert(key, sanitize_json_value(value, slots, location.clone()));
                }
            }
            Value::Object(safe)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| sanitize_json_value(item, slots, location.clone()))
                .collect(),
        ),
        Value::String(text) => {
            for slot in extract_slot_names(&text) {
                add_slot(slots, &slot, location.clone(), true, "Postman JSON field");
            }
            Value::String(text)
        }
        other => other,
    }
}

fn collect_body_slots(slots: &mut Vec<RuntimeSlot>, body: &BodyTemplate) {
    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            collect_slots_from_template(slots, template, SlotLocation::Body, true, "Postman body");
        }
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            for field in fields {
                collect_slots_from_template(
                    slots,
                    &field.value,
                    SlotLocation::Body,
                    field.required,
                    &field.description,
                );
            }
        }
        BodyTemplate::None => {}
    }
}

fn collect_slots_from_template(
    slots: &mut Vec<RuntimeSlot>,
    template: &str,
    location: SlotLocation,
    required: bool,
    description: &str,
) {
    for name in extract_slot_names(template) {
        add_slot(slots, &name, location.clone(), required, description);
    }
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
        confidence: Confidence::High,
    });
}

fn dedupe_slots(slots: &mut Vec<RuntimeSlot>) {
    let mut unique = Vec::new();
    for slot in slots.drain(..) {
        if !unique.iter().any(|existing: &RuntimeSlot| {
            existing.name == slot.name && existing.location == slot.location
        }) {
            unique.push(slot);
        }
    }
    *slots = unique;
}

fn is_auth_generated_header(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::Bearer { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::Basic { .. } => key.eq_ignore_ascii_case("authorization"),
        AuthStyle::HeaderApiKey { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::None | AuthStyle::QueryApiKey { .. } => false,
    }
}

fn is_auth_generated_query_param(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::QueryApiKey { param_name, .. } => param_name.eq_ignore_ascii_case(key),
        AuthStyle::None
        | AuthStyle::Bearer { .. }
        | AuthStyle::Basic { .. }
        | AuthStyle::HeaderApiKey { .. } => false,
    }
}

fn is_disabled(value: &Value) -> bool {
    value
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn header_field(key: &str, value: &str, description: &str, confidence: Confidence) -> HeaderField {
    HeaderField {
        key: key.to_string(),
        value: value.to_string(),
        required: true,
        description: description.to_string(),
        confidence,
    }
}

fn key_value_field(
    key: &str,
    value: &str,
    description: &str,
    confidence: Confidence,
) -> KeyValueField {
    KeyValueField {
        key: key.to_string(),
        value: value.to_string(),
        required: true,
        description: description.to_string(),
        confidence,
    }
}

fn request_name(collection_name: &str, folder_path: &[String], item_name: &str) -> String {
    let mut parts = Vec::new();
    if !collection_name.trim().is_empty() {
        parts.push(collection_name.to_string());
    }
    parts.extend(folder_path.iter().cloned());
    parts.push(item_name.to_string());
    parts.join(" / ")
}

fn safe_slot_name(name: &str) -> String {
    let mut output = String::new();
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    let output = output.trim_matches('_').to_string();
    if output.is_empty() {
        "value".to_string()
    } else {
        output
    }
}

fn safe_note_name(name: &str) -> String {
    name.chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '_' | '-' | '/' | '.' | ':')
        })
        .collect::<String>()
}

fn has_events(value: &Value) -> bool {
    value
        .get("event")
        .and_then(Value::as_array)
        .is_some_and(|events| !events.is_empty())
}

#[cfg(test)]
mod tests {
    use super::parse_postman_collection_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    const RAW_SECRET: &str = "sk_postman_raw_secret_123";

    #[test]
    fn parses_simple_get_collection() {
        let parsed = parse_postman_collection_input(
            r#"{
              "info": {"name": "Users API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
              "item": [{
                "name": "Get user",
                "request": {
                  "method": "GET",
                  "url": "https://api.example.com/users/{{user_id}}?verbose=true"
                }
              }]
            }"#,
        );

        assert_eq!(parsed.source.kind, SourceKind::PostmanCollection);
        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.method, "GET");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/users/{{user_id}}");
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_raw_secret(&parsed);
    }

    #[test]
    fn parses_nested_post_json_body_and_graphql_annotation() {
        let parsed = parse_postman_collection_input(
            r#"{
              "info": {"name": "Nested API"},
              "item": [{
                "name": "Users",
                "item": [{
                  "name": "Create user",
                  "request": {
                    "method": "POST",
                    "url": {"protocol": "https", "host": ["api", "example", "com"], "path": ["users"]},
                    "body": {
                      "mode": "raw",
                      "raw": "{\"query\":\"query User { user { id } }\",\"variables\":{\"name\":\"{{name}}\",\"token\":\"sk_postman_raw_secret_123\"}}"
                    }
                  }
                }]
              }]
            }"#,
        );

        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.method, "POST");
        assert!(draft.name.contains("Users / Create user"));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.source_kinds.contains(&SourceKind::Graphql));
        assert!(
            draft
                .evidence
                .iter()
                .any(|item| item.source_kind == SourceKind::Graphql)
        );
        assert!(draft.slots.iter().any(|slot| slot.name == "token"));
        assert_no_raw_secret(&parsed);
    }

    #[test]
    fn parses_bearer_auth_without_leaking_token() {
        let parsed = parse_postman_collection_input(&format!(
            r#"{{
              "info": {{"name": "Auth API"}},
              "item": [{{
                "name": "Bearer request",
                "request": {{
                  "method": "GET",
                  "auth": {{
                    "type": "bearer",
                    "bearer": [{{"key": "token", "value": "{RAW_SECRET}", "type": "string"}}]
                  }},
                  "url": "https://api.example.com/me"
                }}
              }}]
            }}"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(
            draft
                .slots
                .iter()
                .any(|slot| slot.name == "bearer_token" && slot.current_value.is_none())
        );
        assert_no_raw_secret(&parsed);
    }

    #[test]
    fn parses_api_key_header_and_query_without_leaking_value() {
        let parsed = parse_postman_collection_input(&format!(
            r#"{{
              "info": {{"name": "API Key API"}},
              "item": [
                {{
                  "name": "Header key",
                  "request": {{
                    "method": "GET",
                    "header": [{{"key": "X-API-Key", "value": "{RAW_SECRET}"}}],
                    "url": "https://api.example.com/header"
                  }}
                }},
                {{
                  "name": "Query key",
                  "request": {{
                    "method": "GET",
                    "url": "https://api.example.com/query?api_key={RAW_SECRET}"
                  }}
                }}
              ]
            }}"#
        ));

        assert_eq!(parsed.candidates.len(), 2);
        assert!(matches!(
            parsed.candidates[0].auth,
            AuthStyle::HeaderApiKey { .. }
        ));
        assert!(matches!(
            parsed.candidates[1].auth,
            AuthStyle::QueryApiKey { .. }
        ));
        assert_no_raw_secret(&parsed);
    }

    #[test]
    fn parses_collection_variables_as_slots_not_values() {
        let parsed = parse_postman_collection_input(&format!(
            r#"{{
              "info": {{"name": "Variables API"}},
              "variable": [{{"key": "base_url", "value": "https://secret.example/{RAW_SECRET}"}}],
              "item": [{{
                "name": "Get user",
                "request": {{
                  "method": "GET",
                  "url": "{{{{base_url}}}}/users/{{{{user_id}}}}"
                }}
              }}]
            }}"#
        ));

        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url.as_deref(), Some("{{base_url}}"));
        assert!(draft.slots.iter().any(|slot| slot.name == "base_url"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_raw_secret(&parsed);
    }

    #[test]
    fn scripts_are_not_executed_and_malformed_input_returns_notes() {
        let parsed = parse_postman_collection_input(
            r#"{
              "info": {"name": "Script API"},
              "event": [{"listen": "prerequest", "script": {"exec": ["throw new Error('no')"]}}],
              "item": [{
                "name": "Scripted",
                "event": [{"listen": "test", "script": {"exec": ["pm.test('x')"]}}],
                "request": "https://api.example.com/scripted"
              }]
            }"#,
        );

        assert_eq!(parsed.candidates.len(), 1);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("Ignored collection-level"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("Ignored Postman scripts"))
        );

        let malformed = parse_postman_collection_input("{not-json");
        assert!(malformed.candidates.is_empty());
        assert!(
            malformed
                .notes
                .iter()
                .any(|note| note.contains("not valid JSON"))
        );
    }

    fn assert_no_raw_secret(parsed: &crate::model::ParsedSource) {
        let safe = serde_json::to_string(&(parsed.candidates.clone(), parsed.notes.clone()))
            .expect("serialize safe parsed output");
        assert!(!safe.contains(RAW_SECRET), "{safe}");
    }
}
