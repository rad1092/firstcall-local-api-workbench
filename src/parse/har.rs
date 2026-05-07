use serde_json::{Map, Value, json};
use url::Url;

use crate::exec::redact::{is_secret_key, redact_body, redact_free_text};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::parse::graphql::annotate_graphql_draft;
use crate::util::{extract_slot_names, normalize_method, slot_token};

const HAR_REDACTED_INPUT: &str = "<har input redacted>";

pub fn parse_har_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::Har,
        raw_text: HAR_REDACTED_INPUT.to_string(),
    };
    let mut notes = vec![
        "HAR files may contain credentials, cookies, and private request data; FirstCall imports only sanitized request drafts.".to_string(),
    ];
    let mut candidates = Vec::new();

    let value: Value = match serde_json::from_str(raw_text) {
        Ok(value) => value,
        Err(error) => {
            notes.push(format!("HAR input is not valid JSON: {error}"));
            return ParsedSource {
                source,
                candidates,
                notes,
            };
        }
    };

    let Some(entries) = value
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(Value::as_array)
    else {
        notes.push("HAR input does not contain log.entries[]".to_string());
        return ParsedSource {
            source,
            candidates,
            notes,
        };
    };

    for entry in entries {
        if let Some(draft) = entry_to_draft(entry, &mut notes) {
            candidates.push(draft);
        }
    }

    if candidates.is_empty() {
        notes.push("HAR input did not contain any supported HTTP requests".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

fn entry_to_draft(entry: &Value, notes: &mut Vec<String>) -> Option<RequestDraft> {
    let Some(request) = entry.get("request") else {
        notes.push("Skipped HAR entry without request object".to_string());
        return None;
    };
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .map(normalize_method)
        .unwrap_or_else(|| "GET".to_string());
    let Some(raw_url) = request.get("url").and_then(Value::as_str) else {
        notes.push("Skipped HAR request without URL".to_string());
        return None;
    };
    let Ok(url) = Url::parse(raw_url) else {
        notes.push("Skipped HAR request with unsupported URL shape".to_string());
        return None;
    };

    if is_static_asset(&url, entry) {
        notes.push(format!(
            "Skipped static asset request: {} {}",
            method,
            safe_path_for_note(&url)
        ));
        return None;
    }

    let mut slots = Vec::new();
    let base_url = base_url(&url);
    let path = if url.path().is_empty() {
        "/".to_string()
    } else {
        restore_encoded_slot_braces(url.path())
    };
    collect_slots_from_template(&mut slots, &path, SlotLocation::Path, true, "HAR URL path");

    let mut auth = AuthStyle::None;
    let headers = parse_headers(
        request.get("headers"),
        &mut auth,
        &mut slots,
        notes,
        &method,
        &path,
    );
    let query = parse_query(&url, request.get("queryString"), &mut auth, &mut slots);
    let body = parse_post_data(request.get("postData"), &mut slots, notes);
    collect_body_slots(&mut slots, &body);
    dedupe_slots(&mut slots);

    let mut draft = RequestDraft {
        operation_id: format!("har-{}", uuid::Uuid::new_v4()),
        name: format!("HAR {} {}", method, path),
        method,
        base_url,
        path,
        headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::Har,
            label: "har request".to_string(),
            detail: "Parsed sanitized request from HAR entry".to_string(),
            confidence: Confidence::Medium,
        }],
        confidence: FieldConfidence {
            overall: Confidence::Medium,
            notes: "Built by the limited static HAR parser with aggressive redaction".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![SourceKind::Har],
    };
    annotate_graphql_draft(&mut draft);
    Some(draft)
}

fn base_url(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let mut output = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        output.push(':');
        output.push_str(&port.to_string());
    }
    Some(output)
}

fn parse_headers(
    value: Option<&Value>,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
    notes: &mut Vec<String>,
    method: &str,
    path: &str,
) -> Vec<HeaderField> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name").and_then(Value::as_str)?;
                    let value = item
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if name.eq_ignore_ascii_case("cookie")
                        || name.eq_ignore_ascii_case("set-cookie")
                    {
                        notes.push(format!(
                            "Skipped cookie header for HAR request: {} {}",
                            method, path
                        ));
                        return None;
                    }
                    if name.eq_ignore_ascii_case("authorization") {
                        infer_authorization(value, name, auth, slots);
                        return None;
                    }
                    if is_secret_key(name) {
                        if name.eq_ignore_ascii_case("x-api-key") && matches!(auth, AuthStyle::None)
                        {
                            *auth = AuthStyle::HeaderApiKey {
                                header_name: name.to_string(),
                                slot_name: "api_key".to_string(),
                            };
                            add_slot(
                                slots,
                                "api_key",
                                SlotLocation::Auth,
                                true,
                                "HAR header API key",
                            );
                            return None;
                        }
                        let slot_name = safe_slot_name(name);
                        add_slot(
                            slots,
                            &slot_name,
                            SlotLocation::Header,
                            true,
                            "HAR secret-like header",
                        );
                        return Some(header_field(
                            name,
                            &slot_token(&slot_name),
                            "HAR header",
                            Confidence::Medium,
                        ));
                    }
                    let value = redact_header_value_if_needed(name, value);
                    collect_slots_from_template(
                        slots,
                        &value,
                        SlotLocation::Header,
                        true,
                        "HAR header",
                    );
                    Some(header_field(name, &value, "HAR header", Confidence::High))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn infer_authorization(
    value: &str,
    header_name: &str,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("bearer ") {
        *auth = AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: header_name.to_string(),
        };
        add_slot(
            slots,
            "bearer_token",
            SlotLocation::Auth,
            true,
            "HAR bearer auth",
        );
    } else if lower.starts_with("basic ") {
        *auth = AuthStyle::Basic {
            username_slot: "username".to_string(),
            password_slot: "password".to_string(),
        };
        add_slot(
            slots,
            "username",
            SlotLocation::Auth,
            true,
            "HAR basic auth username",
        );
        add_slot(
            slots,
            "password",
            SlotLocation::Auth,
            true,
            "HAR basic auth password",
        );
    } else if matches!(auth, AuthStyle::None) {
        let slot_name = "authorization".to_string();
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Header,
            true,
            "HAR Authorization header",
        );
    }
}

fn parse_query(
    url: &Url,
    query_string: Option<&Value>,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) -> Vec<KeyValueField> {
    let mut query = Vec::new();
    for (key, value) in url.query_pairs() {
        push_query_field(&mut query, &key, &value, auth, slots);
    }
    if let Some(items) = query_string.and_then(Value::as_array) {
        for item in items {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            if let Some(index) = query
                .iter()
                .position(|existing: &KeyValueField| existing.key == name)
            {
                query.remove(index);
            }
            let value = item
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            push_query_field(&mut query, name, value, auth, slots);
        }
    }
    query
}

fn push_query_field(
    query: &mut Vec<KeyValueField>,
    key: &str,
    value: &str,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) {
    if is_secret_key(key) {
        if matches!(auth, AuthStyle::None) && key.to_ascii_lowercase().contains("api") {
            *auth = AuthStyle::QueryApiKey {
                param_name: key.to_string(),
                slot_name: "api_key".to_string(),
            };
            add_slot(
                slots,
                "api_key",
                SlotLocation::Auth,
                true,
                "HAR query API key",
            );
            return;
        }
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Query,
            true,
            "HAR secret-like query parameter",
        );
        query.push(key_value_field(
            key,
            &slot_token(&slot_name),
            "HAR query parameter",
            Confidence::Medium,
        ));
        return;
    }
    collect_slots_from_template(
        slots,
        value,
        SlotLocation::Query,
        true,
        "HAR query parameter",
    );
    query.push(key_value_field(
        key,
        value,
        "HAR query parameter",
        Confidence::High,
    ));
}

fn parse_post_data(
    value: Option<&Value>,
    slots: &mut Vec<RuntimeSlot>,
    notes: &mut Vec<String>,
) -> BodyTemplate {
    let Some(post_data) = value.and_then(Value::as_object) else {
        return BodyTemplate::None;
    };
    let mime_type = post_data
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(params) = post_data.get("params").and_then(Value::as_array)
        && !params.is_empty()
    {
        let fields = parse_post_data_params(params, slots, notes);
        if fields.is_empty() {
            return BodyTemplate::None;
        }
        if mime_type.contains("multipart/form-data") {
            return BodyTemplate::Multipart { fields };
        }
        return BodyTemplate::Form { fields };
    }
    let text = post_data
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return BodyTemplate::None;
    }
    let parsed_json = serde_json::from_str::<Value>(text);
    if (mime_type.contains("json") || parsed_json.is_ok())
        && let Ok(json_body) = parsed_json
    {
        let safe_body = sanitize_json_value(json_body, slots, SlotLocation::Body);
        return BodyTemplate::Json {
            template: serde_json::to_string(&safe_body)
                .unwrap_or_else(|_| redact_body(text, Some("application/json"))),
        };
    }
    if mime_type.contains("x-www-form-urlencoded") || text.contains('=') {
        let fields = url::form_urlencoded::parse(text.as_bytes())
            .map(|(key, value)| form_field(&key, &value, slots))
            .collect::<Vec<_>>();
        if !fields.is_empty() {
            return BodyTemplate::Form { fields };
        }
    }
    BodyTemplate::Text {
        text: redact_body(text, Some(&mime_type)),
    }
}

fn parse_post_data_params(
    params: &[Value],
    slots: &mut Vec<RuntimeSlot>,
    notes: &mut Vec<String>,
) -> Vec<KeyValueField> {
    params
        .iter()
        .filter_map(|param| {
            let name = param.get("name").and_then(Value::as_str)?;
            if param.get("fileName").is_some()
                || param
                    .get("contentType")
                    .and_then(Value::as_str)
                    .is_some_and(is_binary_mime)
            {
                notes.push(format!(
                    "Skipped HAR multipart file field `{}`",
                    safe_note_name(name)
                ));
                return None;
            }
            let value = param
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Some(form_field(name, value, slots))
        })
        .collect()
}

fn form_field(key: &str, value: &str, slots: &mut Vec<RuntimeSlot>) -> KeyValueField {
    if is_secret_key(key) {
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Body,
            true,
            "HAR secret-like form field",
        );
        return key_value_field(
            key,
            &slot_token(&slot_name),
            "HAR form field",
            Confidence::Medium,
        );
    }
    collect_slots_from_template(slots, value, SlotLocation::Body, true, "HAR form field");
    key_value_field(key, value, "HAR form field", Confidence::High)
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
                        "HAR secret-like JSON field",
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
                add_slot(slots, &slot, location.clone(), true, "HAR JSON field");
            }
            Value::String(text)
        }
        other => other,
    }
}

fn collect_body_slots(slots: &mut Vec<RuntimeSlot>, body: &BodyTemplate) {
    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            collect_slots_from_template(slots, template, SlotLocation::Body, true, "HAR body");
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

fn is_static_asset(url: &Url, entry: &Value) -> bool {
    let path = url.path().to_ascii_lowercase();
    let static_extension = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".mjs", ".map",
        ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".mp3",
    ]
    .iter()
    .any(|extension| path.ends_with(extension));
    if static_extension {
        return true;
    }
    entry
        .pointer("/response/content/mimeType")
        .and_then(Value::as_str)
        .is_some_and(is_static_mime)
}

fn is_static_mime(mime: &str) -> bool {
    let mime = mime.to_ascii_lowercase();
    mime.starts_with("image/")
        || mime.starts_with("font/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime == "text/css"
        || mime.contains("javascript")
        || mime == "application/x-javascript"
        || mime == "application/octet-stream"
}

fn is_binary_mime(mime: &str) -> bool {
    let mime = mime.to_ascii_lowercase();
    mime.starts_with("image/")
        || mime.starts_with("font/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime == "application/octet-stream"
}

fn safe_path_for_note(url: &Url) -> String {
    let restored = restore_encoded_slot_braces(url.path());
    let path = restored.as_str();
    if path.is_empty() {
        "/".to_string()
    } else {
        redact_free_text(path)
    }
}

fn restore_encoded_slot_braces(path: &str) -> String {
    path.replace("%7B", "{")
        .replace("%7b", "{")
        .replace("%7D", "}")
        .replace("%7d", "}")
}

fn redact_header_value_if_needed(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        return crate::exec::redact::redact_header_value(key, value);
    }
    value.to_string()
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

#[cfg(test)]
mod tests {
    use super::parse_har_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    const BEARER_SECRET: &str = "har_raw_bearer_secret_should_not_leak";
    const COOKIE_SECRET: &str = "har_cookie_secret_should_not_leak";
    const QUERY_SECRET: &str = "har_query_secret_should_not_leak";
    const BODY_SECRET: &str = "har_body_secret_should_not_leak";
    const RESPONSE_SECRET: &str = "har_response_secret_should_not_leak";

    #[test]
    fn malformed_har_returns_notes_and_zero_candidates_without_panic() {
        let parsed = parse_har_input("{not-json");

        assert_eq!(parsed.source.kind, SourceKind::Har);
        assert_eq!(parsed.source.raw_text, super::HAR_REDACTED_INPUT);
        assert!(parsed.candidates.is_empty());
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("not valid JSON"))
        );
    }

    #[test]
    fn simple_xhr_get_creates_one_candidate() {
        let parsed = parse_har_input(&har_with_entries(&[r#"{
          "request": {
            "method": "GET",
            "url": "https://api.example.com/v1/users/{{user_id}}?verbose=true",
            "headers": [{"name": "Accept", "value": "application/json"}],
            "queryString": []
          },
          "response": {"content": {"mimeType": "application/json", "text": "{\"ok\":true}"}}
        }"#]));

        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.method, "GET");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/v1/users/{{user_id}}");
        assert!(draft.query.iter().any(|item| item.key == "verbose"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn post_json_body_creates_safe_json_template() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "POST",
                "url": "https://api.example.com/v1/users",
                "headers": [{{"name": "Content-Type", "value": "application/json"}}],
                "queryString": [],
                "postData": {{
                  "mimeType": "application/json",
                  "text": "{{\"name\":\"Ada\",\"token\":\"{BODY_SECRET}\",\"user_id\":\"{{{{user_id}}}}\"}}"
                }}
              }},
              "response": {{
                "headers": [{{"name": "X-Response-Token", "value": "{RESPONSE_SECRET}"}}],
                "cookies": [{{"name": "sid", "value": "{RESPONSE_SECRET}"}}],
                "content": {{"mimeType": "application/json", "text": "{{\"secret\":\"{RESPONSE_SECRET}\"}}"}}
              }}
            }}"#
        )]));

        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.slots.iter().any(|slot| slot.name == "token"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn graphql_post_data_is_annotated_safely() {
        let graphql_secret = "graphql_variable_secret_should_not_leak";
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "POST",
                "url": "https://api.example.com/graphql",
                "headers": [{{"name": "Content-Type", "value": "application/json"}}],
                "queryString": [],
                "postData": {{
                  "mimeType": "application/json",
                  "text": "{{\"query\":\"query GetUser($id: ID!) {{ user(id: $id) {{ id }} }}\",\"variables\":{{\"id\":\"{{{{user_id}}}}\",\"access_token\":\"{graphql_secret}\"}},\"operationName\":\"GetUser\"}}"
                }}
              }},
              "response": {{
                "content": {{"mimeType": "application/json", "text": "{{\"secret\":\"{RESPONSE_SECRET}\"}}"}}
              }}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.source_kinds.contains(&SourceKind::Graphql));
        assert!(
            draft
                .evidence
                .iter()
                .any(|item| item.source_kind == SourceKind::Graphql)
        );
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert!(draft.slots.iter().any(|slot| slot.name == "access_token"));
        let serialized = serde_json::to_string(&parsed).expect("serialize parsed source");
        assert!(!serialized.contains(graphql_secret), "{serialized}");
        assert_no_canaries(&parsed);
    }

    #[test]
    fn bearer_authorization_becomes_auth_slot_without_token() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "GET",
                "url": "https://api.example.com/me",
                "headers": [{{"name": "Authorization", "value": "Bearer {BEARER_SECRET}"}}],
                "queryString": []
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| { header.key.eq_ignore_ascii_case("authorization") })
        );
        assert!(
            draft
                .slots
                .iter()
                .any(|slot| slot.name == "bearer_token" && slot.current_value.is_none())
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn x_api_key_header_becomes_safe_auth_metadata() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "GET",
                "url": "https://api.example.com/keyed",
                "headers": [{{"name": "X-API-Key", "value": "{BEARER_SECRET}"}}],
                "queryString": []
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::HeaderApiKey { .. }));
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| { header.key.eq_ignore_ascii_case("x-api-key") })
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn cookie_header_is_not_retained_as_raw_value() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "GET",
                "url": "https://api.example.com/session",
                "headers": [{{"name": "Cookie", "value": "sid={COOKIE_SECRET}"}}],
                "queryString": []
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| { header.key.eq_ignore_ascii_case("cookie") })
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("Skipped cookie header"))
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn secret_query_values_are_converted_to_safe_auth_or_slots() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "GET",
                "url": "https://api.example.com/users?api_key={QUERY_SECRET}&refresh_token=url_secret_should_not_survive&page=1",
                "headers": [],
                "queryString": [
                  {{"name": "refresh_token", "value": "{QUERY_SECRET}"}},
                  {{"name": "page", "value": "2"}}
                ]
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::QueryApiKey { .. }));
        assert!(
            draft
                .query
                .iter()
                .any(|item| { item.key == "refresh_token" && item.value == "{{refresh_token}}" })
        );
        assert!(
            draft
                .query
                .iter()
                .any(|item| { item.key == "page" && item.value == "2" })
        );
        assert_no_canaries(&parsed);
        assert!(
            !serde_json::to_string(&parsed)
                .expect("serialize parsed source")
                .contains("url_secret_should_not_survive")
        );
    }

    #[test]
    fn form_urlencoded_body_redacts_secret_fields() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "POST",
                "url": "https://api.example.com/login",
                "headers": [{{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}}],
                "queryString": [],
                "postData": {{
                  "mimeType": "application/x-www-form-urlencoded",
                  "text": "username=ada&password={BODY_SECRET}"
                }}
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        let BodyTemplate::Form { fields } = &draft.body else {
            panic!("expected form body");
        };
        assert!(
            fields
                .iter()
                .any(|field| { field.key == "password" && field.value == "{{password}}" })
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn static_assets_are_skipped_with_sanitized_notes() {
        let parsed = parse_har_input(&har_with_entries(&[
            r#"{
              "request": {
                "method": "GET",
                "url": "https://example.com/assets/app.js",
                "headers": [],
                "queryString": []
              },
              "response": {"content": {"mimeType": "application/javascript", "text": "console.log('x')"}}
            }"#,
            r#"{
              "request": {
                "method": "GET",
                "url": "https://api.example.com/v1/users",
                "headers": [],
                "queryString": []
              },
              "response": {"content": {"mimeType": "application/json"}}
            }"#,
        ]));

        assert_eq!(parsed.candidates.len(), 1);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| { note.contains("Skipped static asset request: GET /assets/app.js") })
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn multipart_non_file_fields_are_supported_and_file_fields_are_skipped() {
        let parsed = parse_har_input(&har_with_entries(&[&format!(
            r#"{{
              "request": {{
                "method": "POST",
                "url": "https://api.example.com/upload",
                "headers": [],
                "queryString": [],
                "postData": {{
                  "mimeType": "multipart/form-data",
                  "params": [
                    {{"name": "description", "value": "profile"}},
                    {{"name": "token", "value": "{BODY_SECRET}"}},
                    {{"name": "avatar", "fileName": "me.png", "contentType": "image/png"}}
                  ]
                }}
              }},
              "response": {{"content": {{"mimeType": "application/json"}}}}
            }}"#
        )]));

        let draft = &parsed.candidates[0];
        let BodyTemplate::Multipart { fields } = &draft.body else {
            panic!("expected multipart body");
        };
        assert!(fields.iter().any(|field| field.key == "description"));
        assert!(
            fields
                .iter()
                .any(|field| { field.key == "token" && field.value == "{{token}}" })
        );
        assert!(!fields.iter().any(|field| field.key == "avatar"));
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("Skipped HAR multipart file field"))
        );
        assert_no_canaries(&parsed);
    }

    fn har_with_entries(entries: &[&str]) -> String {
        format!(
            r#"{{"log": {{"version": "1.2", "entries": [{}]}}}}"#,
            entries.join(",")
        )
    }

    fn assert_no_canaries(parsed: &crate::model::ParsedSource) {
        let serialized = serde_json::to_string(parsed).expect("serialize parsed source");
        for canary in [
            BEARER_SECRET,
            COOKIE_SECRET,
            QUERY_SECRET,
            BODY_SECRET,
            RESPONSE_SECRET,
        ] {
            assert!(
                !serialized.contains(canary),
                "{canary} leaked in {serialized}"
            );
        }
    }
}
