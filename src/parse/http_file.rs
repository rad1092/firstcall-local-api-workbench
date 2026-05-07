use serde_json::{Map, Value, json};

use crate::exec::redact::{is_secret_key, redact_body, redact_free_text};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::util::{normalize_method, slot_token};

const HTTP_FILE_REDACTED_INPUT: &str = "<http file input redacted>";

pub fn parse_http_file_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::HttpFile,
        raw_text: HTTP_FILE_REDACTED_INPUT.to_string(),
    };
    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    if raw_text.trim().is_empty() {
        notes.push("HTTP file input is empty".to_string());
        return ParsedSource {
            source,
            candidates,
            notes,
        };
    }

    for section in split_sections(raw_text) {
        if section.lines.iter().all(|line| line.trim().is_empty()) {
            continue;
        }
        if let Some(draft) = section_to_draft(&section, &mut notes) {
            candidates.push(draft);
        }
    }

    if candidates.is_empty() {
        notes.push("HTTP file input did not contain any supported requests".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

struct Section {
    name: Option<String>,
    lines: Vec<String>,
}

#[derive(Clone)]
struct RequestLine {
    method: String,
    target: String,
}

fn split_sections(raw_text: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut current = Section {
        name: None,
        lines: Vec::new(),
    };
    for line in raw_text.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = trimmed.strip_prefix("###") {
            if current.name.is_some() || !current.lines.is_empty() {
                sections.push(current);
            }
            current = Section {
                name: safe_request_name(name.trim()),
                lines: Vec::new(),
            };
        } else {
            current.lines.push(line.to_string());
        }
    }
    if current.name.is_some() || !current.lines.is_empty() {
        sections.push(current);
    }
    sections
}

fn section_to_draft(section: &Section, notes: &mut Vec<String>) -> Option<RequestDraft> {
    let mut request_line = None::<(usize, RequestLine)>;
    let mut inline_name = None::<String>;
    let mut skipping_script = false;
    for (index, line) in section.lines.iter().enumerate() {
        let trimmed = line.trim();
        if skipping_script {
            if trimmed.contains("%}") {
                skipping_script = false;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix("# @name") {
            inline_name = safe_request_name(name.trim());
            continue;
        }
        if is_comment(trimmed) {
            continue;
        }
        if is_variable_declaration(trimmed) {
            notes.push("Ignored HTTP file variable declaration".to_string());
            continue;
        }
        if is_script_start(trimmed) {
            notes.push("Ignored HTTP file script block".to_string());
            if !trimmed.contains("%}") {
                skipping_script = true;
            }
            continue;
        }
        if let Some(parsed) = parse_request_line(trimmed) {
            request_line = Some((index, parsed));
            break;
        }
        notes.push("Skipped unsupported HTTP file line before request line".to_string());
    }

    let Some((request_index, request_line)) = request_line else {
        notes.push("Skipped HTTP file section without request line".to_string());
        return None;
    };

    let mut later_request_line = false;
    for line in &section.lines[request_index + 1..] {
        if parse_request_line(line.trim()).is_some() {
            later_request_line = true;
            break;
        }
    }
    if later_request_line {
        notes.push(
            "HTTP file section contained multiple request lines; parsed the first one".to_string(),
        );
    }

    let ParsedRequestParts {
        headers,
        body_text,
        notes: part_notes,
    } = parse_request_parts(&section.lines[request_index + 1..]);
    notes.extend(part_notes);

    let mut slots = Vec::new();
    let mut auth = AuthStyle::None;
    let UrlParts {
        base_url,
        path,
        query,
        notes: url_notes,
    } = parse_target(&request_line.target, &mut auth, &mut slots);
    notes.extend(url_notes);
    collect_slots_from_template(
        &mut slots,
        &path,
        SlotLocation::Path,
        true,
        "HTTP file URL path",
    );

    let safe_headers = sanitize_headers(headers, &mut auth, &mut slots, notes);
    let body = parse_body(&body_text, &safe_headers, &mut slots);
    collect_body_slots(&mut slots, &body);
    dedupe_slots(&mut slots);

    Some(RequestDraft {
        operation_id: format!("http-file-{}", uuid::Uuid::new_v4()),
        name: request_name(
            section.name.as_ref().or(inline_name.as_ref()),
            &request_line.method,
            &path,
        ),
        method: request_line.method,
        base_url,
        path,
        headers: safe_headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::HttpFile,
            label: "http file request".to_string(),
            detail: "Parsed sanitized request from HTTP file".to_string(),
            confidence: Confidence::Medium,
        }],
        confidence: FieldConfidence {
            overall: Confidence::Medium,
            notes: "Built by the limited static HTTP file parser".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![SourceKind::HttpFile],
    })
}

fn parse_request_line(line: &str) -> Option<RequestLine> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if !is_supported_method(method) {
        return None;
    }
    let target = parts.next()?;
    let suffix = parts.next();
    if suffix.is_some_and(|value| !value.to_ascii_uppercase().starts_with("HTTP/")) {
        return None;
    }
    Some(RequestLine {
        method: normalize_method(method),
        target: target.to_string(),
    })
}

fn is_supported_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

struct ParsedRequestParts {
    headers: Vec<(String, String)>,
    body_text: String,
    notes: Vec<String>,
}

fn parse_request_parts(lines: &[String]) -> ParsedRequestParts {
    let mut headers = Vec::new();
    let mut body_lines = Vec::new();
    let mut notes = Vec::new();
    let mut in_headers = true;
    let mut skipping_script = false;

    for line in lines {
        let trimmed = line.trim();
        if skipping_script {
            if trimmed.contains("%}") {
                skipping_script = false;
            }
            continue;
        }
        if is_script_start(trimmed) {
            notes.push("Ignored HTTP file script block".to_string());
            if !trimmed.contains("%}") {
                skipping_script = true;
            }
            continue;
        }
        if in_headers {
            if trimmed.is_empty() {
                in_headers = false;
                continue;
            }
            if is_comment(trimmed) || is_variable_declaration(trimmed) {
                if is_variable_declaration(trimmed) {
                    notes.push("Ignored HTTP file variable declaration".to_string());
                }
                continue;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
                continue;
            }
            in_headers = false;
            notes.push("HTTP file body started without a blank header separator".to_string());
        }
        body_lines.push(line.to_string());
    }

    ParsedRequestParts {
        headers,
        body_text: body_lines.join("\n").trim().to_string(),
        notes,
    }
}

struct UrlParts {
    base_url: Option<String>,
    path: String,
    query: Vec<KeyValueField>,
    notes: Vec<String>,
}

fn parse_target(target: &str, auth: &mut AuthStyle, slots: &mut Vec<RuntimeSlot>) -> UrlParts {
    let (without_fragment, _) = target
        .split_once('#')
        .map_or((target, None), |(before, after)| (before, Some(after)));
    let (without_query, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, ""), |(before, query)| (before, query));
    let mut notes = Vec::new();
    let (base_url, path) = if let Some(scheme_end) = without_query.find("://") {
        let authority_start = scheme_end + 3;
        let path_start = without_query[authority_start..]
            .find('/')
            .map(|index| authority_start + index)
            .unwrap_or(without_query.len());
        let base_url = without_query[..path_start].to_string();
        let path = without_query
            .get(path_start..)
            .filter(|path| !path.is_empty())
            .unwrap_or("/")
            .to_string();
        (Some(base_url), path)
    } else if without_query.starts_with("{{") {
        notes.push("HTTP file placeholder base URL was left unresolved".to_string());
        (None, without_query.to_string())
    } else {
        let path = if without_query.starts_with('/') {
            without_query.to_string()
        } else {
            format!("/{without_query}")
        };
        (None, path)
    };
    if let Some(base_url) = &base_url {
        collect_slots_from_template(
            slots,
            base_url,
            SlotLocation::Path,
            true,
            "HTTP file base URL",
        );
    }
    let query = parse_query(query, auth, slots);
    UrlParts {
        base_url,
        path,
        query,
        notes,
    }
}

fn parse_query(
    query: &str,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) -> Vec<KeyValueField> {
    let mut fields = Vec::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part
            .split_once('=')
            .map_or((part, ""), |(key, value)| (key, value));
        if let Some(index) = fields
            .iter()
            .position(|existing: &KeyValueField| existing.key == key)
        {
            fields.remove(index);
        }
        push_query_field(&mut fields, key, value, auth, slots);
    }
    fields
}

fn push_query_field(
    fields: &mut Vec<KeyValueField>,
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
                "HTTP file query API key",
            );
            return;
        }
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Query,
            true,
            "HTTP file secret-like query parameter",
        );
        fields.push(key_value_field(
            key,
            &slot_token(&slot_name),
            "HTTP file query parameter",
            Confidence::Medium,
        ));
        return;
    }
    collect_slots_from_template(
        slots,
        value,
        SlotLocation::Query,
        true,
        "HTTP file query parameter",
    );
    fields.push(key_value_field(
        key,
        value,
        "HTTP file query parameter",
        Confidence::High,
    ));
}

fn sanitize_headers(
    headers: Vec<(String, String)>,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
    notes: &mut Vec<String>,
) -> Vec<HeaderField> {
    headers
        .into_iter()
        .filter_map(|(name, value)| {
            if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("set-cookie") {
                notes.push("Skipped HTTP file cookie header".to_string());
                return None;
            }
            if name.eq_ignore_ascii_case("authorization") {
                infer_authorization(&value, &name, auth, slots);
                return None;
            }
            if is_secret_key(&name) {
                if name.eq_ignore_ascii_case("x-api-key") && matches!(auth, AuthStyle::None) {
                    *auth = AuthStyle::HeaderApiKey {
                        header_name: name,
                        slot_name: "api_key".to_string(),
                    };
                    add_slot(
                        slots,
                        "api_key",
                        SlotLocation::Auth,
                        true,
                        "HTTP file header API key",
                    );
                    return None;
                }
                let slot_name = safe_slot_name(&name);
                add_slot(
                    slots,
                    &slot_name,
                    SlotLocation::Header,
                    true,
                    "HTTP file secret-like header",
                );
                return Some(header_field(
                    &name,
                    &slot_token(&slot_name),
                    "HTTP file header",
                    Confidence::Medium,
                ));
            }
            collect_slots_from_template(
                slots,
                &value,
                SlotLocation::Header,
                true,
                "HTTP file header",
            );
            Some(header_field(
                &name,
                &value,
                "HTTP file header",
                Confidence::High,
            ))
        })
        .collect()
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
            "HTTP file bearer auth",
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
            "HTTP file basic auth username",
        );
        add_slot(
            slots,
            "password",
            SlotLocation::Auth,
            true,
            "HTTP file basic auth password",
        );
    } else if matches!(auth, AuthStyle::None) {
        let slot_name = "authorization";
        add_slot(
            slots,
            slot_name,
            SlotLocation::Header,
            true,
            "HTTP file Authorization header",
        );
    }
}

fn parse_body(
    body_text: &str,
    headers: &[HeaderField],
    slots: &mut Vec<RuntimeSlot>,
) -> BodyTemplate {
    if body_text.trim().is_empty() {
        return BodyTemplate::None;
    }
    let content_type = headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.to_ascii_lowercase())
        .unwrap_or_default();
    let parsed_json = serde_json::from_str::<Value>(body_text);
    if (content_type.contains("json") || parsed_json.is_ok())
        && let Ok(value) = parsed_json
    {
        let safe = sanitize_json_value(value, slots, SlotLocation::Body);
        return BodyTemplate::Json {
            template: serde_json::to_string(&safe)
                .unwrap_or_else(|_| redact_body(body_text, Some("application/json"))),
        };
    }
    if content_type.contains("x-www-form-urlencoded") || looks_like_form(body_text) {
        let fields = body_text
            .split('&')
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                let (key, value) = part
                    .split_once('=')
                    .map_or((part, ""), |(key, value)| (key, value));
                form_field(key.trim(), value.trim(), slots)
            })
            .collect::<Vec<_>>();
        if !fields.is_empty() {
            return BodyTemplate::Form { fields };
        }
    }
    let text = redact_body(body_text, None);
    collect_slots_from_template(
        slots,
        &text,
        SlotLocation::Body,
        true,
        "HTTP file text body",
    );
    BodyTemplate::Text { text }
}

fn form_field(key: &str, value: &str, slots: &mut Vec<RuntimeSlot>) -> KeyValueField {
    if is_secret_key(key) {
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Body,
            true,
            "HTTP file secret-like form field",
        );
        return key_value_field(
            key,
            &slot_token(&slot_name),
            "HTTP file form field",
            Confidence::Medium,
        );
    }
    collect_slots_from_template(
        slots,
        value,
        SlotLocation::Body,
        true,
        "HTTP file form field",
    );
    key_value_field(key, value, "HTTP file form field", Confidence::High)
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
                        "HTTP file secret-like JSON field",
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
            collect_slots_from_template(slots, &text, location, true, "HTTP file JSON field");
            Value::String(text)
        }
        other => other,
    }
}

fn collect_body_slots(slots: &mut Vec<RuntimeSlot>, body: &BodyTemplate) {
    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            collect_slots_from_template(
                slots,
                template,
                SlotLocation::Body,
                true,
                "HTTP file body",
            );
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
    for name in extract_http_slots(template) {
        add_slot(slots, &name, location.clone(), required, description);
    }
}

fn extract_http_slots(template: &str) -> Vec<String> {
    let mut slots = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            break;
        };
        let name = after_start[..end].trim();
        if !name.is_empty() && !slots.iter().any(|slot| slot == name) {
            slots.push(name.to_string());
        }
        rest = &after_start[end + 2..];
    }
    slots
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

fn request_name(name: Option<&String>, method: &str, path: &str) -> String {
    if let Some(name) = name {
        return format!("HTTP File {name}");
    }
    format!("HTTP File {} {}", method, path)
}

fn safe_request_name(name: &str) -> Option<String> {
    let name = safe_note_name(name);
    if name.trim().is_empty() || is_secret_key(&name) {
        None
    } else {
        Some(name)
    }
}

fn safe_slot_name(name: &str) -> String {
    let mut output = String::new();
    for character in name.chars() {
        if character == '$' || character == '.' {
            output.push(character);
        } else if character.is_ascii_alphanumeric() {
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
    let redacted = redact_free_text(name);
    redacted
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '_' | '-' | '/' | '.' | ':' | '$')
        })
        .collect::<String>()
}

fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with("//")
}

fn is_variable_declaration(line: &str) -> bool {
    line.starts_with('@') && line.contains('=')
}

fn is_script_start(line: &str) -> bool {
    (line.starts_with("<") || line.starts_with(">")) && line.contains("{%")
}

fn looks_like_form(body: &str) -> bool {
    body.contains('=') && !body.trim_start().starts_with('{')
}

#[cfg(test)]
mod tests {
    use super::parse_http_file_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    const BEARER_SECRET: &str = "http_file_bearer_secret_should_not_leak";
    const API_KEY_SECRET: &str = "http_file_api_key_secret_should_not_leak";
    const COOKIE_SECRET: &str = "http_file_cookie_secret_should_not_leak";
    const QUERY_SECRET: &str = "http_file_query_secret_should_not_leak";
    const BODY_SECRET: &str = "http_file_body_secret_should_not_leak";

    #[test]
    fn empty_and_malformed_inputs_return_notes_and_zero_candidates() {
        let empty = parse_http_file_input("");
        assert_eq!(empty.source.kind, SourceKind::HttpFile);
        assert_eq!(empty.source.raw_text, super::HTTP_FILE_REDACTED_INPUT);
        assert!(empty.candidates.is_empty());
        assert!(empty.notes.iter().any(|note| note.contains("empty")));

        let malformed = parse_http_file_input("this is not a request\nbody before request");
        assert!(malformed.candidates.is_empty());
        assert!(
            malformed
                .notes
                .iter()
                .any(|note| note.contains("without request line"))
        );
    }

    #[test]
    fn simple_get_absolute_url_creates_candidate() {
        let parsed = parse_http_file_input(
            r#"
GET https://api.example.com/v1/users/{{user_id}}?verbose=true HTTP/1.1
Accept: application/json
"#,
        );

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
    fn relative_url_creates_candidate_without_base_url() {
        let parsed = parse_http_file_input("GET /v1/users?limit=10");

        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url, None);
        assert_eq!(draft.path, "/v1/users");
        assert!(draft.query.iter().any(|item| item.key == "limit"));
    }

    #[test]
    fn multiple_requests_and_request_names_are_supported() {
        let parsed = parse_http_file_input(
            r#"
### Get users
GET https://api.example.com/users

### ignored
# @name createUser
POST https://api.example.com/users
Content-Type: application/json

{"name":"Ada"}
"#,
        );

        assert_eq!(parsed.candidates.len(), 2);
        assert_eq!(parsed.candidates[0].name, "HTTP File Get users");
        assert_eq!(parsed.candidates[1].name, "HTTP File ignored");
        assert_no_canaries(&parsed);
    }

    #[test]
    fn json_post_body_creates_json_template() {
        let parsed = parse_http_file_input(&format!(
            r#"
POST https://api.example.com/users
Content-Type: application/json

{{"name":"Ada","password":"{BODY_SECRET}","user_id":"{{{{user_id}}}}"}}
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.slots.iter().any(|slot| slot.name == "password"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn form_and_raw_text_bodies_are_detected() {
        let form = parse_http_file_input(&format!(
            r#"
POST https://api.example.com/login
Content-Type: application/x-www-form-urlencoded

username=ada&password={BODY_SECRET}
"#
        ));
        let BodyTemplate::Form { fields } = &form.candidates[0].body else {
            panic!("expected form body");
        };
        assert!(
            fields
                .iter()
                .any(|field| { field.key == "password" && field.value == "{{password}}" })
        );
        assert_no_canaries(&form);

        let text = parse_http_file_input(
            r#"
POST https://api.example.com/message
Content-Type: text/plain

hello {{name}}
"#,
        );
        assert!(matches!(text.candidates[0].body, BodyTemplate::Text { .. }));
        assert!(
            text.candidates[0]
                .slots
                .iter()
                .any(|slot| slot.name == "name")
        );
    }

    #[test]
    fn authorization_headers_become_auth_without_secret_retention() {
        let bearer = parse_http_file_input(&format!(
            r#"
GET https://api.example.com/me
Authorization: Bearer {BEARER_SECRET}
"#
        ));
        let bearer_draft = &bearer.candidates[0];
        assert!(matches!(bearer_draft.auth, AuthStyle::Bearer { .. }));
        assert!(
            !bearer_draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("authorization"))
        );
        assert_no_canaries(&bearer);

        let basic = parse_http_file_input(
            r#"
GET https://api.example.com/me
Authorization: Basic dXNlcjpwYXNz
"#,
        );
        let basic_draft = &basic.candidates[0];
        assert!(matches!(basic_draft.auth, AuthStyle::Basic { .. }));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "username"));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "password"));
    }

    #[test]
    fn api_key_and_cookie_headers_do_not_leak_values() {
        let parsed = parse_http_file_input(&format!(
            r#"
GET https://api.example.com/keyed
X-API-Key: {API_KEY_SECRET}
Cookie: session={COOKIE_SECRET}
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::HeaderApiKey { .. }));
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("cookie"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("cookie header"))
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn secret_query_values_are_redacted_or_auth_mapped() {
        let parsed = parse_http_file_input(&format!(
            "GET https://api.example.com/users?api_key={API_KEY_SECRET}&token={QUERY_SECRET}&page=1"
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::QueryApiKey { .. }));
        assert!(
            draft
                .query
                .iter()
                .any(|item| { item.key == "token" && item.value == "{{token}}" })
        );
        assert!(draft.query.iter().any(|item| item.key == "page"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn placeholders_and_dynamic_variables_become_unresolved_slots() {
        let parsed = parse_http_file_input(
            r#"
GET {{base_url}}/v1/users/{{user_id}}?request_id={{$uuid}}&ts={{$timestamp}}&env={{$env.USER_ID}}
"#,
        );

        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url, None);
        assert_eq!(draft.path, "{{base_url}}/v1/users/{{user_id}}");
        for expected in ["base_url", "user_id", "$uuid", "$timestamp", "$env.USER_ID"] {
            assert!(
                draft.slots.iter().any(|slot| slot.name == expected),
                "missing slot {expected}"
            );
        }
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("placeholder base URL"))
        );
    }

    #[test]
    fn scripts_and_variable_declarations_are_ignored_without_values() {
        let parsed = parse_http_file_input(&format!(
            r#"
@host = https://api.example.com/{API_KEY_SECRET}
< {{%
GET https://script.example.com/should-not-parse?token={QUERY_SECRET}
%}}
GET https://api.example.com/users

< {{% client.global.set("token", "{BEARER_SECRET}") %}}
> {{%
  client.test("x", function() {{ }});
%}}
"#
        ));

        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(
            parsed.candidates[0].base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("variable declaration"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("script block"))
        );
        assert_no_canaries(&parsed);
    }

    fn assert_no_canaries(parsed: &crate::model::ParsedSource) {
        let serialized = serde_json::to_string(parsed).expect("serialize parsed source");
        for canary in [
            BEARER_SECRET,
            API_KEY_SECRET,
            COOKIE_SECRET,
            QUERY_SECRET,
            BODY_SECRET,
        ] {
            assert!(
                !serialized.contains(canary),
                "{canary} leaked in {serialized}"
            );
        }
    }
}
