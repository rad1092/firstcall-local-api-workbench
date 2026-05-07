use serde_json::{Map, Value, json};

use crate::exec::redact::{is_secret_key, redact_body, redact_header_value};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::util::{normalize_method, slot_token};

const HURL_REDACTED_INPUT: &str = "<hurl input redacted>";

pub fn parse_hurl_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::Hurl,
        raw_text: HURL_REDACTED_INPUT.to_string(),
    };
    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    if raw_text.trim().is_empty() {
        notes.push("Hurl input is empty".to_string());
        return ParsedSource {
            source,
            candidates,
            notes,
        };
    }

    let lines = raw_text.lines().collect::<Vec<_>>();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() || is_comment(trimmed) {
            index += 1;
            continue;
        }
        if parse_request_line(trimmed).is_some() {
            let ParsedRequest { draft, next_index } = parse_request_at(&lines, index, &mut notes);
            candidates.push(draft);
            index = next_index;
            continue;
        }
        if is_response_line(trimmed) {
            index = skip_response_section(&lines, index, &mut notes);
            continue;
        }
        if is_hurl_section(trimmed) {
            index = skip_ignored_section(&lines, index, &mut notes);
            continue;
        }
        notes.push("Skipped unsupported Hurl line before request line".to_string());
        index += 1;
    }

    if candidates.is_empty() {
        notes.push("Hurl input did not contain any supported requests".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

#[derive(Clone)]
struct RequestLine {
    method: String,
    target: String,
}

struct ParsedRequest {
    draft: RequestDraft,
    next_index: usize,
}

fn parse_request_at(
    lines: &[&str],
    request_index: usize,
    notes: &mut Vec<String>,
) -> ParsedRequest {
    let request_line = parse_request_line(lines[request_index].trim())
        .expect("request index must point at a supported request line");
    let ParsedRequestParts {
        headers,
        body_text,
        query_pairs,
        form_pairs,
        has_basic_auth,
        next_index,
    } = parse_request_parts(lines, request_index + 1, notes);

    let mut slots = Vec::new();
    let mut auth = AuthStyle::None;
    let UrlParts {
        base_url,
        path,
        mut query,
        notes: url_notes,
    } = parse_target(&request_line.target, &mut auth, &mut slots);
    notes.extend(url_notes);
    collect_slots_from_template(&mut slots, &path, SlotLocation::Path, true, "Hurl URL path");

    if has_basic_auth {
        auth = AuthStyle::Basic {
            username_slot: "username".to_string(),
            password_slot: "password".to_string(),
        };
        add_slot(
            &mut slots,
            "username",
            SlotLocation::Auth,
            true,
            "Hurl BasicAuth username",
        );
        add_slot(
            &mut slots,
            "password",
            SlotLocation::Auth,
            true,
            "Hurl BasicAuth password",
        );
    }

    apply_query_pairs(&mut query, query_pairs, &mut auth, &mut slots);
    let safe_headers = sanitize_headers(headers, &mut auth, &mut slots, notes);
    let body = if form_pairs.is_empty() {
        parse_body(&body_text, &safe_headers, &mut slots)
    } else {
        BodyTemplate::Form {
            fields: form_pairs
                .iter()
                .map(|(key, value)| form_field(key, value, &mut slots))
                .collect(),
        }
    };
    collect_body_slots(&mut slots, &body);
    dedupe_slots(&mut slots);

    let draft = RequestDraft {
        operation_id: format!("hurl-{}", uuid::Uuid::new_v4()),
        name: format!("Hurl {} request", request_line.method),
        method: request_line.method,
        base_url,
        path,
        headers: safe_headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::Hurl,
            label: "hurl request".to_string(),
            detail: "Parsed sanitized request from Hurl input".to_string(),
            confidence: Confidence::Medium,
        }],
        confidence: FieldConfidence {
            overall: Confidence::Medium,
            notes: "Built by the limited static Hurl request-only parser".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![SourceKind::Hurl],
    };

    ParsedRequest { draft, next_index }
}

fn parse_request_line(line: &str) -> Option<RequestLine> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if !is_supported_method(method) {
        return None;
    }
    let target = parts.next()?;
    if parts.next().is_some() {
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
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

struct ParsedRequestParts {
    headers: Vec<(String, String)>,
    body_text: String,
    query_pairs: Vec<(String, String)>,
    form_pairs: Vec<(String, String)>,
    has_basic_auth: bool,
    next_index: usize,
}

fn parse_request_parts(
    lines: &[&str],
    mut index: usize,
    notes: &mut Vec<String>,
) -> ParsedRequestParts {
    let mut headers = Vec::new();
    let mut body_lines = Vec::new();
    let mut query_pairs = Vec::new();
    let mut form_pairs = Vec::new();
    let mut has_basic_auth = false;
    let mut in_headers = true;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if parse_request_line(trimmed).is_some() {
            break;
        }
        if is_response_line(trimmed) {
            index = skip_response_section(lines, index, notes);
            break;
        }
        if is_hurl_section(trimmed) {
            let section = section_name(trimmed).unwrap_or_default();
            match section.as_str() {
                "query" | "querystringparams" => {
                    let ParsedPairs { pairs, next_index } =
                        parse_key_value_section(lines, index + 1);
                    query_pairs.extend(pairs);
                    index = next_index;
                    continue;
                }
                "form" | "formparams" => {
                    let ParsedPairs { pairs, next_index } =
                        parse_key_value_section(lines, index + 1);
                    form_pairs.extend(pairs);
                    index = next_index;
                    continue;
                }
                "basicauth" => {
                    has_basic_auth = true;
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
                "cookies" => {
                    notes.push("Ignored Hurl cookies section".to_string());
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
                "options" => {
                    notes.push("Ignored Hurl options section".to_string());
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
                "captures" => {
                    notes.push("Ignored Hurl captures section".to_string());
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
                "asserts" => {
                    notes.push("Ignored Hurl assertions section".to_string());
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
                _ => {
                    notes.push("Ignored unsupported Hurl section".to_string());
                    index = skip_section_values(lines, index + 1);
                    continue;
                }
            }
        }

        if in_headers {
            if trimmed.is_empty() {
                in_headers = false;
                index += 1;
                continue;
            }
            if is_comment(trimmed) {
                index += 1;
                continue;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && is_header_name(name.trim())
            {
                headers.push((name.trim().to_string(), value.trim().to_string()));
                index += 1;
                continue;
            }
            in_headers = false;
            notes.push("Hurl request body started without a blank header separator".to_string());
        }

        body_lines.push(lines[index].to_string());
        index += 1;
    }

    ParsedRequestParts {
        headers,
        body_text: body_lines.join("\n").trim().to_string(),
        query_pairs,
        form_pairs,
        has_basic_auth,
        next_index: index,
    }
}

struct ParsedPairs {
    pairs: Vec<(String, String)>,
    next_index: usize,
}

fn parse_key_value_section(lines: &[&str], mut index: usize) -> ParsedPairs {
    let mut pairs = Vec::new();
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            index += 1;
            break;
        }
        if parse_request_line(trimmed).is_some()
            || is_response_line(trimmed)
            || is_hurl_section(trimmed)
        {
            break;
        }
        if is_comment(trimmed) {
            index += 1;
            continue;
        }
        if let Some((key, value)) = parse_key_value_line(trimmed) {
            pairs.push((key, value));
        }
        index += 1;
    }
    ParsedPairs {
        pairs,
        next_index: index,
    }
}

fn parse_key_value_line(line: &str) -> Option<(String, String)> {
    let (key, value) = if let Some((key, value)) = line.split_once(':') {
        (key, value)
    } else {
        line.split_once('=')?
    };
    Some((key.trim().to_string(), value.trim().to_string()))
}

fn skip_response_section(lines: &[&str], response_index: usize, notes: &mut Vec<String>) -> usize {
    notes.push("Ignored Hurl response section".to_string());
    let mut index = response_index + 1;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if parse_request_line(trimmed).is_some() {
            break;
        }
        if is_hurl_section(trimmed) {
            let section = section_name(trimmed).unwrap_or_default();
            match section.as_str() {
                "captures" => notes.push("Ignored Hurl captures section".to_string()),
                "asserts" => notes.push("Ignored Hurl assertions section".to_string()),
                "cookies" => notes.push("Ignored Hurl cookies section".to_string()),
                _ => notes.push("Ignored unsupported Hurl response subsection".to_string()),
            }
            index = skip_section_values(lines, index + 1);
            continue;
        }
        index += 1;
    }
    index
}

fn skip_ignored_section(lines: &[&str], index: usize, notes: &mut Vec<String>) -> usize {
    let section = section_name(lines[index].trim()).unwrap_or_default();
    match section.as_str() {
        "captures" => notes.push("Ignored Hurl captures section".to_string()),
        "asserts" => notes.push("Ignored Hurl assertions section".to_string()),
        "cookies" => notes.push("Ignored Hurl cookies section".to_string()),
        "options" => notes.push("Ignored Hurl options section".to_string()),
        _ => notes.push("Ignored unsupported Hurl section".to_string()),
    }
    skip_section_values(lines, index + 1)
}

fn skip_section_values(lines: &[&str], mut index: usize) -> usize {
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            index += 1;
            break;
        }
        if parse_request_line(trimmed).is_some()
            || is_response_line(trimmed)
            || is_hurl_section(trimmed)
        {
            break;
        }
        index += 1;
    }
    index
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
    let notes = Vec::new();
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
    } else {
        let path = if without_query.starts_with('/') {
            without_query.to_string()
        } else {
            format!("/{without_query}")
        };
        (None, path)
    };
    if let Some(base_url) = &base_url {
        collect_slots_from_template(slots, base_url, SlotLocation::Path, true, "Hurl base URL");
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
        push_query_field(&mut fields, key, value, auth, slots);
    }
    fields
}

fn apply_query_pairs(
    fields: &mut Vec<KeyValueField>,
    pairs: Vec<(String, String)>,
    auth: &mut AuthStyle,
    slots: &mut Vec<RuntimeSlot>,
) {
    for (key, value) in pairs {
        if let Some(index) = fields.iter().position(|existing| existing.key == key) {
            fields.remove(index);
        }
        push_query_field(fields, &key, &value, auth, slots);
    }
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
                "Hurl query API key",
            );
            return;
        }
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Query,
            true,
            "Hurl secret-like query parameter",
        );
        fields.push(key_value_field(
            key,
            &slot_token(&slot_name),
            "Hurl query parameter",
            Confidence::Medium,
        ));
        return;
    }
    collect_slots_from_template(
        slots,
        value,
        SlotLocation::Query,
        true,
        "Hurl query parameter",
    );
    fields.push(key_value_field(
        key,
        value,
        "Hurl query parameter",
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
                notes.push("Skipped Hurl cookie header".to_string());
                return None;
            }
            if name.eq_ignore_ascii_case("authorization") {
                infer_authorization(&value, &name, auth, slots);
                return None;
            }
            if is_secret_key(&name) {
                if name.eq_ignore_ascii_case("x-api-key") && matches!(auth, AuthStyle::None) {
                    let slot_name =
                        placeholder_slot_name(&value).unwrap_or_else(|| "api_key".to_string());
                    *auth = AuthStyle::HeaderApiKey {
                        header_name: name,
                        slot_name: slot_name.clone(),
                    };
                    add_slot(
                        slots,
                        &slot_name,
                        SlotLocation::Auth,
                        true,
                        "Hurl header API key",
                    );
                    return None;
                }
                let slot_name = safe_slot_name(&name);
                add_slot(
                    slots,
                    &slot_name,
                    SlotLocation::Header,
                    true,
                    "Hurl secret-like header",
                );
                return Some(header_field(
                    &name,
                    &slot_token(&slot_name),
                    "Hurl header",
                    Confidence::Medium,
                ));
            }
            let value = redact_header_value(&name, &value);
            collect_slots_from_template(slots, &value, SlotLocation::Header, true, "Hurl header");
            Some(header_field(&name, &value, "Hurl header", Confidence::High))
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
        let slot_name = placeholder_slot_name(value).unwrap_or_else(|| "bearer_token".to_string());
        *auth = AuthStyle::Bearer {
            token_slot: slot_name.clone(),
            header_name: header_name.to_string(),
        };
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Auth,
            true,
            "Hurl bearer auth",
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
            "Hurl basic auth username",
        );
        add_slot(
            slots,
            "password",
            SlotLocation::Auth,
            true,
            "Hurl basic auth password",
        );
    } else if matches!(auth, AuthStyle::None) {
        add_slot(
            slots,
            "authorization",
            SlotLocation::Header,
            true,
            "Hurl Authorization header",
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
    collect_slots_from_template(slots, &text, SlotLocation::Body, true, "Hurl text body");
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
            "Hurl secret-like form field",
        );
        return key_value_field(
            key,
            &slot_token(&slot_name),
            "Hurl form field",
            Confidence::Medium,
        );
    }
    collect_slots_from_template(slots, value, SlotLocation::Body, true, "Hurl form field");
    key_value_field(key, value, "Hurl form field", Confidence::High)
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
                        "Hurl secret-like JSON field",
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
            collect_slots_from_template(slots, &text, location, true, "Hurl JSON field");
            Value::String(text)
        }
        other => other,
    }
}

fn collect_body_slots(slots: &mut Vec<RuntimeSlot>, body: &BodyTemplate) {
    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            collect_slots_from_template(slots, template, SlotLocation::Body, true, "Hurl body");
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
    for name in extract_hurl_slots(template) {
        add_slot(slots, &name, location.clone(), required, description);
    }
}

fn extract_hurl_slots(template: &str) -> Vec<String> {
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

fn placeholder_slot_name(value: &str) -> Option<String> {
    extract_hurl_slots(value).into_iter().next()
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

fn is_comment(line: &str) -> bool {
    line.starts_with('#')
}

fn is_response_line(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    if upper == "HTTP *" {
        return true;
    }
    if let Some(rest) = upper.strip_prefix("HTTP/") {
        return rest
            .split_whitespace()
            .nth(1)
            .is_some_and(is_status_or_wildcard);
    }
    upper.strip_prefix("HTTP ").is_some_and(|rest| {
        rest.split_whitespace()
            .next()
            .is_some_and(is_status_or_wildcard)
    })
}

fn is_status_or_wildcard(value: &str) -> bool {
    value == "*" || value.chars().all(|character| character.is_ascii_digit())
}

fn is_hurl_section(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
}

fn section_name(line: &str) -> Option<String> {
    Some(
        line.strip_prefix('[')?
            .strip_suffix(']')?
            .trim()
            .to_ascii_lowercase(),
    )
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn looks_like_form(body: &str) -> bool {
    body.contains('=') && !body.trim_start().starts_with('{')
}

#[cfg(test)]
mod tests {
    use super::parse_hurl_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    const BEARER_SECRET: &str = "hurl_bearer_secret_should_not_leak";
    const API_KEY_SECRET: &str = "hurl_api_key_secret_should_not_leak";
    const COOKIE_SECRET: &str = "hurl_cookie_secret_should_not_leak";
    const QUERY_SECRET: &str = "hurl_query_secret_should_not_leak";
    const BODY_SECRET: &str = "hurl_body_secret_should_not_leak";
    const RESPONSE_SECRET: &str = "hurl_response_secret_should_not_leak";

    #[test]
    fn empty_and_malformed_inputs_return_notes_and_zero_candidates() {
        let empty = parse_hurl_input("");
        assert_eq!(empty.source.kind, SourceKind::Hurl);
        assert_eq!(empty.source.raw_text, super::HURL_REDACTED_INPUT);
        assert!(empty.candidates.is_empty());
        assert!(empty.notes.iter().any(|note| note.contains("empty")));

        let malformed = parse_hurl_input("this is not hurl\n[Options]\nretry: 3");
        assert!(malformed.candidates.is_empty());
        assert!(
            malformed
                .notes
                .iter()
                .any(|note| note.contains("supported requests"))
        );
    }

    #[test]
    fn simple_get_absolute_url_creates_candidate() {
        let parsed = parse_hurl_input(
            r#"
GET https://api.example.com/v1/users/{{user_id}}?verbose=true
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
        assert_all_slots_unresolved(&parsed);
        assert_no_canaries(&parsed);
    }

    #[test]
    fn relative_url_creates_candidate_without_base_url() {
        let parsed = parse_hurl_input("GET /v1/users?limit=10");

        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url, None);
        assert_eq!(draft.path, "/v1/users");
        assert!(draft.query.iter().any(|item| item.key == "limit"));
    }

    #[test]
    fn multiple_request_sections_create_multiple_candidates() {
        let parsed = parse_hurl_input(
            r#"
GET https://api.example.com/users
HTTP 200
{"ignored":"response"}

POST https://api.example.com/users
Content-Type: application/json

{"name":"Ada"}
"#,
        );

        assert_eq!(parsed.candidates.len(), 2);
        assert_eq!(parsed.candidates[0].method, "GET");
        assert_eq!(parsed.candidates[1].method, "POST");
        assert_no_canaries(&parsed);
    }

    #[test]
    fn json_post_body_creates_json_template() {
        let parsed = parse_hurl_input(&format!(
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
        let form = parse_hurl_input(&format!(
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
                .any(|field| field.key == "password" && field.value == "{{password}}")
        );
        assert_no_canaries(&form);

        let text = parse_hurl_input(
            r#"
POST https://api.example.com/message
Content-Type: text/plain

token: hurl_body_secret_should_not_leak
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
        assert_no_canaries(&text);
    }

    #[test]
    fn authorization_headers_become_auth_without_secret_retention() {
        let bearer = parse_hurl_input(&format!(
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

        let basic = parse_hurl_input(
            r#"
GET https://api.example.com/me
Authorization: Basic raw-base64-credentials
"#,
        );
        let basic_draft = &basic.candidates[0];
        assert!(matches!(basic_draft.auth, AuthStyle::Basic { .. }));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "username"));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "password"));
    }

    #[test]
    fn api_key_and_cookie_headers_do_not_leak_values() {
        let parsed = parse_hurl_input(&format!(
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
            !draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("authorization"))
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
        let parsed = parse_hurl_input(&format!(
            "GET https://api.example.com/users?api_key={API_KEY_SECRET}&token={QUERY_SECRET}&page=1"
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::QueryApiKey { .. }));
        assert!(
            draft
                .query
                .iter()
                .any(|item| item.key == "token" && item.value == "{{token}}")
        );
        assert!(draft.query.iter().any(|item| item.key == "page"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn placeholders_become_runtime_slots() {
        let parsed = parse_hurl_input(
            r#"
PUT https://api.example.com/users/{{user_id}}?custom={{custom-search}}
X-Trace: {{trace_id}}
Content-Type: application/json

{"filter":"{{filter}}"}
"#,
        );

        let draft = &parsed.candidates[0];
        for expected in ["user_id", "custom-search", "trace_id", "filter"] {
            assert!(
                draft.slots.iter().any(|slot| slot.name == expected),
                "missing slot {expected}"
            );
        }
        assert_all_slots_unresolved(&parsed);
    }

    #[test]
    fn request_side_hurl_sections_are_supported_or_ignored_safely() {
        let parsed = parse_hurl_input(&format!(
            r#"
POST https://api.example.com/search
[BasicAuth]
user: raw-user
password: {BODY_SECRET}
[Query]
q: {{{{custom-search}}}}
token: {QUERY_SECRET}
[Form]
name: Ada
password: {BODY_SECRET}
[Cookies]
session: {COOKIE_SECRET}
[Options]
retry: 3
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::Basic { .. }));
        assert!(
            draft
                .query
                .iter()
                .any(|item| item.key == "q" && item.value == "{{custom-search}}")
        );
        let BodyTemplate::Form { fields } = &draft.body else {
            panic!("expected form body");
        };
        assert!(
            fields
                .iter()
                .any(|field| field.key == "password" && field.value == "{{password}}")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("cookies section"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("options section"))
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn response_capture_and_assertion_sections_are_ignored_without_values() {
        let parsed = parse_hurl_input(&format!(
            r#"
GET https://api.example.com/users
HTTP 200
Content-Type: application/json
[Captures]
token: jsonpath "$.token"
[Asserts]
jsonpath "$.secret" == "{RESPONSE_SECRET}"
{{"secret":"{RESPONSE_SECRET}"}}

GET https://api.example.com/next
"#
        ));

        assert_eq!(parsed.candidates.len(), 2);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("response section"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("captures section"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("assertions section"))
        );
        assert_no_canaries(&parsed);
    }

    fn assert_all_slots_unresolved(parsed: &crate::model::ParsedSource) {
        for draft in &parsed.candidates {
            for slot in &draft.slots {
                assert!(
                    slot.current_value.is_none(),
                    "slot {} retained a value",
                    slot.name
                );
            }
        }
    }

    fn assert_no_canaries(parsed: &crate::model::ParsedSource) {
        let serialized = serde_json::to_string(parsed).expect("serialize parsed source");
        for canary in [
            BEARER_SECRET,
            API_KEY_SECRET,
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
