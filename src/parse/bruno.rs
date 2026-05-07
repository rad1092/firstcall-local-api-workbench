use serde_json::{Map, Value, json};

use crate::exec::redact::{is_secret_key, redact_body, redact_free_text, redact_header_value};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::util::{normalize_method, slot_token};

const BRUNO_REDACTED_INPUT: &str = "<bruno input redacted>";

pub fn parse_bruno_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::Bruno,
        raw_text: BRUNO_REDACTED_INPUT.to_string(),
    };
    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    if raw_text.trim().is_empty() {
        notes.push("Bruno input is empty".to_string());
        return ParsedSource {
            source,
            candidates,
            notes,
        };
    }

    if looks_like_open_collection_yaml(raw_text) {
        if let Some(draft) = parse_open_collection_yaml(raw_text, &mut notes) {
            candidates.push(draft);
        }
    } else if let Some(draft) = parse_bru_input(raw_text, &mut notes) {
        candidates.push(draft);
    }

    if candidates.is_empty() {
        notes.push("Bruno input did not contain any supported requests".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

struct DraftInput {
    name: Option<String>,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    query_pairs: Vec<(String, String)>,
    body: BodyInput,
    auth_hint: AuthHint,
}

enum BodyInput {
    None,
    Json(String),
    Text(String),
    Form(Vec<(String, String)>),
    Auto(String),
}

enum AuthHint {
    None,
    Bearer {
        slot_name: String,
    },
    Basic,
    HeaderApiKey {
        header_name: String,
        slot_name: String,
    },
    QueryApiKey {
        param_name: String,
        slot_name: String,
    },
}

#[derive(Clone)]
struct BruBlock {
    name: String,
    lines: Vec<String>,
}

fn parse_bru_input(raw_text: &str, notes: &mut Vec<String>) -> Option<RequestDraft> {
    let blocks = parse_bru_blocks(raw_text, notes);
    let meta = blocks
        .iter()
        .find(|block| block.name.eq_ignore_ascii_case("meta"));
    if let Some(meta) = meta {
        let values = key_value_pairs(&meta.lines);
        if values.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("type") && !value.eq_ignore_ascii_case("http")
        }) {
            notes.push("Skipped Bruno file with non-http type".to_string());
            return None;
        }
    }

    for block in &blocks {
        note_ignored_bru_block(block, notes);
    }

    let method_block = blocks
        .iter()
        .find(|block| is_supported_method(&block.name))?;
    let method = normalize_method(&method_block.name);
    let method_values = key_value_pairs(&method_block.lines);
    let target = get_pair_value(&method_values, "url")?.to_string();
    let body_kind = get_pair_value(&method_values, "body")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());
    let auth_hint = get_pair_value(&method_values, "auth")
        .map(auth_hint_from_label)
        .unwrap_or(AuthHint::None);

    let name = meta
        .and_then(|block| get_pair_value(&key_value_pairs(&block.lines), "name").map(safe_name))
        .flatten();
    let headers = blocks
        .iter()
        .find(|block| block.name.eq_ignore_ascii_case("headers"))
        .map(|block| key_value_pairs(&block.lines))
        .unwrap_or_default();
    let query_pairs = blocks
        .iter()
        .find(|block| block.name.eq_ignore_ascii_case("query"))
        .map(|block| key_value_pairs(&block.lines))
        .unwrap_or_default();
    let body = bru_body_input(&blocks, &body_kind);

    build_draft(
        DraftInput {
            name,
            method,
            target,
            headers,
            query_pairs,
            body,
            auth_hint,
        },
        notes,
    )
}

fn parse_bru_blocks(raw_text: &str, notes: &mut Vec<String>) -> Vec<BruBlock> {
    let lines = raw_text.lines().collect::<Vec<_>>();
    let mut blocks = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            index += 1;
            continue;
        }
        let Some(name) = block_start_name(trimmed) else {
            notes.push("Skipped unsupported Bruno line outside a block".to_string());
            index += 1;
            continue;
        };
        let (content, next_index) = collect_braced_block(&lines, index + 1);
        blocks.push(BruBlock {
            name,
            lines: content,
        });
        index = next_index;
    }
    blocks
}

fn block_start_name(line: &str) -> Option<String> {
    let name = line.strip_suffix('{')?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn collect_braced_block(lines: &[&str], mut index: usize) -> (Vec<String>, usize) {
    let mut depth = 1_i32;
    let mut content = Vec::new();
    while index < lines.len() {
        let line = lines[index];
        let opens = line.chars().filter(|character| *character == '{').count() as i32;
        let closes = line.chars().filter(|character| *character == '}').count() as i32;
        let next_depth = depth + opens - closes;
        if next_depth <= 0 && line.trim() == "}" {
            return (content, index + 1);
        }
        content.push(line.to_string());
        depth = next_depth.max(1);
        index += 1;
    }
    (content, index)
}

fn bru_body_input(blocks: &[BruBlock], body_kind: &str) -> BodyInput {
    let Some(block) = blocks
        .iter()
        .find(|block| block.name.to_ascii_lowercase().starts_with("body:"))
    else {
        return BodyInput::None;
    };
    let kind = block
        .name
        .split_once(':')
        .map(|(_, kind)| kind.trim().to_ascii_lowercase())
        .unwrap_or_else(|| body_kind.to_string());
    let text = block.lines.join("\n").trim().to_string();
    if kind.contains("form") {
        BodyInput::Form(key_value_pairs(&block.lines))
    } else if kind.contains("json") || body_kind == "json" {
        BodyInput::Json(text)
    } else if kind.contains("text") {
        BodyInput::Text(text)
    } else {
        BodyInput::Auto(text)
    }
}

fn note_ignored_bru_block(block: &BruBlock, notes: &mut Vec<String>) {
    let name = block.name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "meta"
            | "headers"
            | "query"
            | "get"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "head"
            | "options"
    ) || name.starts_with("body:")
    {
        return;
    }
    if matches!(
        name.as_str(),
        "tests"
            | "test"
            | "script"
            | "scripts"
            | "prerequest"
            | "pre-request"
            | "postresponse"
            | "post-response"
    ) {
        notes.push("Ignored Bruno scripts/tests section".to_string());
    } else if matches!(
        name.as_str(),
        "vars" | "variables" | "env" | "environment" | "environments"
    ) {
        notes.push("Ignored Bruno variables/environment section".to_string());
    } else if name == "cookies" {
        notes.push("Ignored Bruno cookies section".to_string());
    } else if matches!(name.as_str(), "assertions" | "asserts" | "captures") {
        notes.push("Ignored Bruno assertions/captures section".to_string());
    } else if name == "docs" {
        notes.push("Ignored Bruno docs section".to_string());
    } else {
        notes.push("Ignored unsupported Bruno section".to_string());
    }
}

fn parse_open_collection_yaml(raw_text: &str, notes: &mut Vec<String>) -> Option<RequestDraft> {
    let value: Value = match yaml_serde::from_str(raw_text) {
        Ok(value) => value,
        Err(_) => {
            notes.push("OpenCollection YAML input could not be parsed".to_string());
            return None;
        }
    };

    add_yaml_ignored_notes(&value, notes);
    let info = value.get("info");
    if info
        .and_then(|info| info.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("http"))
    {
        notes.push("Skipped OpenCollection YAML with non-http type".to_string());
        return None;
    }

    let http = value.get("http")?;
    let method = http
        .get("method")
        .and_then(Value::as_str)
        .map(normalize_method)?;
    if !is_supported_method(&method) {
        notes.push("Skipped OpenCollection YAML with unsupported HTTP method".to_string());
        return None;
    }
    let target = http.get("url").and_then(Value::as_str)?.to_string();
    let name = info
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str)
        .and_then(safe_name);
    let headers = yaml_headers(http.get("headers"));
    let query_pairs = yaml_pairs(http.get("query"))
        .into_iter()
        .chain(yaml_pairs(http.get("params")))
        .collect::<Vec<_>>();
    let body = yaml_body_input(http.get("body"));
    let auth_hint = yaml_auth_hint(http.get("auth"));

    build_draft(
        DraftInput {
            name,
            method,
            target,
            headers,
            query_pairs,
            body,
            auth_hint,
        },
        notes,
    )
}

fn add_yaml_ignored_notes(value: &Value, notes: &mut Vec<String>) {
    for key in [
        "runtime",
        "scripts",
        "tests",
        "preRequest",
        "postResponse",
        "assertions",
        "captures",
    ] {
        if value.get(key).is_some() {
            notes.push("Ignored OpenCollection executable sections".to_string());
            break;
        }
    }
    for key in ["variables", "environments", "environment"] {
        if value.get(key).is_some() {
            notes.push("Ignored OpenCollection variables/environment sections".to_string());
            break;
        }
    }
    for key in ["cookies", "settings", "docs"] {
        if value.get(key).is_some() {
            notes.push(match key {
                "cookies" => "Ignored OpenCollection cookies section".to_string(),
                "settings" => "Ignored OpenCollection settings section".to_string(),
                _ => "Ignored OpenCollection docs section".to_string(),
            });
        }
    }
}

fn yaml_headers(value: Option<&Value>) -> Vec<(String, String)> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                let name = item.get("name").and_then(Value::as_str)?;
                let value = item.get("value").map(scalar_to_string).unwrap_or_default();
                Some((name.to_string(), value))
            })
            .collect(),
        Some(Value::Object(object)) => object
            .iter()
            .map(|(key, value)| (key.to_string(), scalar_to_string(value)))
            .collect(),
        _ => Vec::new(),
    }
}

fn yaml_pairs(value: Option<&Value>) -> Vec<(String, String)> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                let key = item
                    .get("name")
                    .or_else(|| item.get("key"))
                    .and_then(Value::as_str)?;
                let value = item.get("value").map(scalar_to_string).unwrap_or_default();
                Some((key.to_string(), value))
            })
            .collect(),
        Some(Value::Object(object)) => object
            .iter()
            .map(|(key, value)| (key.to_string(), scalar_to_string(value)))
            .collect(),
        _ => Vec::new(),
    }
}

fn yaml_body_input(value: Option<&Value>) -> BodyInput {
    let Some(Value::Object(object)) = value else {
        return BodyInput::None;
    };
    let body_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if body_type.contains("form") {
        let fields = yaml_pairs(object.get("fields"))
            .into_iter()
            .chain(yaml_pairs(object.get("params")))
            .collect::<Vec<_>>();
        return BodyInput::Form(fields);
    }
    let data = object.get("data").map(scalar_to_string).unwrap_or_default();
    if body_type.contains("json") {
        BodyInput::Json(data)
    } else if body_type.contains("text") {
        BodyInput::Text(data)
    } else {
        BodyInput::Auto(data)
    }
}

fn yaml_auth_hint(value: Option<&Value>) -> AuthHint {
    match value {
        Some(Value::String(label)) => auth_hint_from_label(label),
        Some(Value::Object(object)) => {
            let auth_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if auth_type == "bearer" {
                let slot_name = object
                    .get("token")
                    .or_else(|| object.get("value"))
                    .and_then(Value::as_str)
                    .and_then(placeholder_slot_name)
                    .unwrap_or_else(|| "bearer_token".to_string());
                AuthHint::Bearer { slot_name }
            } else if auth_type == "basic" {
                AuthHint::Basic
            } else if matches!(auth_type.as_str(), "apikey" | "api_key" | "api-key") {
                let name = object
                    .get("name")
                    .or_else(|| object.get("key"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| "api_key".to_string());
                let slot_name = object
                    .get("value")
                    .or_else(|| object.get("token"))
                    .and_then(Value::as_str)
                    .and_then(placeholder_slot_name)
                    .unwrap_or_else(|| safe_slot_name(&name));
                let placement = object
                    .get("placement")
                    .or_else(|| object.get("in"))
                    .and_then(Value::as_str)
                    .unwrap_or("header")
                    .to_ascii_lowercase();
                if placement == "query" {
                    AuthHint::QueryApiKey {
                        param_name: name,
                        slot_name,
                    }
                } else {
                    AuthHint::HeaderApiKey {
                        header_name: name,
                        slot_name,
                    }
                }
            } else {
                AuthHint::None
            }
        }
        _ => AuthHint::None,
    }
}

fn build_draft(input: DraftInput, notes: &mut Vec<String>) -> Option<RequestDraft> {
    let mut slots = Vec::new();
    let mut auth = AuthStyle::None;
    apply_auth_hint(input.auth_hint, &mut auth, &mut slots);

    let UrlParts {
        base_url,
        path,
        mut query,
    } = parse_target(&input.target, &mut auth, &mut slots);
    collect_slots_from_template(
        &mut slots,
        &path,
        SlotLocation::Path,
        true,
        "Bruno URL path",
    );
    apply_query_pairs(&mut query, input.query_pairs, &mut auth, &mut slots);
    let safe_headers = sanitize_headers(input.headers, &mut auth, &mut slots, notes);
    let body = body_input_to_template(input.body, &safe_headers, &mut slots);
    collect_body_slots(&mut slots, &body);
    dedupe_slots(&mut slots);

    Some(RequestDraft {
        operation_id: format!("bruno-{}", uuid::Uuid::new_v4()),
        name: request_name(input.name.as_ref(), &input.method, &path),
        method: input.method,
        base_url,
        path,
        headers: safe_headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::Bruno,
            label: "bruno request".to_string(),
            detail: "Parsed sanitized request from Bruno/OpenCollection input".to_string(),
            confidence: Confidence::Medium,
        }],
        confidence: FieldConfidence {
            overall: Confidence::Medium,
            notes: "Built by the limited static Bruno/OpenCollection parser".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![SourceKind::Bruno],
    })
}

struct UrlParts {
    base_url: Option<String>,
    path: String,
    query: Vec<KeyValueField>,
}

fn parse_target(target: &str, auth: &mut AuthStyle, slots: &mut Vec<RuntimeSlot>) -> UrlParts {
    let (without_fragment, _) = target
        .split_once('#')
        .map_or((target, None), |(before, after)| (before, Some(after)));
    let (without_query, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, ""), |(before, query)| (before, query));
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
        collect_slots_from_template(slots, base_url, SlotLocation::Path, true, "Bruno base URL");
    }
    let query = parse_query(query, auth, slots);
    UrlParts {
        base_url,
        path,
        query,
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
                "Bruno query API key",
            );
            return;
        }
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Query,
            true,
            "Bruno secret-like query parameter",
        );
        fields.push(key_value_field(
            key,
            &slot_token(&slot_name),
            "Bruno query parameter",
            Confidence::Medium,
        ));
        return;
    }
    collect_slots_from_template(
        slots,
        value,
        SlotLocation::Query,
        true,
        "Bruno query parameter",
    );
    fields.push(key_value_field(
        key,
        value,
        "Bruno query parameter",
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
                notes.push("Ignored Bruno cookie header".to_string());
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
                        "Bruno header API key",
                    );
                    return None;
                }
                let slot_name = safe_slot_name(&name);
                add_slot(
                    slots,
                    &slot_name,
                    SlotLocation::Header,
                    true,
                    "Bruno secret-like header",
                );
                return Some(header_field(
                    &name,
                    &slot_token(&slot_name),
                    "Bruno header",
                    Confidence::Medium,
                ));
            }
            let value = redact_header_value(&name, &value);
            collect_slots_from_template(slots, &value, SlotLocation::Header, true, "Bruno header");
            Some(header_field(
                &name,
                &value,
                "Bruno header",
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
            "Bruno bearer auth",
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
            "Bruno basic auth username",
        );
        add_slot(
            slots,
            "password",
            SlotLocation::Auth,
            true,
            "Bruno basic auth password",
        );
    }
}

fn apply_auth_hint(auth_hint: AuthHint, auth: &mut AuthStyle, slots: &mut Vec<RuntimeSlot>) {
    match auth_hint {
        AuthHint::None => {}
        AuthHint::Bearer { slot_name } => {
            *auth = AuthStyle::Bearer {
                token_slot: slot_name.clone(),
                header_name: "Authorization".to_string(),
            };
            add_slot(
                slots,
                &slot_name,
                SlotLocation::Auth,
                true,
                "Bruno bearer auth",
            );
        }
        AuthHint::Basic => {
            *auth = AuthStyle::Basic {
                username_slot: "username".to_string(),
                password_slot: "password".to_string(),
            };
            add_slot(
                slots,
                "username",
                SlotLocation::Auth,
                true,
                "Bruno basic auth username",
            );
            add_slot(
                slots,
                "password",
                SlotLocation::Auth,
                true,
                "Bruno basic auth password",
            );
        }
        AuthHint::HeaderApiKey {
            header_name,
            slot_name,
        } => {
            *auth = AuthStyle::HeaderApiKey {
                header_name,
                slot_name: slot_name.clone(),
            };
            add_slot(
                slots,
                &slot_name,
                SlotLocation::Auth,
                true,
                "Bruno header API key",
            );
        }
        AuthHint::QueryApiKey {
            param_name,
            slot_name,
        } => {
            *auth = AuthStyle::QueryApiKey {
                param_name,
                slot_name: slot_name.clone(),
            };
            add_slot(
                slots,
                &slot_name,
                SlotLocation::Auth,
                true,
                "Bruno query API key",
            );
        }
    }
}

fn auth_hint_from_label(label: &str) -> AuthHint {
    match label.to_ascii_lowercase().as_str() {
        "bearer" => AuthHint::Bearer {
            slot_name: "bearer_token".to_string(),
        },
        "basic" => AuthHint::Basic,
        "apikey" | "api_key" | "api-key" | "headerapikey" | "header_api_key" => {
            AuthHint::HeaderApiKey {
                header_name: "X-API-Key".to_string(),
                slot_name: "api_key".to_string(),
            }
        }
        "queryapikey" | "query_api_key" => AuthHint::QueryApiKey {
            param_name: "api_key".to_string(),
            slot_name: "api_key".to_string(),
        },
        _ => AuthHint::None,
    }
}

fn body_input_to_template(
    body: BodyInput,
    headers: &[HeaderField],
    slots: &mut Vec<RuntimeSlot>,
) -> BodyTemplate {
    match body {
        BodyInput::None => BodyTemplate::None,
        BodyInput::Json(text) => json_body_template(&text, slots),
        BodyInput::Text(text) => {
            let text = redact_body(&text, None);
            collect_slots_from_template(slots, &text, SlotLocation::Body, true, "Bruno text body");
            BodyTemplate::Text { text }
        }
        BodyInput::Form(fields) => BodyTemplate::Form {
            fields: fields
                .iter()
                .map(|(key, value)| form_field(key, value, slots))
                .collect(),
        },
        BodyInput::Auto(text) => auto_body_template(&text, headers, slots),
    }
}

fn auto_body_template(
    text: &str,
    headers: &[HeaderField],
    slots: &mut Vec<RuntimeSlot>,
) -> BodyTemplate {
    if text.trim().is_empty() {
        return BodyTemplate::None;
    }
    let content_type = headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.to_ascii_lowercase())
        .unwrap_or_default();
    if content_type.contains("json") || serde_json::from_str::<Value>(text).is_ok() {
        return json_body_template(text, slots);
    }
    if content_type.contains("x-www-form-urlencoded") || looks_like_form(text) {
        let fields = text
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
    let text = redact_body(text, None);
    collect_slots_from_template(slots, &text, SlotLocation::Body, true, "Bruno text body");
    BodyTemplate::Text { text }
}

fn json_body_template(text: &str, slots: &mut Vec<RuntimeSlot>) -> BodyTemplate {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        let safe = sanitize_json_value(value, slots, SlotLocation::Body);
        return BodyTemplate::Json {
            template: serde_json::to_string(&safe)
                .unwrap_or_else(|_| redact_body(text, Some("application/json"))),
        };
    }
    BodyTemplate::Json {
        template: redact_body(text, Some("application/json")),
    }
}

fn form_field(key: &str, value: &str, slots: &mut Vec<RuntimeSlot>) -> KeyValueField {
    if is_secret_key(key) {
        let slot_name = safe_slot_name(key);
        add_slot(
            slots,
            &slot_name,
            SlotLocation::Body,
            true,
            "Bruno secret-like form field",
        );
        return key_value_field(
            key,
            &slot_token(&slot_name),
            "Bruno form field",
            Confidence::Medium,
        );
    }
    collect_slots_from_template(slots, value, SlotLocation::Body, true, "Bruno form field");
    key_value_field(key, value, "Bruno form field", Confidence::High)
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
                        "Bruno secret-like JSON field",
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
            collect_slots_from_template(slots, &text, location, true, "Bruno JSON field");
            Value::String(text)
        }
        other => other,
    }
}

fn collect_body_slots(slots: &mut Vec<RuntimeSlot>, body: &BodyTemplate) {
    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            collect_slots_from_template(slots, template, SlotLocation::Body, true, "Bruno body");
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
    for name in extract_bruno_slots(template) {
        add_slot(slots, &name, location.clone(), required, description);
    }
}

fn extract_bruno_slots(template: &str) -> Vec<String> {
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
    extract_bruno_slots(value).into_iter().next()
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
        return format!("Bruno {name}");
    }
    let path = if is_secret_key(path) {
        "<path>".to_string()
    } else {
        safe_note_text(path)
    };
    format!("Bruno {} {}", method, path)
}

fn safe_name(name: &str) -> Option<String> {
    let safe = safe_note_text(name);
    if safe.trim().is_empty() || is_secret_key(&safe) {
        None
    } else {
        Some(safe)
    }
}

fn safe_note_text(text: &str) -> String {
    redact_free_text(text)
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '_' | '-' | '/' | '.' | ':' | '$')
        })
        .collect::<String>()
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

fn key_value_pairs(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| parse_key_value_line(line.trim()))
        .collect()
}

fn parse_key_value_line(line: &str) -> Option<(String, String)> {
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    let (key, value) = line.split_once(':')?;
    Some((key.trim().to_string(), value.trim().to_string()))
}

fn get_pair_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

fn is_supported_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn looks_like_open_collection_yaml(raw_text: &str) -> bool {
    raw_text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("info:") || trimmed.starts_with("http:")
    })
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn looks_like_form(body: &str) -> bool {
    body.contains('=') && !body.trim_start().starts_with('{')
}

#[cfg(test)]
mod tests {
    use super::parse_bruno_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    const BEARER_SECRET: &str = "bruno_bearer_secret_should_not_leak";
    const BASIC_SECRET: &str = "bruno_basic_secret_should_not_leak";
    const API_KEY_SECRET: &str = "bruno_api_key_secret_should_not_leak";
    const COOKIE_SECRET: &str = "bruno_cookie_secret_should_not_leak";
    const QUERY_SECRET: &str = "bruno_query_secret_should_not_leak";
    const BODY_SECRET: &str = "bruno_body_secret_should_not_leak";
    const SCRIPT_SECRET: &str = "bruno_script_secret_should_not_leak";
    const VARIABLE_SECRET: &str = "bruno_variable_secret_should_not_leak";
    const ENVIRONMENT_SECRET: &str = "bruno_environment_secret_should_not_leak";
    const RESPONSE_SECRET: &str = "bruno_response_secret_should_not_leak";

    #[test]
    fn empty_and_malformed_inputs_return_notes_and_zero_candidates() {
        let empty = parse_bruno_input("");
        assert_eq!(empty.source.kind, SourceKind::Bruno);
        assert_eq!(empty.source.raw_text, super::BRUNO_REDACTED_INPUT);
        assert!(empty.candidates.is_empty());
        assert!(empty.notes.iter().any(|note| note.contains("empty")));

        let malformed = parse_bruno_input("not a bruno file");
        assert!(malformed.candidates.is_empty());
        assert!(
            malformed
                .notes
                .iter()
                .any(|note| note.contains("supported requests"))
        );
    }

    #[test]
    fn bru_simple_get_absolute_url_creates_candidate() {
        let parsed = parse_bruno_input(
            r#"
meta {
  name: Get User
  type: http
  seq: 1
}

get {
  url: https://api.example.com/users/{{user_id}}?verbose=true
  body: none
  auth: none
}

headers {
  Accept: application/json
}
"#,
        );

        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.name, "Bruno Get User");
        assert_eq!(draft.method, "GET");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/users/{{user_id}}");
        assert!(draft.query.iter().any(|item| item.key == "verbose"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_all_slots_unresolved(&parsed);
        assert_no_canaries(&parsed);
    }

    #[test]
    fn bru_relative_url_creates_candidate_without_base_url() {
        let parsed = parse_bruno_input(
            r#"
get {
  url: /v1/users?limit=10
  body: none
  auth: inherit
}
"#,
        );

        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url, None);
        assert_eq!(draft.path, "/v1/users");
        assert!(draft.query.iter().any(|item| item.key == "limit"));
    }

    #[test]
    fn bru_json_post_body_creates_json_template() {
        let parsed = parse_bruno_input(&format!(
            r#"
meta {{
  name: Create User
  type: http
  seq: 1
}}

post {{
  url: https://api.example.com/users
  body: json
  auth: bearer
}}

headers {{
  Content-Type: application/json
  Authorization: Bearer {BEARER_SECRET}
}}

body:json {{
  {{
    "name": "Ada",
    "password": "{BODY_SECRET}",
    "user_id": "{{{{user_id}}}}"
  }}
}}
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.slots.iter().any(|slot| slot.name == "password"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn bru_form_and_text_bodies_are_detected() {
        let form = parse_bruno_input(&format!(
            r#"
post {{
  url: https://api.example.com/login
  body: form-urlencoded
}}

body:form-urlencoded {{
  username: ada
  password: {BODY_SECRET}
}}
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

        let text = parse_bruno_input(
            r#"
post {
  url: https://api.example.com/message
  body: text
}

body:text {
token: bruno_body_secret_should_not_leak
hello {{name}}
}
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
    fn bru_auth_headers_do_not_retain_credentials() {
        let bearer = parse_bruno_input(&format!(
            r#"
get {{
  url: https://api.example.com/me
  auth: bearer
}}
headers {{
  Authorization: Bearer {BEARER_SECRET}
}}
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

        let basic = parse_bruno_input(&format!(
            r#"
get {{
  url: https://api.example.com/me
  auth: basic
}}
headers {{
  Authorization: Basic {BASIC_SECRET}
}}
"#
        ));
        let basic_draft = &basic.candidates[0];
        assert!(matches!(basic_draft.auth, AuthStyle::Basic { .. }));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "username"));
        assert!(basic_draft.slots.iter().any(|slot| slot.name == "password"));
        assert_no_canaries(&basic);
    }

    #[test]
    fn bru_api_key_cookie_and_secret_query_are_safe() {
        let parsed = parse_bruno_input(&format!(
            r#"
get {{
  url: https://api.example.com/keyed?api_key={API_KEY_SECRET}&token={QUERY_SECRET}&page=1
}}
headers {{
  X-API-Key: {API_KEY_SECRET}
  Cookie: session={COOKIE_SECRET}
}}
query {{
  token: {QUERY_SECRET}
}}
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(
            draft.auth,
            AuthStyle::HeaderApiKey { .. } | AuthStyle::QueryApiKey { .. }
        ));
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("cookie"))
        );
        assert!(
            draft
                .query
                .iter()
                .any(|item| item.key == "token" && item.value == "{{token}}")
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn bru_placeholders_become_runtime_slots() {
        let parsed = parse_bruno_input(
            r#"
put {
  url: https://api.example.com/users/{{user_id}}?trace={{process.env.API_KEY}}
  body: json
}
headers {
  X-Trace: {{trace_id}}
}
body:json {
  {"filter":"{{filter}}"}
}
"#,
        );

        let draft = &parsed.candidates[0];
        for expected in ["user_id", "process.env.API_KEY", "trace_id", "filter"] {
            assert!(
                draft.slots.iter().any(|slot| slot.name == expected),
                "missing slot {expected}"
            );
        }
        assert_all_slots_unresolved(&parsed);
    }

    #[test]
    fn bru_scripts_variables_docs_and_response_sections_are_ignored() {
        let parsed = parse_bruno_input(&format!(
            r#"
get {{
  url: https://api.example.com/users
}}
tests {{
  const secret = "{SCRIPT_SECRET}";
}}
vars {{
  token: {VARIABLE_SECRET}
}}
environments {{
  token: {ENVIRONMENT_SECRET}
}}
docs {{
  never import {VARIABLE_SECRET}
}}
response {{
  secret: {RESPONSE_SECRET}
}}
"#
        ));

        assert_eq!(parsed.candidates.len(), 1);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("scripts/tests"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("variables/environment"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("docs section"))
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn yaml_simple_get_creates_candidate() {
        let parsed = parse_bruno_input(
            r#"
info:
  name: Get User
  type: http
  seq: 1
http:
  method: GET
  url: https://api.example.com/users/{{user_id}}
  headers:
    - name: Accept
      value: application/json
"#,
        );

        let draft = &parsed.candidates[0];
        assert_eq!(draft.name, "Bruno Get User");
        assert_eq!(draft.method, "GET");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert!(draft.slots.iter().any(|slot| slot.name == "user_id"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn yaml_json_post_body_and_header_auth_are_safe() {
        let parsed = parse_bruno_input(&format!(
            r#"
info:
  name: Create User
  type: http
  seq: 1
http:
  method: POST
  url: https://api.example.com/users
  headers:
    - name: Content-Type
      value: application/json
    - name: Authorization
      value: Bearer {BEARER_SECRET}
  body:
    type: json
    data: |-
      {{
        "name": "Ada",
        "password": "{BODY_SECRET}",
        "user_id": "{{{{user_id}}}}"
      }}
  auth: inherit
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.slots.iter().any(|slot| slot.name == "password"));
        assert_no_canaries(&parsed);
    }

    #[test]
    fn yaml_headers_map_and_auth_object_are_safe() {
        let parsed = parse_bruno_input(&format!(
            r#"
info:
  name: Keyed
  type: http
http:
  method: GET
  url: https://api.example.com/keyed
  headers:
    Accept: application/json
    Cookie: session={COOKIE_SECRET}
  auth:
    type: apiKey
    placement: query
    name: api_key
    value: {API_KEY_SECRET}
"#
        ));

        let draft = &parsed.candidates[0];
        assert!(matches!(draft.auth, AuthStyle::QueryApiKey { .. }));
        assert!(
            !draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("cookie"))
        );
        assert_no_canaries(&parsed);

        let placeholder = parse_bruno_input(
            r#"
info:
  name: Bearer Placeholder
  type: http
http:
  method: GET
  url: /me
  auth:
    type: bearer
    token: "{{token}}"
"#,
        );
        assert!(
            placeholder.candidates[0]
                .slots
                .iter()
                .any(|slot| slot.name == "token")
        );
    }

    #[test]
    fn yaml_form_body_is_supported() {
        let parsed = parse_bruno_input(&format!(
            r#"
info:
  name: Login
  type: http
http:
  method: POST
  url: https://api.example.com/login
  body:
    type: form-urlencoded
    fields:
      username: ada
      password: {BODY_SECRET}
"#
        ));

        let BodyTemplate::Form { fields } = &parsed.candidates[0].body else {
            panic!("expected form body");
        };
        assert!(
            fields
                .iter()
                .any(|field| field.key == "password" && field.value == "{{password}}")
        );
        assert_no_canaries(&parsed);
    }

    #[test]
    fn yaml_runtime_variables_docs_and_tests_are_ignored() {
        let parsed = parse_bruno_input(&format!(
            r#"
info:
  name: Ignored Sections
  type: http
http:
  method: GET
  url: https://api.example.com/users
runtime:
  scripts:
    - type: tests
      code: |-
        const secret = "{SCRIPT_SECRET}";
tests:
  - expect secret {SCRIPT_SECRET}
variables:
  token: {VARIABLE_SECRET}
environments:
  token: {ENVIRONMENT_SECRET}
docs: never import {VARIABLE_SECRET}
"#
        ));

        assert_eq!(parsed.candidates.len(), 1);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("executable sections"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("variables/environment"))
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("docs section"))
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
            BASIC_SECRET,
            API_KEY_SECRET,
            COOKIE_SECRET,
            QUERY_SECRET,
            BODY_SECRET,
            SCRIPT_SECRET,
            VARIABLE_SECRET,
            ENVIRONMENT_SECRET,
            RESPONSE_SECRET,
        ] {
            assert!(
                !serialized.contains(canary),
                "{canary} leaked in {serialized}"
            );
        }
    }
}
