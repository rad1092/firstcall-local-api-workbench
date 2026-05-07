use anyhow::{Context, Result};
use url::Url;

use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::parse::graphql::annotate_graphql_draft;
use crate::util::{extract_slot_names, normalize_method, slot_token};

pub fn parse_curl_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::Curl,
        raw_text: raw_text.to_string(),
    };
    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    match parse_single_curl(raw_text) {
        Ok(draft) => candidates.push(draft),
        Err(error) => notes.push(error.to_string()),
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

fn parse_single_curl(raw_text: &str) -> Result<RequestDraft> {
    let normalized = raw_text.replace("\\\r\n", " ").replace("\\\n", " ");
    let mut tokens = shlex::split(&normalized).context("Could not tokenize curl command")?;
    if matches!(tokens.first(), Some(token) if token.eq_ignore_ascii_case("curl")) {
        tokens.remove(0);
    }
    if tokens.is_empty() {
        anyhow::bail!("No curl tokens found")
    }

    let mut method = None::<String>;
    let mut url_token = None::<String>;
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut data_chunks = Vec::new();
    let mut form_fields = Vec::new();
    let mut basic_user = None::<String>;
    let mut use_get = false;
    let mut unsupported_reason = None::<String>;

    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        match token.as_str() {
            "-X" | "--request" => {
                method = Some(next_value(&tokens, &mut index, token)?.to_string());
            }
            "-H" | "--header" => {
                headers.push(parse_header(next_value(&tokens, &mut index, token)?));
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" => {
                let value = next_value(&tokens, &mut index, token)?;
                if value.starts_with('@') {
                    unsupported_reason =
                        Some("File-based curl payloads are not supported in v1".to_string());
                } else {
                    data_chunks.push(value.to_string());
                }
            }
            "--url" => {
                url_token = Some(next_value(&tokens, &mut index, token)?.to_string());
            }
            "-u" | "--user" => {
                basic_user = Some(next_value(&tokens, &mut index, token)?.to_string());
            }
            "-G" => {
                use_get = true;
            }
            "--compressed" => {}
            "-F" | "--form" => {
                let value = next_value(&tokens, &mut index, token)?;
                if value.contains('@') || value.contains('<') {
                    unsupported_reason =
                        Some("Multipart file uploads are not supported in v1".to_string());
                } else if let Some((key, val)) = split_field(value, '=') {
                    form_fields.push(KeyValueField {
                        key: key.to_string(),
                        value: val.to_string(),
                        required: true,
                        description: "Parsed from curl form field".to_string(),
                        confidence: Confidence::High,
                    });
                } else {
                    unsupported_reason = Some(format!("Unsupported form field syntax: {value}"));
                }
            }
            "-s" | "--silent" | "-S" | "--show-error" | "-i" | "--include" | "-L"
            | "--location" => {}
            other if other.starts_with('-') => {
                notes_for_unknown_flag(other, &mut unsupported_reason);
            }
            other => {
                if url_token.is_none() {
                    url_token = Some(other.to_string());
                }
            }
        }
        index += 1;
    }

    let url_token = url_token.context("No URL found in curl command")?;
    let method = method
        .map(|value| normalize_method(&value))
        .unwrap_or_else(|| infer_method(&data_chunks, &form_fields, use_get));

    let (base_url, mut path, parsed_query) = split_url(&url_token);
    query.extend(parsed_query);
    path = normalize_path_template(&path);

    let mut body = BodyTemplate::None;
    if !form_fields.is_empty() {
        body = BodyTemplate::Multipart {
            fields: form_fields,
        };
    } else if !data_chunks.is_empty() {
        if use_get {
            for chunk in data_chunks {
                query.extend(parse_key_value_pairs(&chunk));
            }
        } else {
            body = infer_body(&data_chunks.join("&"), &headers);
        }
    }

    let mut slots = collect_slots(&path, &headers, &query, &body);
    let mut auth = AuthStyle::None;
    let mut retained_headers = Vec::new();
    for header in headers {
        if header.key.eq_ignore_ascii_case("authorization")
            && let Some(parsed) = detect_authorization(&header.value)
        {
            auth = parsed.auth;
            slots.extend(parsed.slots);
            continue;
        }

        if header.key.eq_ignore_ascii_case("x-api-key") {
            auth = AuthStyle::HeaderApiKey {
                header_name: header.key.clone(),
                slot_name: "api_key".to_string(),
            };
            slots.push(RuntimeSlot {
                name: "api_key".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: Some(header.value.clone()),
                description: format!("Value for {}", header.key),
                confidence: Confidence::High,
            });
            continue;
        }

        retained_headers.push(header);
    }

    if let Some(user_value) = basic_user {
        let (username, password) = split_basic_user(&user_value);
        auth = AuthStyle::Basic {
            username_slot: "basic_username".to_string(),
            password_slot: "basic_password".to_string(),
        };
        slots.push(RuntimeSlot {
            name: "basic_username".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: username,
            description: "Basic auth username".to_string(),
            confidence: Confidence::High,
        });
        slots.push(RuntimeSlot {
            name: "basic_password".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: password,
            description: "Basic auth password".to_string(),
            confidence: Confidence::High,
        });
    }

    if matches!(auth, AuthStyle::None) {
        for item in &query {
            if item.key.eq_ignore_ascii_case("api_key") || item.key.eq_ignore_ascii_case("apikey") {
                auth = AuthStyle::QueryApiKey {
                    param_name: item.key.clone(),
                    slot_name: item.key.clone(),
                };
            }
        }
    }

    dedupe_slots(&mut slots);

    let mut draft = RequestDraft {
        operation_id: format!("curl-{}", uuid::Uuid::new_v4()),
        name: format!("{} {}", method, path),
        method,
        base_url,
        path,
        headers: retained_headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::Curl,
            label: "curl example".to_string(),
            detail: "Parsed from user-provided curl command".to_string(),
            confidence: Confidence::High,
        }],
        confidence: FieldConfidence {
            overall: Confidence::High,
            notes: "curl input has highest precedence".to_string(),
        },
        response_schema: None,
        unsupported_reason,
        source_kinds: vec![SourceKind::Curl],
    };
    annotate_graphql_draft(&mut draft);
    Ok(draft)
}

fn next_value<'a>(tokens: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str> {
    *index += 1;
    tokens
        .get(*index)
        .map(String::as_str)
        .with_context(|| format!("Missing value after {flag}"))
}

fn parse_header(raw: &str) -> HeaderField {
    let (key, value) = split_field(raw, ':').unwrap_or((raw.trim(), ""));
    HeaderField {
        key: key.trim().to_string(),
        value: value.trim().to_string(),
        required: true,
        description: "Parsed from curl header".to_string(),
        confidence: Confidence::High,
    }
}

fn split_field(raw: &str, separator: char) -> Option<(&str, &str)> {
    let (key, value) = raw.split_once(separator)?;
    Some((key, value))
}

fn notes_for_unknown_flag(flag: &str, unsupported_reason: &mut Option<String>) {
    if unsupported_reason.is_none() {
        *unsupported_reason = Some(format!("Unsupported curl option encountered: {flag}"));
    }
}

fn infer_method(data_chunks: &[String], form_fields: &[KeyValueField], use_get: bool) -> String {
    if use_get {
        "GET".to_string()
    } else if !data_chunks.is_empty() || !form_fields.is_empty() {
        "POST".to_string()
    } else {
        "GET".to_string()
    }
}

fn split_url(raw: &str) -> (Option<String>, String, Vec<KeyValueField>) {
    match Url::parse(raw) {
        Ok(url) => {
            let mut query = Vec::new();
            for (key, value) in url.query_pairs() {
                query.push(KeyValueField {
                    key: key.to_string(),
                    value: value.to_string(),
                    required: false,
                    description: "Parsed from URL query string".to_string(),
                    confidence: Confidence::High,
                });
            }
            let base_url = format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or_default(),
                url.port()
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default()
            );
            (Some(base_url), url.path().to_string(), query)
        }
        Err(_) => (None, raw.to_string(), Vec::new()),
    }
}

fn infer_body(raw: &str, headers: &[HeaderField]) -> BodyTemplate {
    if looks_like_json(raw, headers) {
        BodyTemplate::Json {
            template: raw.to_string(),
        }
    } else if raw.contains('=') && raw.contains('&') {
        BodyTemplate::Form {
            fields: parse_key_value_pairs(raw),
        }
    } else {
        BodyTemplate::Text {
            text: raw.to_string(),
        }
    }
}

fn looks_like_json(raw: &str, headers: &[HeaderField]) -> bool {
    if raw.trim_start().starts_with('{') || raw.trim_start().starts_with('[') {
        return serde_json::from_str::<serde_json::Value>(raw).is_ok();
    }
    headers.iter().any(|header| {
        header.key.eq_ignore_ascii_case("content-type")
            && header.value.to_ascii_lowercase().contains("json")
    })
}

fn parse_key_value_pairs(raw: &str) -> Vec<KeyValueField> {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(key, value)| KeyValueField {
            key: key.to_string(),
            value: value.to_string(),
            required: false,
            description: "Parsed key/value pair".to_string(),
            confidence: Confidence::Medium,
        })
        .collect()
}

fn normalize_path_template(path: &str) -> String {
    let mut normalized = path.to_string();
    for capture in regex::Regex::new(r"\{([a-zA-Z0-9_\-]+)\}")
        .expect("path regex")
        .captures_iter(path)
    {
        let full = capture.get(0).map(|item| item.as_str()).unwrap_or_default();
        let name = capture.get(1).map(|item| item.as_str()).unwrap_or_default();
        normalized = normalized.replace(full, &slot_token(name));
    }
    normalized
}

fn collect_slots(
    path: &str,
    headers: &[HeaderField],
    query: &[KeyValueField],
    body: &BodyTemplate,
) -> Vec<RuntimeSlot> {
    let mut slots = Vec::new();
    for name in extract_slot_names(path) {
        slots.push(RuntimeSlot {
            name: name.clone(),
            location: SlotLocation::Path,
            required: true,
            current_value: None,
            description: format!("Value for path parameter {name}"),
            confidence: Confidence::High,
        });
    }

    for item in query {
        for name in extract_slot_names(&item.value) {
            slots.push(RuntimeSlot {
                name: name.clone(),
                location: SlotLocation::Query,
                required: item.required,
                current_value: None,
                description: format!("Value for query parameter {}", item.key),
                confidence: item.confidence.clone(),
            });
        }
    }

    for header in headers {
        for name in extract_slot_names(&header.value) {
            slots.push(RuntimeSlot {
                name: name.clone(),
                location: SlotLocation::Header,
                required: header.required,
                current_value: None,
                description: format!("Value for header {}", header.key),
                confidence: header.confidence.clone(),
            });
        }
    }

    match body {
        BodyTemplate::Json { template } | BodyTemplate::Text { text: template } => {
            for name in extract_slot_names(template) {
                slots.push(RuntimeSlot {
                    name: name.clone(),
                    location: SlotLocation::Body,
                    required: true,
                    current_value: None,
                    description: format!("Value for body field {name}"),
                    confidence: Confidence::Medium,
                });
            }
        }
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            for field in fields {
                for name in extract_slot_names(&field.value) {
                    slots.push(RuntimeSlot {
                        name: name.clone(),
                        location: SlotLocation::Body,
                        required: field.required,
                        current_value: None,
                        description: format!("Value for body field {}", field.key),
                        confidence: field.confidence.clone(),
                    });
                }
            }
        }
        BodyTemplate::None => {}
    }

    slots
}

struct AuthorizationParse {
    auth: AuthStyle,
    slots: Vec<RuntimeSlot>,
}

fn detect_authorization(value: &str) -> Option<AuthorizationParse> {
    let value = value.trim();
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(AuthorizationParse {
            auth: AuthStyle::Bearer {
                token_slot: "bearer_token".to_string(),
                header_name: "Authorization".to_string(),
            },
            slots: vec![RuntimeSlot {
                name: "bearer_token".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: Some(token.trim().to_string()),
                description: "Bearer token".to_string(),
                confidence: Confidence::High,
            }],
        });
    }

    if value.starts_with("Basic ") {
        return Some(AuthorizationParse {
            auth: AuthStyle::Basic {
                username_slot: "basic_username".to_string(),
                password_slot: "basic_password".to_string(),
            },
            slots: vec![
                RuntimeSlot {
                    name: "basic_username".to_string(),
                    location: SlotLocation::Auth,
                    required: true,
                    current_value: None,
                    description: "Basic auth username".to_string(),
                    confidence: Confidence::Medium,
                },
                RuntimeSlot {
                    name: "basic_password".to_string(),
                    location: SlotLocation::Auth,
                    required: true,
                    current_value: None,
                    description: "Basic auth password".to_string(),
                    confidence: Confidence::Medium,
                },
            ],
        });
    }
    None
}

fn split_basic_user(value: &str) -> (Option<String>, Option<String>) {
    if let Some((user, pass)) = value.split_once(':') {
        (Some(user.to_string()), Some(pass.to_string()))
    } else {
        (Some(value.to_string()), None)
    }
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

#[cfg(test)]
mod tests {
    use super::parse_curl_input;
    use crate::model::{AuthStyle, BodyTemplate, SourceKind};

    #[test]
    fn parses_bearer_json_curl() {
        let parsed = parse_curl_input(
            "curl https://api.example.com/v1/customers -X POST -H 'Authorization: Bearer secret' -H 'Content-Type: application/json' -d '{\"name\":\"Ada\"}'",
        );
        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.method, "POST");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/v1/customers");
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
    }

    #[test]
    fn flags_multipart_file_uploads_as_unsupported() {
        let parsed = parse_curl_input("curl https://api.example.com/upload -F file=@sample.png");
        let draft = &parsed.candidates[0];
        assert!(draft.unsupported_reason.is_some());
    }

    #[test]
    fn graphql_json_body_is_annotated_safely() {
        let graphql_secret = "graphql_variable_secret_should_not_leak";
        let parsed = parse_curl_input(&format!(
            "curl https://api.example.com/graphql -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"query GetUser($id: ID!) {{ user(id: $id) {{ id }} }}\",\"variables\":{{\"id\":\"{{{{user_id}}}}\",\"password\":\"{graphql_secret}\"}},\"operationName\":\"GetUser\"}}'"
        ));

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
        assert!(draft.slots.iter().any(|slot| slot.name == "password"));
        let serialized = serde_json::to_string(&(parsed.candidates, parsed.notes))
            .expect("serialize parsed output");
        assert!(!serialized.contains(graphql_secret), "{serialized}");
    }
}
