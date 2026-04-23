use std::collections::BTreeMap;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::parse::curl::parse_curl_input;
use crate::util::{extract_slot_names, slot_token};

static METHOD_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?im)\b(GET|POST|PUT|PATCH|DELETE)\s+(https?://[^\s`]+|/[A-Za-z0-9_\-./{}]+(?:\?[^\s`]+)?)",
    )
    .expect("method path regex")
});
static BASE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"https?://[A-Za-z0-9\.\-_:]+(?:/[A-Za-z0-9_\-./]+)?"#).expect("base url regex")
});
static CURL_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)```(?:bash|sh|curl)?\s*(curl.+?)```").expect("curl block regex")
});
static JSON_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)```(?:json)?\s*(\{.+?\}|\[.+?\])\s*```").expect("json block regex")
});
static FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?im)(?:required\s+)?(?:query parameter|parameter|field|header)\s+[`'"]?([a-zA-Z0-9_\-]+)[`'"]?"#,
    )
    .expect("field regex")
});

pub fn parse_docs_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::Docs,
        raw_text: raw_text.to_string(),
    };

    let mut candidates = Vec::new();
    let mut notes = Vec::new();

    let curl_candidates = extract_curl_candidates(raw_text);
    let mut seen = BTreeMap::<String, usize>::new();
    for mut candidate in curl_candidates {
        candidate.source_kinds = vec![SourceKind::Docs];
        candidate.confidence = FieldConfidence {
            overall: Confidence::High,
            notes: "Docs contained a curl example; curl evidence dominates prose".to_string(),
        };
        candidate.evidence.push(EvidenceItem {
            source_kind: SourceKind::Docs,
            label: "docs curl block".to_string(),
            detail: "Detected code-fenced curl example inside docs".to_string(),
            confidence: Confidence::High,
        });
        let key = draft_key(&candidate);
        seen.insert(key, candidates.len());
        candidates.push(candidate);
    }

    let base_url = BASE_URL_RE.find(raw_text).map(|item| {
        let raw = item.as_str();
        match url::Url::parse(raw) {
            Ok(url) => format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or_default(),
                url.port()
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default()
            ),
            Err(_) => raw.to_string(),
        }
    });

    let body_example = JSON_BLOCK_RE
        .captures(raw_text)
        .and_then(|captures| captures.get(1).map(|item| item.as_str().trim().to_string()));

    for captures in METHOD_PATH_RE.captures_iter(raw_text) {
        let method = captures.get(1).map(|item| item.as_str()).unwrap_or("GET");
        let raw_target = captures.get(2).map(|item| item.as_str()).unwrap_or("/");
        let (candidate_base_url, path, query) = parse_target(raw_target, base_url.clone());
        let path = normalize_path_template(&path);
        let mut slots = infer_slots(&path, &query, body_example.as_deref());
        let mut auth = infer_auth_style(raw_text, &mut slots);
        let headers = infer_headers(raw_text);
        if matches!(auth, AuthStyle::None) {
            auth = infer_auth_from_headers(&headers, &mut slots);
        }

        let mut draft = RequestDraft {
            operation_id: format!("docs-{}", uuid::Uuid::new_v4()),
            name: format!("{} {}", method.to_uppercase(), path),
            method: method.to_uppercase(),
            base_url: candidate_base_url,
            path,
            headers,
            query,
            body: body_example
                .as_ref()
                .map(|body| BodyTemplate::Json {
                    template: body.clone(),
                })
                .unwrap_or(BodyTemplate::None),
            auth,
            slots,
            evidence: vec![EvidenceItem {
                source_kind: SourceKind::Docs,
                label: "docs prose".to_string(),
                detail: format!("Detected `{method} {raw_target}` in prose"),
                confidence: Confidence::Medium,
            }],
            confidence: FieldConfidence {
                overall: Confidence::Medium,
                notes: "Built from prose heuristics".to_string(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: vec![SourceKind::Docs],
        };

        let key = draft_key(&draft);
        if let Some(index) = seen.get(&key).copied() {
            candidates[index].evidence.push(EvidenceItem {
                source_kind: SourceKind::Docs,
                label: "docs prose confirmation".to_string(),
                detail: format!("Prose also referenced `{}`", draft.endpoint_summary()),
                confidence: Confidence::Medium,
            });
            continue;
        }

        if draft.base_url.is_none() && base_url.is_none() {
            draft.confidence.overall = Confidence::Low;
            draft.confidence.notes = "Method/path found but base URL was not explicit".to_string();
        }
        seen.insert(key, candidates.len());
        candidates.push(draft);
    }

    if candidates.is_empty() {
        notes.push("Docs were too unclear to build a sensible request".to_string());
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

fn extract_curl_candidates(raw_text: &str) -> Vec<RequestDraft> {
    let mut drafts = Vec::new();
    for captures in CURL_BLOCK_RE.captures_iter(raw_text) {
        if let Some(block) = captures.get(1) {
            let parsed = parse_curl_input(block.as_str());
            drafts.extend(parsed.candidates);
        }
    }
    drafts
}

fn parse_target(
    raw_target: &str,
    fallback_base_url: Option<String>,
) -> (Option<String>, String, Vec<KeyValueField>) {
    if let Ok(url) = url::Url::parse(raw_target) {
        let base_url = format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap_or_default(),
            url.port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        let query = url
            .query_pairs()
            .map(|(key, value)| KeyValueField {
                key: key.to_string(),
                value: value.to_string(),
                required: false,
                description: "Query inferred from prose example".to_string(),
                confidence: Confidence::Medium,
            })
            .collect();
        return (Some(base_url), url.path().to_string(), query);
    }

    let mut path = raw_target.to_string();
    let mut query = Vec::new();
    if let Some((left, right)) = raw_target.split_once('?') {
        path = left.to_string();
        query = url::form_urlencoded::parse(right.as_bytes())
            .map(|(key, value)| KeyValueField {
                key: key.to_string(),
                value: value.to_string(),
                required: false,
                description: "Query inferred from prose example".to_string(),
                confidence: Confidence::Medium,
            })
            .collect();
    }
    (fallback_base_url, path, query)
}

fn infer_headers(raw_text: &str) -> Vec<HeaderField> {
    let mut headers = Vec::new();
    if raw_text.to_ascii_lowercase().contains("content-type")
        && raw_text.to_ascii_lowercase().contains("json")
    {
        headers.push(HeaderField {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
            required: true,
            description: "Docs mention JSON content type".to_string(),
            confidence: Confidence::Medium,
        });
    }

    for captures in FIELD_RE.captures_iter(raw_text) {
        let key = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or_default();
        if raw_text.to_ascii_lowercase().contains("header")
            && (key.eq_ignore_ascii_case("authorization")
                || key.eq_ignore_ascii_case("x-api-key")
                || key.eq_ignore_ascii_case("content-type"))
        {
            headers.push(HeaderField {
                key: key.to_string(),
                value: if key.eq_ignore_ascii_case("content-type") {
                    "application/json".to_string()
                } else {
                    slot_token(&key.to_ascii_lowercase().replace('-', "_"))
                },
                required: true,
                description: "Header mentioned in docs".to_string(),
                confidence: Confidence::Low,
            });
        }
    }
    dedupe_headers(&mut headers);
    headers
}

fn infer_auth_style(raw_text: &str, slots: &mut Vec<RuntimeSlot>) -> AuthStyle {
    let lower = raw_text.to_ascii_lowercase();
    if lower.contains("bearer token") || lower.contains("authorization: bearer") {
        slots.push(RuntimeSlot {
            name: "bearer_token".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: None,
            description: "Bearer token from docs".to_string(),
            confidence: Confidence::Medium,
        });
        return AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        };
    }
    if lower.contains("x-api-key") {
        slots.push(RuntimeSlot {
            name: "api_key".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: None,
            description: "API key from docs".to_string(),
            confidence: Confidence::Medium,
        });
        return AuthStyle::HeaderApiKey {
            header_name: "X-API-Key".to_string(),
            slot_name: "api_key".to_string(),
        };
    }
    if lower.contains("api_key") && lower.contains("query") {
        slots.push(RuntimeSlot {
            name: "api_key".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: None,
            description: "API key query parameter from docs".to_string(),
            confidence: Confidence::Low,
        });
        return AuthStyle::QueryApiKey {
            param_name: "api_key".to_string(),
            slot_name: "api_key".to_string(),
        };
    }
    AuthStyle::None
}

fn infer_auth_from_headers(headers: &[HeaderField], slots: &mut Vec<RuntimeSlot>) -> AuthStyle {
    for header in headers {
        if header.key.eq_ignore_ascii_case("authorization") {
            slots.push(RuntimeSlot {
                name: "bearer_token".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: None,
                description: "Authorization token".to_string(),
                confidence: Confidence::Low,
            });
            return AuthStyle::Bearer {
                token_slot: "bearer_token".to_string(),
                header_name: header.key.clone(),
            };
        }
        if header.key.eq_ignore_ascii_case("x-api-key") {
            slots.push(RuntimeSlot {
                name: "api_key".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: None,
                description: "API key".to_string(),
                confidence: Confidence::Low,
            });
            return AuthStyle::HeaderApiKey {
                header_name: header.key.clone(),
                slot_name: "api_key".to_string(),
            };
        }
    }
    AuthStyle::None
}

fn infer_slots(path: &str, query: &[KeyValueField], body: Option<&str>) -> Vec<RuntimeSlot> {
    let mut slots = Vec::new();
    for slot in extract_slot_names(path) {
        slots.push(RuntimeSlot {
            name: slot.clone(),
            location: SlotLocation::Path,
            required: true,
            current_value: None,
            description: format!("Path parameter {slot}"),
            confidence: Confidence::Medium,
        });
    }

    for item in query {
        for slot in extract_slot_names(&item.value) {
            slots.push(RuntimeSlot {
                name: slot.clone(),
                location: SlotLocation::Query,
                required: item.required,
                current_value: None,
                description: format!("Query parameter {}", item.key),
                confidence: item.confidence.clone(),
            });
        }
    }

    if let Some(body) = body {
        for slot in extract_slot_names(body) {
            slots.push(RuntimeSlot {
                name: slot.clone(),
                location: SlotLocation::Body,
                required: true,
                current_value: None,
                description: format!("Body field {slot}"),
                confidence: Confidence::Low,
            });
        }
    }

    for captures in FIELD_RE.captures_iter(path) {
        if let Some(field) = captures.get(1) {
            let field_name = field.as_str().to_ascii_lowercase();
            if !slots.iter().any(|slot| slot.name == field_name) {
                slots.push(RuntimeSlot {
                    name: field_name.clone(),
                    location: SlotLocation::Body,
                    required: true,
                    current_value: None,
                    description: "Required field mentioned in docs".to_string(),
                    confidence: Confidence::Low,
                });
            }
        }
    }

    dedupe_slots(&mut slots);
    slots
}

fn normalize_path_template(path: &str) -> String {
    let mut normalized = path.to_string();
    let path_regex = Regex::new(r"\{([a-zA-Z0-9_\-]+)\}").expect("path regex");
    for captures in path_regex.captures_iter(path) {
        let full = captures
            .get(0)
            .map(|item| item.as_str())
            .unwrap_or_default();
        let name = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or_default();
        normalized = normalized.replace(full, &slot_token(name));
    }
    normalized
}

fn draft_key(draft: &RequestDraft) -> String {
    format!("{} {}", draft.method, draft.path)
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

fn dedupe_headers(headers: &mut Vec<HeaderField>) {
    let mut unique = Vec::new();
    for header in headers.drain(..) {
        if !unique
            .iter()
            .any(|existing: &HeaderField| existing.key.eq_ignore_ascii_case(&header.key))
        {
            unique.push(header);
        }
    }
    *headers = unique;
}

#[cfg(test)]
mod tests {
    use super::parse_docs_input;
    use crate::model::AuthStyle;

    #[test]
    fn extracts_docs_candidates_and_auth_hint() {
        let docs = r#"
Base URL: https://api.example.com
POST /v1/customers/{customer_id}
Use Bearer token authentication.
```json
{"plan":"pro","customer_id":"{{customer_id}}"}
```
"#;
        let parsed = parse_docs_input(docs);
        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.method, "POST");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/v1/customers/{{customer_id}}");
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
    }
}
