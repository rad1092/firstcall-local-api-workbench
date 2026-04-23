use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};

use crate::model::{
    BodyTemplate, HeaderField, KeyValueField, RenderedHeader, RenderedRequest, RequestDraft,
    ResponseSnapshot, RuntimeSlot,
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

    use super::{REDACTED, redact_body, redact_json_value, redact_request};
    use crate::model::{RenderedHeader, RenderedRequest};

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
}
