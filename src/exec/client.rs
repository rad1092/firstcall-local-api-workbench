use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::blocking::{Client, multipart};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tracing::debug;

use crate::exec::classifier::classify_outcome;
use crate::exec::validation::validate_json_schema;
use crate::model::{
    AppSettings, AuthStyle, Blocker, BodyTemplate, ExecutionResult, KeyValueField, RenderedHeader,
    RenderedRequest, RequestDraft, ResponseSnapshot,
};
use crate::util::{looks_like_slot_value, replace_slots};

pub mod bounded;

const REDIRECT_BLOCKED_MESSAGE: &str = "Redirect blocked: use the API's final endpoint URL and verify it again before exporting an MCP tool";

pub fn build_http_client(settings: &AppSettings) -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(settings.timeout_secs))
        .build()
        .map_err(anyhow::Error::from)
}

pub fn execute_request(
    draft: &RequestDraft,
    settings: &AppSettings,
    client: &Client,
) -> ExecutionResult {
    match perform_request(draft, settings, client) {
        Ok(result) => result,
        Err(error) => ExecutionResult {
            rendered_request: RenderedRequest {
                method: draft.method.clone(),
                url: draft.endpoint_summary(),
                headers: Vec::new(),
                body_preview: None,
            },
            response_snapshot: Some(ResponseSnapshot {
                status: None,
                headers: Vec::new(),
                body_preview: String::new(),
                elapsed_ms: 0,
                validation_errors: Vec::new(),
                transport_error: Some(error.to_string()),
            }),
            outcome: crate::model::Outcome::Failure,
            blocker: Some(Blocker::UnknownFailure),
            notes: error.to_string(),
        },
    }
}

fn perform_request(
    draft: &RequestDraft,
    settings: &AppSettings,
    client: &Client,
) -> Result<ExecutionResult> {
    if let Some(reason) = &draft.unsupported_reason {
        return Ok(blocked_result(
            draft,
            Blocker::UnsupportedInput,
            reason.clone(),
        ));
    }

    let prepared = prepare_request(draft)?;
    let rendered_request = RenderedRequest {
        method: prepared.method.clone(),
        url: prepared.url.clone(),
        headers: prepared
            .headers
            .iter()
            .map(|(key, value)| RenderedHeader {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        body_preview: prepared.body_preview.clone(),
    };

    let method: reqwest::Method = prepared.method.parse().context("Unsupported HTTP method")?;
    let mut builder = client.request(method, &prepared.url);

    let header_map = to_header_map(&prepared.headers)?;
    builder = builder.headers(header_map);

    builder = match prepared.body {
        PreparedBody::None => builder,
        PreparedBody::Text { text } => builder.body(text),
        PreparedBody::Multipart { fields } => {
            let mut form = multipart::Form::new();
            for (key, value) in fields {
                form = form.text(key, value.expose_secret().to_string());
            }
            builder.multipart(form)
        }
    };

    let started = Instant::now();
    let response = builder.send();
    let elapsed_ms = started.elapsed().as_millis();

    let response_snapshot = match response {
        Ok(response) if response.status().is_redirection() => ResponseSnapshot {
            status: Some(response.status().as_u16()),
            headers: Vec::new(),
            body_preview: String::new(),
            elapsed_ms,
            validation_errors: Vec::new(),
            transport_error: Some(REDIRECT_BLOCKED_MESSAGE.to_string()),
        },
        Ok(response) => response_to_snapshot(response, elapsed_ms, settings, draft),
        Err(error) => ResponseSnapshot {
            status: None,
            headers: Vec::new(),
            body_preview: String::new(),
            elapsed_ms,
            validation_errors: Vec::new(),
            transport_error: Some(error.to_string()),
        },
    };

    let notes = if response_snapshot.transport_error.as_deref() == Some(REDIRECT_BLOCKED_MESSAGE) {
        REDIRECT_BLOCKED_MESSAGE.to_string()
    } else if response_snapshot.validation_errors.is_empty() {
        "Request executed".to_string()
    } else {
        format!(
            "Request executed with {} validation issue(s)",
            response_snapshot.validation_errors.len()
        )
    };
    let (outcome, blocker) = classify_outcome(
        None,
        Some(&response_snapshot),
        draft.unsupported_reason.as_deref(),
        settings,
    );
    Ok(ExecutionResult {
        rendered_request,
        response_snapshot: Some(response_snapshot),
        outcome,
        blocker,
        notes,
    })
}

fn blocked_result(draft: &RequestDraft, blocker: Blocker, notes: String) -> ExecutionResult {
    ExecutionResult {
        rendered_request: RenderedRequest {
            method: draft.method.clone(),
            url: draft.endpoint_summary(),
            headers: Vec::new(),
            body_preview: None,
        },
        response_snapshot: None,
        outcome: crate::model::Outcome::Failure,
        blocker: Some(blocker),
        notes,
    }
}

struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body_preview: Option<String>,
    body: PreparedBody,
}

enum PreparedBody {
    None,
    Text { text: String },
    Multipart { fields: Vec<(String, SecretString)> },
}

fn prepare_request(draft: &RequestDraft) -> Result<PreparedRequest> {
    let base_url = draft
        .base_url
        .as_deref()
        .context("Base URL is required before running the request")?;
    let slot_values = collect_slot_values(draft)?;

    let (rendered_path, missing_path) = replace_slots(&draft.path, &slot_values);
    if !missing_path.is_empty() {
        anyhow::bail!("Missing required path values: {}", missing_path.join(", "));
    }

    let mut url = build_url(base_url, &rendered_path)?;
    for item in &draft.query {
        let value = render_value(
            &item.value,
            &slot_values,
            &format!("query parameter {}", item.key),
        )?;
        url.query_pairs_mut().append_pair(&item.key, &value);
    }

    let mut headers = Vec::<(String, String)>::new();
    for header in &draft.headers {
        let value = render_value(
            &header.value,
            &slot_values,
            &format!("header {}", header.key),
        )?;
        headers.push((header.key.clone(), value));
    }

    let auth_headers = apply_auth(&draft.auth, &slot_values, &mut url)?;
    headers.extend(auth_headers);

    let body = match &draft.body {
        BodyTemplate::None => PreparedBody::None,
        BodyTemplate::Json { template } => {
            let rendered = render_value(template, &slot_values, "JSON body")?;
            serde_json::from_str::<Value>(&rendered)
                .context("JSON body is invalid after slot substitution")?;
            ensure_content_type(&mut headers, "application/json");
            PreparedBody::Text { text: rendered }
        }
        BodyTemplate::Text { text } => PreparedBody::Text {
            text: render_value(text, &slot_values, "text body")?,
        },
        BodyTemplate::Form { fields } => {
            let encoded = encode_fields(fields, &slot_values)?;
            ensure_content_type(&mut headers, "application/x-www-form-urlencoded");
            PreparedBody::Text { text: encoded }
        }
        BodyTemplate::Multipart { fields } => PreparedBody::Multipart {
            fields: render_secret_fields(fields, &slot_values)?,
        },
    };

    let body_preview = match &body {
        PreparedBody::None => None,
        PreparedBody::Text { text } => Some(text.clone()),
        PreparedBody::Multipart { fields } => Some(
            fields
                .iter()
                .map(|(key, value)| format!("{key}={}", value.expose_secret()))
                .collect::<Vec<_>>()
                .join("&"),
        ),
    };

    Ok(PreparedRequest {
        method: draft.method.clone(),
        url: url.to_string(),
        headers,
        body_preview,
        body,
    })
}

fn collect_slot_values(draft: &RequestDraft) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for slot in &draft.slots {
        let current = slot.current_value.clone().unwrap_or_default();
        if slot.required && current.trim().is_empty() {
            anyhow::bail!("Missing required slot: {}", slot.name);
        }
        if !current.trim().is_empty() {
            values.insert(slot.name.clone(), current);
        }
    }
    Ok(values)
}

fn render_value(template: &str, values: &HashMap<String, String>, label: &str) -> Result<String> {
    let (rendered, missing) = replace_slots(template, values);
    if !missing.is_empty() {
        anyhow::bail!("Missing values for {label}: {}", missing.join(", "));
    }
    if looks_like_slot_value(&rendered) {
        anyhow::bail!("Unresolved placeholder remains in {label}");
    }
    Ok(rendered)
}

fn encode_fields(fields: &[KeyValueField], values: &HashMap<String, String>) -> Result<String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for field in fields {
        serializer.append_pair(
            &field.key,
            &render_value(&field.value, values, &format!("body field {}", field.key))?,
        );
    }
    Ok(serializer.finish())
}

fn render_secret_fields(
    fields: &[KeyValueField],
    values: &HashMap<String, String>,
) -> Result<Vec<(String, SecretString)>> {
    let mut rendered = Vec::new();
    for field in fields {
        let value = render_value(
            &field.value,
            values,
            &format!("multipart field {}", field.key),
        )?;
        rendered.push((field.key.clone(), SecretString::new(value.into())));
    }
    Ok(rendered)
}

fn apply_auth(
    auth: &AuthStyle,
    values: &HashMap<String, String>,
    url: &mut url::Url,
) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    match auth {
        AuthStyle::None => {}
        AuthStyle::Bearer {
            token_slot,
            header_name,
        } => {
            let token = values
                .get(token_slot)
                .with_context(|| format!("Missing auth slot {token_slot}"))?;
            headers.push((header_name.clone(), format!("Bearer {token}")));
        }
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => {
            let username = values
                .get(username_slot)
                .with_context(|| format!("Missing auth slot {username_slot}"))?;
            let password = values
                .get(password_slot)
                .with_context(|| format!("Missing auth slot {password_slot}"))?;
            let raw = format!("{username}:{password}");
            headers.push((
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(raw)
                ),
            ));
        }
        AuthStyle::HeaderApiKey {
            header_name,
            slot_name,
        } => {
            let value = values
                .get(slot_name)
                .with_context(|| format!("Missing auth slot {slot_name}"))?;
            headers.push((header_name.clone(), value.clone()));
        }
        AuthStyle::QueryApiKey {
            param_name,
            slot_name,
        } => {
            let value = values
                .get(slot_name)
                .with_context(|| format!("Missing auth slot {slot_name}"))?;
            url.query_pairs_mut().append_pair(param_name, value);
        }
    }
    Ok(headers)
}

fn ensure_content_type(headers: &mut Vec<(String, String)>, value: &str) {
    if headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
    {
        return;
    }
    headers.push(("Content-Type".to_string(), value.to_string()));
}

fn build_url(base_url: &str, path: &str) -> Result<url::Url> {
    let normalized = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", base_url.trim_end_matches('/'), path)
    };
    url::Url::parse(&normalized).with_context(|| format!("Malformed URL: {normalized}"))
}

fn to_header_map(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (key, value) in headers {
        let name = HeaderName::from_bytes(key.as_bytes())
            .with_context(|| format!("Invalid header name: {key}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("Invalid value for header {key}"))?;
        map.insert(name, value);
    }
    Ok(map)
}

fn response_to_snapshot(
    response: reqwest::blocking::Response,
    elapsed_ms: u128,
    settings: &AppSettings,
    draft: &RequestDraft,
) -> ResponseSnapshot {
    let status = response.status().as_u16();
    let headers: Vec<RenderedHeader> = response
        .headers()
        .iter()
        .map(|(key, value)| RenderedHeader {
            key: key.as_str().to_string(),
            value: value.to_str().unwrap_or("<binary>").to_string(),
        })
        .collect();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let bytes = match response.bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return ResponseSnapshot {
                status: Some(status),
                headers,
                body_preview: String::new(),
                elapsed_ms,
                validation_errors: Vec::new(),
                transport_error: Some(error.to_string()),
            };
        }
    };

    let preview_bytes = bytes
        .iter()
        .take(settings.response_preview_limit_bytes)
        .copied()
        .collect::<Vec<_>>();
    let body_text = String::from_utf8_lossy(&preview_bytes).to_string();
    let body_preview = if content_type.contains("json") {
        pretty_json(&body_text).unwrap_or(body_text)
    } else {
        body_text
    };

    let validation_errors = if content_type.contains("json") {
        match (
            draft.response_schema.as_ref(),
            serde_json::from_slice::<Value>(&bytes),
        ) {
            (Some(schema), Ok(body)) => {
                let validation = validate_json_schema(&schema.schema, &body);
                validation.errors
            }
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };

    debug!("HTTP response status={status}");
    ResponseSnapshot {
        status: Some(status),
        headers,
        body_preview,
        elapsed_ms,
        validation_errors,
        transport_error: None,
    }
}

fn pretty_json(text: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

#[cfg(test)]
mod tests {
    use reqwest::blocking::Client;

    use super::{build_http_client, prepare_request};
    use crate::model::{
        AppSettings, AuthStyle, BodyTemplate, Confidence, FieldConfidence, RequestDraft,
        RuntimeSlot, SlotLocation,
    };

    #[test]
    fn prepares_url_and_body() {
        let draft = RequestDraft {
            operation_id: "x".to_string(),
            name: "Test".to_string(),
            method: "POST".to_string(),
            base_url: Some("https://api.example.com".to_string()),
            path: "/v1/customers/{{customer_id}}".to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: BodyTemplate::Json {
                template: "{\"id\":\"{{customer_id}}\"}".to_string(),
            },
            auth: AuthStyle::None,
            slots: vec![RuntimeSlot {
                name: "customer_id".to_string(),
                location: SlotLocation::Path,
                required: true,
                current_value: Some("cus_123".to_string()),
                description: String::new(),
                confidence: Confidence::High,
            }],
            evidence: Vec::new(),
            confidence: FieldConfidence {
                overall: Confidence::High,
                notes: String::new(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: Vec::new(),
        };
        let prepared = prepare_request(&draft).expect("request should prepare");
        assert!(prepared.url.ends_with("/v1/customers/cus_123"));
    }

    #[test]
    fn builds_http_client() {
        let client: Client =
            build_http_client(&AppSettings::default()).expect("client should build");
        let _ = client;
    }
}
