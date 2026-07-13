use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use firstcall::exec::client::{build_http_client, execute_request};
use firstcall::model::{
    AppSettings, AuthStyle, Blocker, BodyTemplate, Confidence, FieldConfidence, HeaderField,
    KeyValueField, Outcome, RequestDraft, RuntimeSlot, SchemaSpec, SlotLocation,
};
use serde_json::json;

#[test]
fn successful_json_request_flow() {
    let (base_url, request_rx) = spawn_server(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"note_123\",\"status\":\"ok\"}",
    );

    let draft = RequestDraft {
        operation_id: "op_success".to_string(),
        name: "Create note".to_string(),
        method: "POST".to_string(),
        base_url: Some(base_url),
        path: "/v1/customers/{{customer_id}}/notes".to_string(),
        headers: Vec::new(),
        query: Vec::new(),
        body: BodyTemplate::Json {
            template: "{\"note\":\"Reached by phone\"}".to_string(),
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
        response_schema: Some(SchemaSpec {
            name: Some("response".to_string()),
            schema: json!({
                "type": "object",
                "required": ["id", "status"],
                "properties": {
                    "id": { "type": "string" },
                    "status": { "type": "string" }
                }
            }),
        }),
        unsupported_reason: None,
        source_kinds: Vec::new(),
    };

    let client = build_http_client(&AppSettings::default()).expect("client");
    let result = execute_request(&draft, &AppSettings::default(), &client);
    assert_eq!(result.outcome, firstcall::model::Outcome::Success);
    assert!(result.blocker.is_none());
    assert_eq!(
        result
            .response_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.status),
        Some(200)
    );

    let request = request_rx.recv().expect("request capture");
    assert!(request.starts_with("POST /v1/customers/cus_123/notes HTTP/1.1"));
}

#[test]
fn auth_failure_flow() {
    let (base_url, _request_rx) = spawn_server(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"unauthorized\"}",
    );

    let draft = RequestDraft {
        operation_id: "op_auth".to_string(),
        name: "Auth".to_string(),
        method: "GET".to_string(),
        base_url: Some(base_url),
        path: "/v1/secure".to_string(),
        headers: Vec::new(),
        query: Vec::new(),
        body: BodyTemplate::None,
        auth: AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        },
        slots: vec![RuntimeSlot {
            name: "bearer_token".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: Some("secret".to_string()),
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

    let client = build_http_client(&AppSettings::default()).expect("client");
    let result = execute_request(&draft, &AppSettings::default(), &client);
    assert_eq!(result.outcome, firstcall::model::Outcome::Failure);
    assert_eq!(result.blocker, Some(firstcall::model::Blocker::AuthBlocked));
    assert_eq!(
        result
            .response_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.status),
        Some(401)
    );
}

#[test]
fn path_slots_are_encoded_as_data_without_changing_request_structure() {
    let (base_url, request_rx) = spawn_server(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
    );
    let mut draft = get_draft(base_url, "/users/{{user_id}}");
    draft.slots.push(RuntimeSlot {
        name: "user_id".to_string(),
        location: SlotLocation::Path,
        required: true,
        current_value: Some("alpha beta?scope=all#fragment".to_string()),
        description: String::new(),
        confidence: Confidence::High,
    });

    let settings = AppSettings::default();
    let client = build_http_client(&settings).expect("client");
    let result = execute_request(&draft, &settings, &client);

    assert_eq!(result.outcome, Outcome::Success);
    let request = request_rx.recv().expect("request capture");
    assert!(request.starts_with("GET /users/alpha%20beta%3Fscope%3Dall%23fragment HTTP/1.1"));
}

#[test]
fn structural_and_encoded_structural_path_slots_are_rejected_before_network() {
    for value in [
        "alpha/beta",
        r"alpha\beta",
        "%2fadmin",
        "%252Fadmin",
        "%5cadmin",
        ".",
        "..",
        "%2e%2e",
        "%252e%252e",
    ] {
        let mut draft = get_draft("https://example.com".to_string(), "/users/{{user_id}}");
        draft.slots.push(RuntimeSlot {
            name: "user_id".to_string(),
            location: SlotLocation::Path,
            required: true,
            current_value: Some(value.to_string()),
            description: String::new(),
            confidence: Confidence::High,
        });

        let settings = AppSettings::default();
        let client = build_http_client(&settings).expect("client");
        let result = execute_request(&draft, &settings, &client);

        assert_eq!(result.outcome, Outcome::Failure, "value={value}");
        assert!(result.notes.contains("slash, backslash, or dot segment"));
    }
}

#[test]
fn structural_characters_remain_valid_in_non_path_slots() {
    let (base_url, request_rx) = spawn_server(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
    );
    let mut draft = get_draft(base_url, "/users");
    draft.query.push(field("filter", "{{filter}}"));
    draft.slots.push(RuntimeSlot {
        name: "filter".to_string(),
        location: SlotLocation::Query,
        required: true,
        current_value: Some("team/admin".to_string()),
        description: String::new(),
        confidence: Confidence::High,
    });

    let settings = AppSettings::default();
    let client = build_http_client(&settings).expect("client");
    let result = execute_request(&draft, &settings, &client);

    assert_eq!(result.outcome, Outcome::Success);
    let request = request_rx.recv().expect("request capture");
    assert!(request.starts_with("GET /users?filter=team%2Fadmin HTTP/1.1"));
}

#[test]
fn read_only_method_override_inputs_are_rejected_before_network() {
    for name in [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    ] {
        let mut draft = get_draft("https://example.com".to_string(), "/users");
        draft.headers.push(header(name, "DELETE"));
        assert_policy_failure(&draft, "blocked by policy");
    }

    let mut query = get_draft("https://example.com".to_string(), "/users");
    query.query.push(field("_METHOD", "DELETE"));
    assert_policy_failure(&query, "_method query parameter");

    let mut form = get_draft("https://example.com".to_string(), "/users");
    form.body = BodyTemplate::Form {
        fields: vec![field("_method", "DELETE")],
    };
    assert_policy_failure(&form, "_method form field");
}

#[test]
fn authority_proxy_and_framing_headers_are_rejected_before_network() {
    for name in [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Upgrade",
        "Proxy-Authorization",
        "Cookie",
        "Forwarded",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-For",
        "X-Original-URL",
        "X-Rewrite-URL",
    ] {
        let mut draft = get_draft("https://example.com".to_string(), "/users");
        draft.headers.push(header(name, "attacker-controlled"));
        assert_policy_failure(&draft, "blocked by policy");
    }
}

#[test]
fn ipv4_mapped_ipv6_uses_the_mapped_ipv4_address_class_policy() {
    for base_url in [
        "http://[::ffff:0:0]",
        "http://[::ffff:a9fe:101]",
        "http://[::ffff:e000:1]",
    ] {
        let draft = get_draft(base_url.to_string(), "/users");
        assert_policy_failure(&draft, "disallowed IPv6 address class");
    }
}

#[test]
fn oversized_response_is_bounded_and_never_marked_successful() {
    let body = "x".repeat(128);
    let (base_url, _request_rx) = spawn_server(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    let draft = get_draft(base_url, "/large");
    let settings = AppSettings {
        response_preview_limit_bytes: 8,
        response_body_limit_bytes: 16,
        ..AppSettings::default()
    };
    let client = build_http_client(&settings).expect("client");

    let result = execute_request(&draft, &settings, &client);
    let snapshot = result.response_snapshot.expect("response snapshot");

    assert_eq!(result.outcome, Outcome::Failure);
    assert_eq!(result.blocker, Some(Blocker::ResourceLimitExceeded));
    assert!(snapshot.body_truncated);
    assert_eq!(snapshot.bytes_read, 17);
    assert_eq!(snapshot.body_preview.len(), 8);
}

#[test]
fn malformed_json_with_response_schema_is_a_schema_mismatch() {
    let (base_url, _request_rx) = spawn_server(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{",
    );
    let mut draft = get_draft(base_url, "/malformed");
    draft.response_schema = Some(SchemaSpec {
        name: Some("response".to_string()),
        schema: json!({ "type": "object" }),
    });
    let settings = AppSettings::default();
    let client = build_http_client(&settings).expect("client");

    let result = execute_request(&draft, &settings, &client);

    assert_eq!(result.outcome, Outcome::Partial);
    assert_eq!(result.blocker, Some(Blocker::SchemaMismatch));
    assert!(
        result
            .response_snapshot
            .expect("snapshot")
            .validation_errors
            .iter()
            .any(|error| error.contains("malformed"))
    );
}

#[test]
fn automatic_redirects_are_not_followed() {
    let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
    target.set_nonblocking(true).expect("nonblocking target");
    let target_address = target.local_addr().expect("target address");
    let (target_tx, target_rx) = mpsc::channel();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match target.accept() {
                Ok(_) => {
                    target_tx.send(true).ok();
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        target_tx.send(false).ok();
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    target_tx.send(false).ok();
                    return;
                }
            }
        }
    });
    let (base_url, _request_rx) = spawn_server(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let draft = get_draft(base_url, "/redirect");
    let settings = AppSettings::default();
    let client = build_http_client(&settings).expect("client");

    let result = execute_request(&draft, &settings, &client);

    assert_eq!(
        result
            .response_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.status),
        Some(302)
    );
    assert!(!target_rx.recv().expect("target observation"));
}

fn get_draft(base_url: String, path: &str) -> RequestDraft {
    RequestDraft {
        operation_id: "op_get".to_string(),
        name: "GET fixture".to_string(),
        method: "GET".to_string(),
        base_url: Some(base_url),
        path: path.to_string(),
        headers: Vec::new(),
        query: Vec::new(),
        body: BodyTemplate::None,
        auth: AuthStyle::None,
        slots: Vec::new(),
        evidence: Vec::new(),
        confidence: FieldConfidence {
            overall: Confidence::High,
            notes: String::new(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: Vec::new(),
    }
}

fn header(key: &str, value: &str) -> HeaderField {
    HeaderField {
        key: key.to_string(),
        value: value.to_string(),
        required: true,
        description: String::new(),
        confidence: Confidence::High,
    }
}

fn field(key: &str, value: &str) -> KeyValueField {
    KeyValueField {
        key: key.to_string(),
        value: value.to_string(),
        required: true,
        description: String::new(),
        confidence: Confidence::High,
    }
}

fn assert_policy_failure(draft: &RequestDraft, expected_note: &str) {
    let settings = AppSettings::default();
    let client = build_http_client(&settings).expect("client");
    let result = execute_request(draft, &settings, &client);
    assert_eq!(result.outcome, Outcome::Failure);
    assert!(
        result.notes.contains(expected_note),
        "expected note containing {expected_note:?}, got {:?}",
        result.notes
    );
}

fn spawn_server(response: impl Into<String>) -> (String, mpsc::Receiver<String>) {
    let response = response.into();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer).expect("read");
        tx.send(String::from_utf8_lossy(&buffer[..bytes_read]).to_string())
            .ok();
        stream.write_all(response.as_bytes()).expect("write");
        stream.flush().expect("flush");
    });
    (format!("http://{}", address), rx)
}
