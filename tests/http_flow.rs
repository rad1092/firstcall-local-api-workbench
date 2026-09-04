use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use firstcall::exec::client::{build_http_client, execute_request};
use firstcall::model::{
    AppSettings, AuthStyle, BodyTemplate, Confidence, FieldConfidence, RequestDraft, RuntimeSlot,
    SchemaSpec, SlotLocation,
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
fn redirect_cannot_be_verified_as_a_working_native_tool_or_contact_its_destination() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let (base_url, request_rx) = spawn_server(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        destination.local_addr().unwrap()
    ));
    let draft = RequestDraft {
        operation_id: "redirect".into(),
        name: "Redirecting API".into(),
        method: "GET".into(),
        base_url: Some(base_url),
        path: "/start".into(),
        headers: vec![],
        query: vec![],
        body: BodyTemplate::None,
        auth: AuthStyle::None,
        slots: vec![],
        evidence: vec![],
        confidence: FieldConfidence {
            overall: Confidence::High,
            notes: String::new(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: vec![],
    };
    // Even a custom status range must not mark a blocked redirect verified.
    let settings = AppSettings {
        success_status_max: 399,
        ..AppSettings::default()
    };
    let client = build_http_client(&settings).unwrap();
    let result = execute_request(&draft, &settings, &client);
    assert_eq!(result.outcome, firstcall::model::Outcome::Failure);
    assert_eq!(result.response_snapshot.as_ref().unwrap().status, Some(302));
    assert!(result.notes.contains("Redirect blocked"));
    assert!(result.notes.contains("final endpoint URL"));
    assert!(
        request_rx
            .recv()
            .unwrap()
            .starts_with("GET /start HTTP/1.1")
    );
    assert!(
        destination.accept().is_err(),
        "Redirect destination was contacted"
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
