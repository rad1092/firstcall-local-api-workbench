use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use firstcall::export::agent_package::export_agent_package;
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, KeyValueField, Recipe, RuntimeSlot, SlotLocation,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const SECRET: &str = "runtime-credential-never-in-model-output";

fn slot(name: &str, location: SlotLocation) -> RuntimeSlot {
    RuntimeSlot {
        name: name.into(),
        location,
        required: true,
        current_value: None,
        description: format!("The {name} to look up"),
        confidence: Confidence::High,
    }
}

fn recipe(url: String) -> Recipe {
    Recipe {
        id: None,
        name: "Find user".into(),
        method: "GET".into(),
        url_template: url,
        headers_template: vec![],
        query_template: vec![],
        body_template: BodyTemplate::None,
        auth_style: AuthStyle::None,
        slots: vec![slot("user_id", SlotLocation::Path)],
        last_success_at: Some(chrono::Utc::now()),
        last_success_status: Some(200),
    }
}

fn package(recipe: &Recipe) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    export_agent_package(recipe, dir.path()).unwrap();
    let properties: serde_json::Map<_, _> = recipe
        .slots
        .iter()
        .filter(|slot| slot.location != SlotLocation::Auth)
        .map(|slot| {
            (
                slot.name.clone(),
                json!({"type":"string", "description":slot.description}),
            )
        })
        .collect();
    let required: Vec<_> = recipe
        .slots
        .iter()
        .filter(|slot| slot.location != SlotLocation::Auth && slot.required)
        .map(|slot| &slot.name)
        .collect();
    fs::write(dir.path().join("tool.json"), json!({"schema_version":1,"name":"find_user","title":"Find user",
        "description":"Look up the user's profile and return their display name.",
        "input_schema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}}).to_string()).unwrap();
    dir
}

fn handshake() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test-client","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ]
}

fn call(id: u64, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"find_user","arguments":arguments}})
}

fn run_raw(package: &TempDir, input: &[u8], env: &[(&str, &str)], mutating: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_firstcall-cli"));
    command
        .env_clear()
        .args(["serve", "--package"])
        .arg(package.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if mutating {
        command.arg("--allow-mutating");
    }
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    // Invalid packages can exit before reading stdin.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

fn run(
    package: &TempDir,
    messages: Vec<Value>,
    env: &[(&str, &str)],
    mutating: bool,
) -> (Output, Vec<Value>) {
    let input = messages
        .iter()
        .map(|message| format!("{message}\n"))
        .collect::<String>();
    let output = run_raw(package, input.as_bytes(), env, mutating);
    let messages = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (output, messages)
}

fn create_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    (listener, origin)
}

fn accept(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "MCP never called the API");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}"),
        }
    }
}

fn server(
    listener: TcpListener,
    status: &str,
    headers: &str,
    body: String,
) -> thread::JoinHandle<String> {
    let status = status.to_string();
    let headers = headers.to_string();
    thread::spawn(move || {
        let mut stream = accept(listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let text = String::from_utf8(request.clone()).unwrap();
        let length = text
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or_default();
        let mut request_body = vec![0; length];
        stream.read_exact(&mut request_body).unwrap();
        request.extend(request_body);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        String::from_utf8(request).unwrap()
    })
}

#[test]
fn stdio_handshake_lists_descriptive_tool_and_returns_real_redacted_json() {
    let (listener, origin) = create_listener();
    let mut recipe = recipe(format!("{origin}/users/{{{{user_id}}}}"));
    recipe.auth_style = AuthStyle::Bearer {
        token_slot: "bearer_token".into(),
        header_name: "Authorization".into(),
    };
    recipe.slots.push(slot("bearer_token", SlotLocation::Auth));
    recipe.slots.push(slot("search", SlotLocation::Query));
    recipe.query_template.push(KeyValueField {
        key: "q".into(),
        value: "{{search}}".into(),
        required: true,
        description: "Search".into(),
        confidence: Confidence::High,
    });
    let package = package(&recipe);
    let handle = server(
        listener,
        "200 OK",
        "Content-Type: application/json\r\n",
        json!({"name":"Ada", "echo":SECRET,
        "nested":{"token":"other-sensitive-value"},"items":[1,2]})
        .to_string(),
    );
    let mut messages = handshake();
    messages.push(json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}));
    messages.push(json!({"jsonrpc":"2.0","method":"notifications/unknown"}));
    messages.push(json!({"jsonrpc":"2.0","id":"ping","method":"ping"}));
    messages.push(call(3, json!({"user_id":"ada", "search":"a&admin=true"})));
    let (output, responses) = run(
        &package,
        messages,
        &[("FIRSTCALL_BEARER_TOKEN", SECRET)],
        false,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(responses.len(), 4, "Notifications must produce no output");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(responses[1]["result"]["tools"][0]["name"], "find_user");
    assert_eq!(
        responses[1]["result"]["tools"][0]["annotations"]["readOnlyHint"],
        true
    );
    assert!(
        responses[1]["result"]["tools"][0]["inputSchema"]["properties"]
            .get("bearer_token")
            .is_none()
    );
    let result = &responses[3]["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["data"]["name"], "Ada");
    assert_eq!(result["structuredContent"]["data"]["echo"], "<redacted>");
    assert_eq!(
        result["structuredContent"]["data"]["nested"]["token"],
        "<redacted>"
    );
    assert_eq!(result["structuredContent"]["truncated"], false);
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_text.contains(SECRET));
    assert!(!output_text.contains("other-sensitive-value"));
    let request = handle.join().unwrap();
    assert!(
        request.starts_with("GET /users/ada?q=a%26admin%3Dtrue HTTP/1.1"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {SECRET}"))
    );
}

#[test]
fn invalid_arguments_cannot_override_url_auth_or_declared_path() {
    let (listener, origin) = create_listener();
    let package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
    let mut messages = handshake();
    for (index, arguments) in [
        json!({"user_id":"ada","url":"https://elsewhere.invalid"}),
        json!({"user_id":"ada","authorization":"Bearer override"}),
        json!({"user_id":"../admin"}),
        json!({"user_id":"%2e%2e"}),
        json!({"user_id":"https://elsewhere.invalid"}),
        json!({"user_id":12}),
        json!({}),
    ]
    .into_iter()
    .enumerate()
    {
        messages.push(call(index as u64 + 2, arguments));
    }
    let (output, responses) = run(&package, messages, &[], false);
    assert!(output.status.success());
    for response in &responses[1..] {
        assert_eq!(response["result"]["isError"], true, "{response}");
    }
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn env_credentials_are_required_and_never_accepted_as_arguments() {
    let (listener, origin) = create_listener();
    let mut recipe = recipe(format!("{origin}/users/{{{{user_id}}}}"));
    recipe.auth_style = AuthStyle::Bearer {
        token_slot: "bearer_token".into(),
        header_name: "Authorization".into(),
    };
    recipe.slots.push(slot("bearer_token", SlotLocation::Auth));
    let package = package(&recipe);
    let mut messages = handshake();
    messages.push(call(2, json!({"user_id":"ada"})));
    messages.push(call(3, json!({"user_id":"ada","bearer_token":SECRET})));
    let (output, responses) = run(&package, messages, &[], false);
    assert!(output.status.success());
    assert_eq!(responses[1]["result"]["isError"], true);
    assert_eq!(responses[2]["result"]["isError"], true);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_err());
}

#[test]
fn mutating_requests_require_explicit_flag_and_json_slots_cannot_inject_fields() {
    let (listener, origin) = create_listener();
    let mut recipe = recipe(format!("{origin}/users/{{{{user_id}}}}"));
    recipe.method = "POST".into();
    recipe.slots.push(slot("display_name", SlotLocation::Body));
    recipe.body_template = BodyTemplate::Json {
        template: r#"{"display_name":"{{display_name}}"}"#.into(),
    };
    let package = package(&recipe);
    let (denied, responses) = run(&package, handshake(), &[], false);
    assert!(!denied.status.success());
    assert!(responses.is_empty());
    let handle = server(
        listener,
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"updated":true}"#.into(),
    );
    let mut messages = handshake();
    let payload = "Ada\",\"admin\":true,\"extra\":\"";
    messages.push(call(2, json!({"user_id":"ada","display_name":payload})));
    let (output, responses) = run(&package, messages, &[], true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(responses[1]["result"]["isError"], false, "{}", responses[1]);
    let request = handle.join().unwrap();
    let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"display_name":payload}));
}

#[test]
fn oversized_and_invalid_json_responses_are_explicit_errors() {
    for (body, expected) in [
        (
            format!("\"{}\"", "x".repeat(firstcall::mcp::MAX_RESPONSE_BYTES)),
            "Response too large",
        ),
        ("{\"unfinished\":".into(), "invalid JSON"),
    ] {
        let (listener, origin) = create_listener();
        let package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
        let handle = server(
            listener,
            "200 OK",
            "Content-Type: application/json\r\n",
            body,
        );
        let mut messages = handshake();
        messages.push(call(2, json!({"user_id":"ada"})));
        let (output, responses) = run(&package, messages, &[], false);
        assert!(output.status.success());
        assert_eq!(responses[1]["result"]["isError"], true);
        assert!(
            responses[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(expected)
        );
        assert!(
            responses[1]["result"]["structuredContent"]
                .get("data")
                .is_none()
        );
        handle.join().unwrap();
    }
}

#[test]
fn redirects_do_not_escape_the_declared_endpoint() {
    let (listener, origin) = create_listener();
    let (destination, target) = create_listener();
    let package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
    let handle = server(
        listener,
        "302 Found",
        &format!("Location: {target}/secret\r\n"),
        String::new(),
    );
    let mut messages = handshake();
    messages.push(call(2, json!({"user_id":"ada"})));
    let (_, responses) = run(&package, messages, &[], false);
    assert_eq!(responses[1]["result"]["isError"], true);
    assert!(responses[1].to_string().contains("Redirect blocked"));
    handle.join().unwrap();
    destination.set_nonblocking(true).unwrap();
    assert!(destination.accept().is_err());
}

#[test]
fn stdio_rejects_bad_frames_honors_lifecycle_and_negotiates_versions() {
    let package = package(&recipe("http://127.0.0.1:1/users/{{user_id}}".into()));
    let mut init = handshake();
    init[0]["params"]["protocolVersion"] = json!("2099-01-01");
    let mut messages = vec![json!({"jsonrpc":"2.0","id":0,"method":"tools/list"})];
    messages.extend(init);
    messages.push(json!({"jsonrpc":"2.0","id":3,"method":"not-a-method"}));
    let (_, responses) = run(&package, messages, &[], false);
    assert_eq!(responses[0]["error"]["code"], -32002);
    assert_eq!(responses[1]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(responses[2]["error"]["code"], -32601);
    let output = run_raw(&package, b"not JSON\n[]\n", &[], false);
    let lines: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[1]["error"]["code"], -32600);
    let output = run_raw(
        &package,
        &vec![b'x'; firstcall::mcp::MAX_INPUT_BYTES + 1],
        &[],
        false,
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("65536 byte limit"));
    assert!(output.stdout.len() < 1024);
}

#[test]
fn bad_packages_and_schema_capability_expansion_fail_before_handshake() {
    let package = package(&recipe("http://127.0.0.1:1/users/{{user_id}}".into()));
    let tool_path = package.path().join("tool.json");
    let mut tool: Value = serde_json::from_slice(&fs::read(&tool_path).unwrap()).unwrap();
    tool["input_schema"]["properties"]["host"] = json!({"type":"string"});
    fs::write(&tool_path, tool.to_string()).unwrap();
    let (output, responses) = run(&package, handshake(), &[], false);
    assert!(!output.status.success());
    assert!(responses.is_empty());
    fs::remove_file(tool_path).unwrap();
    fs::write(package.path().join("recipe.yaml"), "not: a valid recipe").unwrap();
    let (output, responses) = run(&package, handshake(), &[], false);
    assert!(!output.status.success());
    assert!(responses.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid tool package"));
}

#[test]
fn native_export_client_config_runs_an_actual_tool_without_node_or_build() {
    native_export_round_trip("GET");
}

#[test]
fn options_export_requires_opt_in_and_generated_configuration_runs_successfully() {
    native_export_round_trip("OPTIONS");
}

fn native_export_round_trip(method: &str) {
    use firstcall::export::native_package::{
        NativeExportOptions, default_tool_definition, export_native_mcp_package,
        export_native_mcp_package_with_options,
    };
    let (listener, origin) = create_listener();
    let mut recipe = recipe(format!("{origin}/users/{{{{user_id}}}}"));
    recipe.method = method.into();
    let mut definition = default_tool_definition(&recipe);
    definition.name = "find_user".into();
    definition.description =
        "Look up a user's profile by numeric ID and return their display name.".into();
    definition.input_schema["properties"]["user_id"]["type"] = json!("integer");
    let root = tempfile::tempdir().unwrap();
    let package_path = root.path().join("native-tool");
    let cli_path = std::path::Path::new(env!("CARGO_BIN_EXE_firstcall-cli"));
    if method == "OPTIONS" {
        assert!(export_native_mcp_package(&recipe, &package_path, &definition, cli_path).is_err());
        assert!(!package_path.exists());
    }
    let exported = export_native_mcp_package_with_options(
        &recipe,
        &package_path,
        &definition,
        cli_path,
        NativeExportOptions {
            allow_mutating: method == "OPTIONS",
        },
    )
    .unwrap();
    assert!(!exported.directory.join("mcp-server").exists());
    let config: Value = serde_json::from_str(&exported.client_config).unwrap();
    let config = &config["mcpServers"]["find_user"];
    assert_eq!(
        config["args"].as_array().unwrap().len(),
        if method == "OPTIONS" { 4 } else { 3 }
    );
    if method == "OPTIONS" {
        assert_eq!(config["args"][3], "--allow-mutating");
    }
    let handle = server(
        listener,
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"id":42,"name":"Ada"}"#.into(),
    );
    let mut process = Command::new(config["command"].as_str().unwrap());
    process
        .env_clear()
        .args(
            config["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process.spawn().unwrap();
    let mut messages = handshake();
    messages.push(call(2, json!({"user_id":42})));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            messages
                .iter()
                .map(|message| format!("{message}\n"))
                .collect::<String>()
                .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        responses[1]["result"]["structuredContent"]["data"],
        json!({"id":42,"name":"Ada"})
    );
    assert!(
        handle
            .join()
            .unwrap()
            .starts_with(&format!("{method} /users/42 HTTP/1.1"))
    );
}

#[test]
fn full_json_beyond_gui_preview_limit_is_returned_and_streams_stay_bounded() {
    let (listener, origin) = create_listener();
    let large_package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
    let data = json!({"document":"a".repeat(140_000), "last_field":"still-present"});
    let handle = server(
        listener,
        "200 OK",
        "Content-Type: application/json\r\n",
        data.to_string(),
    );
    let mut messages = handshake();
    messages.push(call(2, json!({"user_id":"ada"})));
    let (_, responses) = run(&large_package, messages, &[], false);
    assert_eq!(responses[1]["result"]["structuredContent"]["data"], data);
    handle.join().unwrap();

    let (listener, origin) = create_listener();
    let other_package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
    let handle = thread::spawn(move || {
        let mut stream = accept(listener);
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        // No Content-Length: the reader must stop after limit + 1 bytes itself.
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\"",
        );
        let _ = stream.write_all(&vec![b'x'; firstcall::mcp::MAX_RESPONSE_BYTES + 100]);
    });
    let mut messages = handshake();
    messages.push(call(2, json!({"user_id":"ada"})));
    let (_, responses) = run(&other_package, messages, &[], false);
    assert_eq!(responses[1]["result"]["isError"], true);
    assert!(responses[1].to_string().contains("Response too large"));
    handle.join().unwrap();
}

#[test]
fn bad_verification_fingerprint_and_routing_auth_header_are_rejected() {
    use sha2::{Digest, Sha256};
    let lock_package = package(&recipe("http://127.0.0.1:1/users/{{user_id}}".into()));
    let lock_path = lock_package.path().join("verified.lock.json");
    let mut lock: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["request_fingerprint"] = json!("0".repeat(64));
    fs::write(&lock_path, lock.to_string()).unwrap();
    // Even if someone updates the file checksum, the recipe must match its verification.
    let manifest_path = lock_package.path().join("package.manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let digest = Sha256::digest(fs::read(lock_path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for file in manifest["files"].as_array_mut().unwrap() {
        if file["path"] == "verified.lock.json" {
            file["sha256"] = json!(digest);
        }
    }
    fs::write(manifest_path, manifest.to_string()).unwrap();
    let (output, responses) = run(&lock_package, handshake(), &[], false);
    assert!(!output.status.success());
    assert!(responses.is_empty());

    let mut bad_recipe = recipe("http://127.0.0.1:1/users/{{user_id}}".into());
    bad_recipe.auth_style = AuthStyle::HeaderApiKey {
        header_name: "Host".into(),
        slot_name: "api_key".into(),
    };
    let bad_package = package(&bad_recipe);
    let (output, responses) = run(
        &bad_package,
        handshake(),
        &[("FIRSTCALL_API_KEY", "elsewhere.invalid")],
        false,
    );
    assert!(!output.status.success());
    assert!(responses.is_empty());
}

#[test]
fn current_protocol_is_stateless_and_validates_metadata_on_every_request() {
    let (listener, origin) = create_listener();
    let package = package(&recipe(format!("{origin}/users/{{{{user_id}}}}")));
    let handle = server(
        listener,
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"name":"Ada"}"#.into(),
    );
    let metadata = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28", "io.modelcontextprotocol/clientCapabilities":{}});
    let mut actual_call = call(5, json!({"user_id":"ada"}));
    actual_call["params"]["_meta"] = metadata.clone();
    let messages = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":metadata}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":metadata}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}),
        actual_call,
    ];
    let (output, responses) = run(&package, messages, &[], false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        responses[0]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    assert_eq!(responses[0]["result"]["resultType"], "complete");
    assert_eq!(responses[1]["result"]["tools"][0]["name"], "find_user");
    assert_eq!(responses[1]["result"]["cacheScope"], "private");
    assert_eq!(
        responses[2]["error"]["code"], -32602,
        "Capabilities must not be inherited from the prior request"
    );
    assert_eq!(responses[3]["error"]["code"], -32022);
    assert_eq!(responses[4]["result"]["resultType"], "complete");
    assert_eq!(
        responses[4]["result"]["structuredContent"]["data"]["name"],
        "Ada"
    );
    assert_eq!(
        responses[4]["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "firstcall"
    );
    handle.join().unwrap();
}
