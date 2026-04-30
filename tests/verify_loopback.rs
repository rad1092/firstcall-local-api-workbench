use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use firstcall::model::{AuthStyle, BodyTemplate, Confidence, Recipe, RuntimeSlot, SlotLocation};
use firstcall::verify::{VerifyOptions, verify_recipe_with_env};
use serde_json::Value;
use tempfile::tempdir;

const RAW_SECRET: &str = "sk_loopback_raw_secret_123";
const RAW_BASIC_PASSWORD: &str = "loopback_basic_password_secret";

struct LoopbackServer {
    base_url: String,
    handle: JoinHandle<CapturedRequest>,
}

struct CapturedRequest {
    request_text: Option<String>,
    requests_received: usize,
}

impl LoopbackServer {
    fn join(self) -> CapturedRequest {
        self.handle.join().expect("loopback server thread")
    }
}

fn spawn_one_shot_http_server(status: u16, body: &'static str) -> LoopbackServer {
    spawn_loopback_server(status, body, Duration::from_secs(5))
}

fn spawn_no_request_http_server() -> LoopbackServer {
    spawn_loopback_server(200, r#"{"ok":true}"#, Duration::from_millis(500))
}

fn spawn_loopback_server(
    status: u16,
    body: &'static str,
    accept_timeout: Duration,
) -> LoopbackServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + accept_timeout;
        loop {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    stream.set_nonblocking(false).expect("set blocking stream");
                    let request_text = read_request_headers(&mut stream).expect("read request");
                    write_response(&mut stream, status, body).expect("write response");
                    return CapturedRequest {
                        request_text: Some(request_text),
                        requests_received: 1,
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return CapturedRequest {
                            request_text: None,
                            requests_received: 0,
                        };
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept loopback request: {error}"),
            }
        }
    });

    LoopbackServer { base_url, handle }
}

fn read_request_headers(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") || bytes.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn write_response(
    stream: &mut std::net::TcpStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

#[test]
fn verify_recipe_with_env_succeeds_against_local_get_server() {
    let server = spawn_one_shot_http_server(200, r#"{"ok":true}"#);
    let recipe = no_auth_recipe("GET", &server.base_url);

    let report =
        verify_recipe_with_env(&recipe, VerifyOptions::default(), |_| None).expect("verify recipe");
    let captured = server.join();

    assert_eq!(captured.requests_received, 1);
    assert!(captured.request_text.is_some());
    assert!(report.success());
    assert_eq!(report.status, Some(200));
    assert!(report.verified_at.is_some());
    assert!(report.updated_recipe.last_success_at.is_some());
    assert_eq!(report.updated_recipe.last_success_status, Some(200));
    assert_no_raw_secret(&serde_json::to_string(&report.updated_recipe).expect("recipe json"));
}

#[test]
fn cli_verify_writes_updated_recipe_and_lock_on_local_success() {
    let server = spawn_one_shot_http_server(200, r#"{"ok":true}"#);
    let recipe = no_auth_recipe("GET", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .output()
        .expect("run cli");
    let captured = server.join();
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 1);
    assert!(captured.request_text.is_some());
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("HTTP status: 200"));
    assert!(combined.contains("Outcome: success"));
    assert!(out_path.exists());
    assert!(lock_path.exists());

    let updated: Recipe = read_json(&out_path);
    assert_eq!(updated.last_success_status, Some(200));
    assert!(updated.last_success_at.is_some());

    let lock: Value = read_json(&lock_path);
    assert_eq!(lock["verified"], true);
    assert_eq!(lock["last_success_status"], 200);
    assert!(is_sha256_hex(lock["request_fingerprint"].as_str().unwrap()));

    assert_no_raw_secret(&combined);
    assert_no_raw_secret(&fs::read_to_string(&out_path).expect("read recipe"));
    assert_no_raw_secret(&fs::read_to_string(&lock_path).expect("read lock"));
}

#[test]
fn bearer_auth_is_sent_but_not_written_to_outputs() {
    let server = spawn_one_shot_http_server(200, r#"{"ok":true}"#);
    let recipe = bearer_recipe("GET", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .env("FIRSTCALL_BEARER_TOKEN", RAW_SECRET)
        .output()
        .expect("run cli");
    let captured = server.join();
    let request = captured.request_text.expect("captured request");
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 1);
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer ")
    );
    assert!(request.contains(RAW_SECRET));
    assert!(output.status.success(), "{combined}");
    assert_no_raw_secret(&combined);
    assert_no_raw_secret(&fs::read_to_string(&out_path).expect("read recipe"));
    assert_no_raw_secret(&fs::read_to_string(&lock_path).expect("read lock"));
}

#[test]
fn cli_verify_non_2xx_local_response_does_not_mark_verified() {
    let server = spawn_one_shot_http_server(401, r#"{"error":"unauthorized"}"#);
    let recipe = no_auth_recipe("GET", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .output()
        .expect("run cli");
    let captured = server.join();
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 1);
    assert!(captured.request_text.is_some());
    assert!(!output.status.success());
    assert!(combined.contains("HTTP status: 401"));
    assert!(!out_path.exists());
    assert!(!lock_path.exists());

    let original: Recipe = read_json(&recipe_path);
    assert!(original.last_success_at.is_none());
    assert!(original.last_success_status.is_none());
    assert_no_raw_secret(&combined);
}

#[test]
fn cli_verify_mutating_method_requires_allow_before_network() {
    let server = spawn_no_request_http_server();
    let recipe = no_auth_recipe("POST", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .output()
        .expect("run cli");
    let captured = server.join();
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 0);
    assert!(captured.request_text.is_none());
    assert!(!output.status.success());
    assert!(combined.contains("--allow-mutating"));
    assert!(!out_path.exists());
    assert!(!lock_path.exists());
    assert_no_raw_secret(&combined);
}

#[test]
fn cli_verify_mutating_method_with_allow_writes_recipe_and_lock() {
    let server = spawn_one_shot_http_server(200, r#"{"ok":true}"#);
    let recipe = no_auth_recipe("POST", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    let out_path = dir.path().join("recipe.verified.json");
    let lock_path = dir.path().join("verified.lock.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--allow-mutating", "--out"])
        .arg(&out_path)
        .args(["--lock-out"])
        .arg(&lock_path)
        .output()
        .expect("run cli");
    let captured = server.join();
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 1);
    assert!(captured.request_text.is_some());
    assert!(output.status.success(), "{combined}");
    assert!(out_path.exists());
    assert!(lock_path.exists());
    assert_no_raw_secret(&combined);
    assert_no_raw_secret(&fs::read_to_string(&out_path).expect("read recipe"));
    assert_no_raw_secret(&fs::read_to_string(&lock_path).expect("read lock"));
}

#[test]
fn verify_dry_run_against_loopback_does_not_execute_network() {
    let server = spawn_no_request_http_server();
    let recipe = no_auth_recipe("GET", &server.base_url);
    let dir = tempdir().expect("tempdir");
    let recipe_path = dir.path().join("recipe.json");
    write_recipe(&recipe_path, &recipe);

    let output = verify_command()
        .args(["verify", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--dry-run"])
        .output()
        .expect("run cli");
    let captured = server.join();
    let combined = combined_output(&output);

    assert_eq!(captured.requests_received, 0);
    assert!(captured.request_text.is_none());
    assert!(output.status.success(), "{combined}");
    assert!(combined.contains("Would execute HTTP: no"));
    assert_no_raw_secret(&combined);
}

fn no_auth_recipe(method: &str, base_url: &str) -> Recipe {
    Recipe {
        id: None,
        name: "Loopback Verify".to_string(),
        method: method.to_string(),
        url_template: format!("{base_url}/users/{{{{user_id}}}}"),
        headers_template: Vec::new(),
        query_template: Vec::new(),
        body_template: BodyTemplate::None,
        auth_style: AuthStyle::None,
        slots: vec![RuntimeSlot {
            name: "user_id".to_string(),
            location: SlotLocation::Path,
            required: true,
            current_value: Some("user_123".to_string()),
            description: String::new(),
            confidence: Confidence::High,
        }],
        last_success_at: None,
        last_success_status: None,
    }
}

fn bearer_recipe(method: &str, base_url: &str) -> Recipe {
    Recipe {
        auth_style: AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        },
        ..no_auth_recipe(method, base_url)
    }
}

fn write_recipe(path: &std::path::Path, recipe: &Recipe) {
    fs::write(
        path,
        serde_json::to_string_pretty(recipe).expect("recipe json"),
    )
    .expect("write recipe");
}

fn verify_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn assert_no_raw_secret(text: &str) {
    assert!(!text.contains(RAW_SECRET));
    assert!(!text.contains(RAW_BASIC_PASSWORD));
}
