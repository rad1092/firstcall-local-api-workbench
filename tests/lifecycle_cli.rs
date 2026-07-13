use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use firstcall::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, Recipe, RuntimeSlot, SlotLocation,
};
use firstcall::store::db::{AppPaths, open_database};
use firstcall::store::repos::AppRepository;
use serde_json::Value;
use tempfile::tempdir;

const RAW_SECRET: &str = "sk_lifecycle_raw_secret_123";
const RAW_QUERY_SECRET: &str = "raw_lifecycle_query_secret_123";
const ENV_BEARER_VALUE: &str = "env_lifecycle_bearer_secret_should_not_print";
const ENV_API_VALUE: &str = "env_lifecycle_api_secret_should_not_print";
const ENV_USER_VALUE: &str = "env_lifecycle_user_should_not_print";
const ENV_MESSAGE_VALUE: &str = "env_lifecycle_message_should_not_print";
const BODY_CONTENT: &str = "lifecycle_body_contents_should_not_show_in_summaries";

#[test]
fn cli_storage_lifecycle_import_verify_and_repackage() {
    let server = spawn_one_shot_http_server(200, r#"{"ok":true}"#);
    let root = tempdir().expect("tempdir");
    let recipe_path = root.path().join("recipe.json");
    let initial_package_dir = root.path().join("initial-package");
    let repackage_before_verify_dir = root.path().join("repackage-before-verify");
    let repackage_dir = root.path().join("repackage");
    let data_dir = root.path().join("data");
    let config_dir = root.path().join("config");
    let paths = AppPaths::from_root(&data_dir, &config_dir).expect("paths");

    let recipe = lifecycle_recipe(&server.base_url);
    fs::write(
        &recipe_path,
        serde_json::to_string_pretty(&recipe).expect("recipe json"),
    )
    .expect("write recipe");

    assert!(!paths.db_path.exists());

    let output = cli()
        .args(["package", "--recipe-json"])
        .arg(&recipe_path)
        .args(["--out"])
        .arg(&initial_package_dir)
        .output()
        .expect("package recipe json");
    assert_success_without_secret_leaks(&output);
    assert_package_files(&initial_package_dir);
    assert_package_files_do_not_contain_secrets(&initial_package_dir);

    let validation = run_json_command(
        cli()
            .args(["validate-package", "--dir"])
            .arg(&initial_package_dir)
            .args(["--json"]),
    );
    assert_eq!(validation["mode"], "validate-package");
    assert_eq!(validation["status"], "valid");
    assert_no_secret_values(&validation.to_string());

    let inspection = run_json_command(
        cli()
            .args(["inspect-package", "--dir"])
            .arg(&initial_package_dir)
            .args(["--json"]),
    );
    assert_eq!(inspection["mode"], "inspect-package");
    assert_eq!(inspection["import_readiness"], "ready");
    assert_no_secret_values(&inspection.to_string());

    let import_report = run_json_command(
        cli()
            .args(["import-package", "--dir"])
            .arg(&initial_package_dir)
            .args(["--data-dir"])
            .arg(&data_dir)
            .args(["--config-dir"])
            .arg(&config_dir)
            .args(["--json"]),
    );
    assert_eq!(import_report["mode"], "import-package");
    assert_eq!(import_report["import_status"], "imported");
    assert_eq!(import_report["requires_local_re_verification"], true);
    assert_eq!(import_report["preserved_verified_status"], false);
    assert_eq!(import_report["secrets_imported"], false);
    assert!(paths.db_path.exists());
    assert_no_secret_values(&import_report.to_string());
    let recipe_id = import_report["imported_recipe_id"]
        .as_i64()
        .expect("imported recipe id");

    let stored_after_import = read_stored_recipe(&paths, recipe_id);
    assert!(stored_after_import.last_success_at.is_none());
    assert_eq!(stored_after_import.last_success_status, None);
    assert_no_secret_values(&serde_json::to_string(&stored_after_import).expect("stored json"));

    let recipe_list = run_json_command(
        cli()
            .args(["recipe-list", "--data-dir"])
            .arg(&data_dir)
            .args(["--config-dir"])
            .arg(&config_dir)
            .args(["--json"]),
    );
    assert_eq!(recipe_list["mode"], "recipe-list");
    assert_eq!(recipe_list["recipes"].as_array().expect("recipes").len(), 1);
    assert_eq!(recipe_list["recipes"][0]["id"], recipe_id);
    assert_eq!(
        recipe_list["recipes"][0]["requires_local_re_verification"],
        true
    );
    assert_safe_recipe_summary(&recipe_list.to_string());

    let recipe_show = recipe_show_json(recipe_id, &data_dir, &config_dir);
    assert_eq!(recipe_show["mode"], "recipe-show");
    assert_eq!(recipe_show["recipe"]["id"], recipe_id);
    assert_eq!(
        recipe_show["recipe"]["requires_local_re_verification"],
        true
    );
    assert_safe_recipe_summary(&recipe_show.to_string());

    let output = cli()
        .args(["package", "--recipe-id"])
        .arg(recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--out"])
        .arg(&repackage_before_verify_dir)
        .output()
        .expect("package before verify");
    let combined = combined_output(&output);
    assert!(!output.status.success(), "{combined}");
    assert!(combined.contains("not eligible for agent export"));
    assert!(!repackage_before_verify_dir.exists());
    assert_no_secret_values(&combined);

    let dry_run = run_json_command(
        cli()
            .args(["verify", "--recipe-id"])
            .arg(recipe_id.to_string())
            .args(["--data-dir"])
            .arg(&data_dir)
            .args(["--config-dir"])
            .arg(&config_dir)
            .args(["--allow-mutating", "--dry-run", "--json"])
            .env("FIRSTCALL_SLOT_USER_ID", ENV_USER_VALUE)
            .env("FIRSTCALL_SLOT_MESSAGE", ENV_MESSAGE_VALUE)
            .env("FIRSTCALL_BEARER_TOKEN", ENV_BEARER_VALUE)
            .env("FIRSTCALL_API_KEY", ENV_API_VALUE),
    );
    assert_eq!(dry_run["mode"], "dry-run");
    assert_eq!(dry_run["source"], "recipe-id");
    assert_eq!(dry_run["recipe_id"], recipe_id);
    assert_eq!(dry_run["would_execute_http"], false);
    assert_eq!(dry_run["preflight_status"], "ready");
    assert_no_secret_values(&dry_run.to_string());

    let stored_after_dry_run = read_stored_recipe(&paths, recipe_id);
    assert!(stored_after_dry_run.last_success_at.is_none());
    assert_eq!(stored_after_dry_run.last_success_status, None);

    let output = cli()
        .args(["verify", "--recipe-id"])
        .arg(recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--allow-mutating"])
        .env("FIRSTCALL_SLOT_USER_ID", ENV_USER_VALUE)
        .env("FIRSTCALL_SLOT_MESSAGE", ENV_MESSAGE_VALUE)
        .env("FIRSTCALL_BEARER_TOKEN", ENV_BEARER_VALUE)
        .env("FIRSTCALL_API_KEY", ENV_API_VALUE)
        .output()
        .expect("verify recipe id");
    let captured = server.join();
    let combined = combined_output(&output);
    assert!(output.status.success(), "{combined}");
    assert_eq!(captured.requests_received, 1);
    assert!(combined.contains("HTTP status: 200"));
    assert!(combined.contains("Outcome: success"));
    assert!(combined.contains("Updated stored recipe verification"));
    assert_no_secret_values(&combined);

    let stored_after_verify = read_stored_recipe(&paths, recipe_id);
    assert!(stored_after_verify.last_success_at.is_some());
    assert_eq!(stored_after_verify.last_success_status, Some(200));
    assert_no_secret_values(&serde_json::to_string(&stored_after_verify).expect("stored json"));

    let recipe_show = recipe_show_json(recipe_id, &data_dir, &config_dir);
    assert_eq!(
        recipe_show["recipe"]["requires_local_re_verification"],
        false
    );
    assert_eq!(recipe_show["recipe"]["last_success_status"], 200);
    assert_safe_recipe_summary(&recipe_show.to_string());

    let output = cli()
        .args(["package", "--recipe-id"])
        .arg(recipe_id.to_string())
        .args(["--data-dir"])
        .arg(&data_dir)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--out"])
        .arg(&repackage_dir)
        .output()
        .expect("package recipe id");
    assert_success_without_secret_leaks(&output);
    assert_package_files(&repackage_dir);
    assert_package_files_do_not_contain_secrets(&repackage_dir);

    let validation = run_json_command(
        cli()
            .args(["validate-package", "--dir"])
            .arg(&repackage_dir)
            .args(["--json"]),
    );
    assert_eq!(validation["status"], "valid");
    assert_no_secret_values(&validation.to_string());

    let inspection = run_json_command(
        cli()
            .args(["inspect-package", "--dir"])
            .arg(&repackage_dir)
            .args(["--json"]),
    );
    assert_eq!(inspection["import_readiness"], "ready");
    assert_no_secret_values(&inspection.to_string());
}

fn lifecycle_recipe(base_url: &str) -> Recipe {
    Recipe {
        id: None,
        name: "Lifecycle Create User".to_string(),
        method: "POST".to_string(),
        url_template: format!("{base_url}/users/{{{{user_id}}}}?api_key={RAW_QUERY_SECRET}"),
        headers_template: vec![HeaderField {
            key: "Authorization".to_string(),
            value: format!("Bearer {RAW_SECRET}"),
            required: true,
            description: String::new(),
            confidence: Confidence::High,
        }],
        query_template: Vec::new(),
        body_template: BodyTemplate::Json {
            template: format!(r#"{{"message":"{{{{message}}}}","note":"{BODY_CONTENT}"}}"#),
        },
        auth_style: AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        },
        slots: vec![
            RuntimeSlot {
                name: "user_id".to_string(),
                location: SlotLocation::Path,
                required: true,
                current_value: Some("initial_user_value".to_string()),
                description: "User identifier".to_string(),
                confidence: Confidence::High,
            },
            RuntimeSlot {
                name: "message".to_string(),
                location: SlotLocation::Body,
                required: true,
                current_value: Some("initial_message_value".to_string()),
                description: "Message body".to_string(),
                confidence: Confidence::High,
            },
            RuntimeSlot {
                name: "bearer_token".to_string(),
                location: SlotLocation::Auth,
                required: true,
                current_value: Some(RAW_SECRET.to_string()),
                description: String::new(),
                confidence: Confidence::High,
            },
        ],
        response_schema: None,
        last_success_at: Some(verified_time()),
        last_success_status: Some(200),
    }
}

struct LoopbackServer {
    base_url: String,
    handle: JoinHandle<CapturedRequest>,
}

struct CapturedRequest {
    requests_received: usize,
}

impl LoopbackServer {
    fn join(self) -> CapturedRequest {
        self.handle.join().expect("loopback server thread")
    }
}

fn spawn_one_shot_http_server(status: u16, body: &'static str) -> LoopbackServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    stream.set_nonblocking(false).expect("set blocking stream");
                    read_request_headers(&mut stream).expect("read request");
                    write_response(&mut stream, status, body).expect("write response");
                    return CapturedRequest {
                        requests_received: 1,
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return CapturedRequest {
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
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn recipe_show_json(recipe_id: i64, data_dir: &Path, config_dir: &Path) -> Value {
    run_json_command(
        cli()
            .args(["recipe-show", "--id"])
            .arg(recipe_id.to_string())
            .args(["--data-dir"])
            .arg(data_dir)
            .args(["--config-dir"])
            .arg(config_dir)
            .args(["--json"]),
    )
}

fn run_json_command(command: &mut Command) -> Value {
    let output = command.output().expect("run cli");
    assert_success_without_secret_leaks(&output);
    let report = stdout_json(&output);
    assert_no_secret_values(&report.to_string());
    report
}

fn read_stored_recipe(paths: &AppPaths, recipe_id: i64) -> Recipe {
    let repository = AppRepository::new(open_database(paths).expect("database"));
    repository
        .get_recipe(recipe_id)
        .expect("get recipe")
        .expect("stored recipe")
}

fn assert_package_files(root: &Path) {
    for relative in [
        "recipe.yaml",
        "verified.lock.json",
        "skill.md",
        "policy.json",
        "package.manifest.json",
        "mcp-server/package.json",
        "mcp-server/package-lock.json",
        "mcp-server/tsconfig.json",
        "mcp-server/src/server.ts",
        "mcp-server/README.md",
    ] {
        assert!(root.join(relative).exists(), "missing {relative}");
    }
}

fn assert_package_files_do_not_contain_secrets(root: &Path) {
    for content in read_all_files(root) {
        assert_no_secret_values(&content);
    }
}

fn assert_safe_recipe_summary(text: &str) {
    assert_no_secret_values(text);
    assert!(!text.contains("current_value"));
    assert!(!text.contains(BODY_CONTENT));
}

fn assert_success_without_secret_leaks(output: &Output) {
    let combined = combined_output(output);
    assert!(output.status.success(), "{combined}");
    assert_no_secret_values(&combined);
}

fn assert_no_secret_values(text: &str) {
    for secret in [
        RAW_SECRET,
        RAW_QUERY_SECRET,
        ENV_BEARER_VALUE,
        ENV_API_VALUE,
        ENV_USER_VALUE,
        ENV_MESSAGE_VALUE,
    ] {
        assert!(!text.contains(secret), "leaked {secret}");
    }
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout json")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_all_files(root: &Path) -> Vec<String> {
    let mut contents = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                contents.push(fs::read_to_string(path).expect("read file"));
            }
        }
    }
    contents
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firstcall-cli"))
}

fn verified_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-04-29T00:00:00Z")
        .expect("time")
        .with_timezone(&Utc)
}
