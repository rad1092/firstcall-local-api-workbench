use firstcall::export::native_package::{
    NativeExportOptions, default_tool_definition, export_native_mcp_package_with_options,
    validate_tool_definition,
};
use firstcall::export::package_inspect::inspect_agent_package_dir;
use firstcall::model::Recipe;
use serde_json::{Value, json};
use std::fs;
use tempfile::tempdir;

fn recipe() -> Recipe {
    serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json")).expect("fixture")
}

fn tool(recipe: &Recipe) -> firstcall::export::native_package::NativeToolDefinition {
    let mut tool = default_tool_definition(recipe);
    tool.name = "update_customer_email".into();
    tool.title = "Update customer email".into();
    tool.description =
        "Update a customer's email address by user ID and return the updated customer record."
            .into();
    tool
}

#[test]
fn native_export_is_validated_descriptive_and_ready_without_node() {
    let root = tempdir().unwrap();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let mut recipe = recipe();
    recipe
        .slots
        .iter_mut()
        .find(|s| s.name == "bearer_token")
        .unwrap()
        .current_value = Some("a-credential-never-exported-91231".into());
    let output = root.path().join("customer-tool");
    let result = export_native_mcp_package_with_options(
        &recipe,
        &output,
        &tool(&recipe),
        &cli,
        NativeExportOptions {
            allow_mutating: true,
        },
    )
    .unwrap();
    let inspect = inspect_agent_package_dir(&output);
    assert!(
        inspect.is_ready(),
        "{:?} {:?}",
        inspect.validation.errors,
        inspect.blockers
    );
    assert!(!output.join("mcp-server").exists());
    assert_eq!(inspect.request_fingerprint_status.as_str(), "matched");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(output.join("package.manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["runtime"], "firstcall-native");
    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(output.join("tool.json")).unwrap()).unwrap();
    assert_eq!(metadata["description"], tool(&recipe).description);
    assert_eq!(
        metadata["input_schema"]["properties"]["email"]["description"],
        "Updated email address"
    );
    assert!(
        metadata["input_schema"]["properties"]
            .get("bearer_token")
            .is_none()
    );
    let config: Value = serde_json::from_str(&result.client_config).unwrap();
    let server = &config["mcpServers"]["update_customer_email"];
    assert_eq!(
        server["command"],
        fs::canonicalize(cli).unwrap().to_str().unwrap()
    );
    assert_eq!(server["args"][0], "serve");
    assert_eq!(server["args"][2], result.directory.to_str().unwrap());
    assert_eq!(server["env"]["FIRSTCALL_BEARER_TOKEN"], "");
    for file in fs::read_dir(output).unwrap() {
        let text = fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(!text.contains("a-credential-never-exported-91231"));
    }
}

#[test]
fn edited_tool_contract_fails_integrity_validation() {
    let root = tempdir().unwrap();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let recipe = recipe();
    let output = root.path().join("tool");
    export_native_mcp_package_with_options(
        &recipe,
        &output,
        &tool(&recipe),
        &cli,
        NativeExportOptions {
            allow_mutating: true,
        },
    )
    .unwrap();
    let mut metadata = tool(&recipe);
    metadata.description =
        "A different unreviewed tool description replacing the original verified package.".into();
    fs::write(
        output.join("tool.json"),
        serde_json::to_string(&metadata).unwrap(),
    )
    .unwrap();
    let report = inspect_agent_package_dir(&output);
    assert!(!report.is_ready());
    assert!(
        report
            .validation
            .errors
            .iter()
            .any(|e| e.contains("manifest hash mismatch: tool.json"))
    );
}

#[test]
fn secrets_and_new_parameters_cannot_become_mcp_arguments() {
    let recipe = recipe();
    let mut metadata = tool(&recipe);
    metadata.input_schema["properties"]["bearer_token"] =
        json!({"type":"string", "description":"credential"});
    assert!(validate_tool_definition(&recipe, &metadata).is_err());
    let mut metadata = tool(&recipe);
    metadata.input_schema["properties"]["redirect_host"] =
        json!({"type":"string", "description":"other destination"});
    assert!(validate_tool_definition(&recipe, &metadata).is_err());
    let mut metadata = tool(&recipe);
    metadata.input_schema["properties"]["user_id"]["$ref"] = json!("https://other.example/schema");
    assert!(validate_tool_definition(&recipe, &metadata).is_err());
}

#[test]
fn purpose_and_required_inputs_are_checked_before_export() {
    let recipe = recipe();
    assert!(validate_tool_definition(&recipe, &default_tool_definition(&recipe)).is_err());
    let mut metadata = tool(&recipe);
    metadata.input_schema["required"] = json!([]);
    assert!(validate_tool_definition(&recipe, &metadata).is_err());
    metadata = tool(&recipe);
    metadata.input_schema["properties"]["user_id"]["type"] = json!("integer");
    assert!(validate_tool_definition(&recipe, &metadata).is_ok());
}

#[test]
fn export_preserves_existing_folders_and_rejects_unverified_requests() {
    let root = tempdir().unwrap();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let output = root.path().join("existing");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("notes.txt"), "user notes").unwrap();
    let mut recipe = recipe();
    assert!(
        export_native_mcp_package_with_options(
            &recipe,
            &output,
            &tool(&recipe),
            &cli,
            NativeExportOptions {
                allow_mutating: true
            }
        )
        .is_err()
    );
    assert_eq!(
        fs::read_to_string(output.join("notes.txt")).unwrap(),
        "user notes"
    );
    recipe.last_success_at = None;
    let unused = root.path().join("unverified");
    assert!(
        export_native_mcp_package_with_options(
            &recipe,
            &unused,
            &tool(&recipe),
            &cli,
            NativeExportOptions {
                allow_mutating: true
            }
        )
        .is_err()
    );
    assert!(!unused.exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".firstcall-export-")
    }));
}

#[test]
fn credential_values_in_client_config_are_rejected() {
    let root = tempdir().unwrap();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let recipe = recipe();
    let output = root.path().join("tool");
    let exported = export_native_mcp_package_with_options(
        &recipe,
        &output,
        &tool(&recipe),
        &cli,
        NativeExportOptions {
            allow_mutating: true,
        },
    )
    .unwrap();
    let mut config: Value = serde_json::from_str(&exported.client_config).unwrap();
    config["mcpServers"]["update_customer_email"]["env"]["FIRSTCALL_BEARER_TOKEN"] =
        json!("must-stay-outside-package");
    fs::write(
        output.join("client-config.json"),
        serde_json::to_string(&config).unwrap(),
    )
    .unwrap();
    let inspect = inspect_agent_package_dir(&output);
    assert!(!inspect.is_ready());
    assert!(
        inspect
            .validation
            .errors
            .iter()
            .any(|error| error.contains("empty environment placeholders"))
    );
}

#[test]
fn export_rejects_requests_the_native_runtime_cannot_execute_before_creating_files() {
    use firstcall::model::AuthStyle;

    let root = tempdir().unwrap();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let mut routing_header = recipe();
    routing_header.auth_style = AuthStyle::HeaderApiKey {
        header_name: "Host".into(),
        slot_name: "bearer_token".into(),
    };
    let mut unsupported_method = recipe();
    unsupported_method.method = "TRACE".into();
    let mut dynamic_host = recipe();
    dynamic_host.url_template = "https://{{host}}/v1/users/{{user_id}}".into();

    for (name, request, diagnostic) in [
        (
            "routing-header",
            routing_header,
            "routing or framing headers",
        ),
        (
            "unsupported-method",
            unsupported_method,
            "Unsupported HTTP method",
        ),
        (
            "dynamic-host",
            dynamic_host,
            "cannot change the endpoint host",
        ),
    ] {
        let output = root.path().join(name);
        let error = export_native_mcp_package_with_options(
            &request,
            &output,
            &tool(&request),
            &cli,
            NativeExportOptions {
                allow_mutating: true,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains(diagnostic), "{error}");
        assert!(!output.exists());
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}
