#![cfg(feature = "desktop")]

use firstcall::app::{BootstrapOptions, FirstCallApp, InputTab, TopScreen};
use firstcall::export::package_inspect::inspect_agent_package_dir;
use firstcall::model::Recipe;
use firstcall::store::db::AppPaths;
use std::fs;
use tempfile::tempdir;

#[test]
fn verified_request_becomes_a_described_export_and_connection_state() {
    let root = tempdir().unwrap();
    let paths =
        AppPaths::from_root(&root.path().join("data"), &root.path().join("config")).unwrap();
    let mut app = FirstCallApp::bootstrap_with_options(BootstrapOptions {
        paths: Some(paths),
        ..Default::default()
    });
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json")).unwrap();
    let id = app.repository.insert_recipe(&recipe).unwrap();
    app.prepare_native_tool(id);
    assert_eq!(app.screen, TopScreen::Recipes);
    let editor = app.tool_editor.as_mut().unwrap();
    assert!(
        editor.definition.input_schema["properties"]
            .get("bearer_token")
            .is_none()
    );
    editor.allow_mutating = true;
    editor.definition.name = "update_contact".into();
    editor.definition.description =
        "Update a customer's email address by ID and return the resulting contact record.".into();
    editor.definition.input_schema["properties"]["email"]["description"] =
        "The customer's replacement email address".into();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let package = root.path().join("contact-tool");
    let exported = app.export_native_tool_to(&package, &cli).unwrap();
    assert!(app.tool_editor.is_none());
    assert_eq!(
        app.last_native_export.as_ref().unwrap().directory,
        exported.directory
    );
    assert!(inspect_agent_package_dir(&package).is_ready());
    assert!(exported.client_config.contains("serve"));
    assert_eq!(app.repository.list_recipes().unwrap().len(), 1);
}

#[test]
fn failed_export_keeps_the_edited_tool_for_retry() {
    let root = tempdir().unwrap();
    let paths =
        AppPaths::from_root(&root.path().join("data"), &root.path().join("config")).unwrap();
    let mut app = FirstCallApp::bootstrap_with_options(BootstrapOptions {
        paths: Some(paths),
        ..Default::default()
    });
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json")).unwrap();
    let id = app.repository.insert_recipe(&recipe).unwrap();
    app.prepare_native_tool(id);
    app.tool_editor.as_mut().unwrap().definition.description =
        "Look up the customer's contact details by their customer identifier.".into();
    let destination = root.path().join("tool");
    assert!(
        app.export_native_tool_to(&destination, &root.path().join("missing-cli"))
            .is_err()
    );
    assert!(app.tool_editor.is_some());
    assert!(app.last_native_export.is_none());
    assert!(!destination.exists());
}

#[test]
fn both_first_run_examples_are_real_read_requests_with_usable_sample_inputs() {
    for sample_tab in [InputTab::Curl, InputTab::OpenApi] {
        let root = tempdir().unwrap();
        let paths =
            AppPaths::from_root(&root.path().join("data"), &root.path().join("config")).unwrap();
        let app = FirstCallApp::bootstrap_with_options(BootstrapOptions {
            paths: Some(paths),
            sample_tab: Some(sample_tab),
            ..Default::default()
        });
        let draft = app
            .working_draft
            .as_ref()
            .expect("example operation parsed");
        assert_eq!(draft.method, "GET");
        assert_eq!(draft.base_url.as_deref(), Some("https://api.github.com"));
        assert_eq!(draft.auth.label(), "none");
        assert_eq!(
            draft
                .slots
                .iter()
                .find(|s| s.name == "owner")
                .unwrap()
                .current_value
                .as_deref(),
            Some("octocat")
        );
        assert_eq!(
            draft
                .slots
                .iter()
                .find(|s| s.name == "repository")
                .unwrap()
                .current_value
                .as_deref(),
            Some("Hello-World")
        );
        assert!(
            draft
                .headers
                .iter()
                .any(|header| header.key.eq_ignore_ascii_case("User-Agent")
                    && header.value == "FirstCall")
        );
        assert!(
            app.last_execution.is_none(),
            "loading an example never pretends it has been verified"
        );
    }
}

#[test]
fn write_requests_require_explicit_export_permission() {
    let root = tempdir().unwrap();
    let paths =
        AppPaths::from_root(&root.path().join("data"), &root.path().join("config")).unwrap();
    let mut app = FirstCallApp::bootstrap_with_options(BootstrapOptions {
        paths: Some(paths),
        ..Default::default()
    });
    let recipe: Recipe =
        serde_json::from_str(include_str!("../fixtures/verified-agent-recipe.json")).unwrap();
    let id = app.repository.insert_recipe(&recipe).unwrap();
    app.prepare_native_tool(id);
    app.tool_editor.as_mut().unwrap().definition.description =
        "Update a customer's email address and return the resulting contact record.".into();
    let cli = root.path().join("firstcall-cli");
    fs::write(&cli, "test executable path").unwrap();
    let destination = root.path().join("tool");
    assert!(
        app.export_native_tool_to(&destination, &cli)
            .unwrap_err()
            .to_string()
            .contains("Explicitly allow")
    );
    assert!(!destination.exists());
    app.tool_editor.as_mut().unwrap().allow_mutating = true;
    let exported = app.export_native_tool_to(&destination, &cli).unwrap();
    assert!(exported.client_config.contains("--allow-mutating"));
}
