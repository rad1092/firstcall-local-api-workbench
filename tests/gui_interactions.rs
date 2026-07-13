#![cfg(feature = "desktop")]

use egui::accesskit::Role;
use egui_kittest::{
    Harness,
    kittest::{NodeT as _, Queryable as _},
};
use tempfile::{TempDir, tempdir};

use firstcall::app::{BootstrapOptions, FirstCallApp, TopScreen};
use firstcall::store::db::AppPaths;

fn app_paths(root: &TempDir) -> AppPaths {
    AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
        .expect("temporary app paths")
}

fn harness_for(paths: AppPaths) -> Harness<'static, FirstCallApp> {
    Harness::<FirstCallApp>::builder()
        .with_size(egui::vec2(1_600.0, 1_000.0))
        .build_eframe(move |_cc| {
            FirstCallApp::bootstrap_with_options(BootstrapOptions {
                paths: Some(paths),
                ..BootstrapOptions::default()
            })
        })
}

#[test]
fn settings_navigation_renders_and_persists_response_body_hard_limit() {
    let root = tempdir().expect("tempdir");
    let mut harness = harness_for(app_paths(&root));

    harness
        .get_by_role_and_label(Role::Button, "Settings")
        .click();
    harness.run();

    assert_eq!(harness.state().screen, TopScreen::Settings);
    assert!(
        harness
            .query_by_label("Response body hard limit (bytes)")
            .is_some(),
        "the hard-limit setting should be present in the rendered accessibility tree"
    );

    harness.state_mut().settings.response_body_limit_bytes = 2_097_152;
    harness.state_mut().settings.response_preview_limit_bytes = 262_144;
    harness.step();

    let hard_limit = harness.get_by(|node| {
        node.role() == Role::SpinButton && node.numeric_value() == Some(2_097_152.0)
    });
    assert!(!hard_limit.accesskit_node().is_disabled());

    harness
        .get_by_role_and_label(Role::Button, "Save Settings")
        .click();
    harness.run();

    let stored = harness
        .state()
        .repository
        .load_settings()
        .expect("stored settings");
    assert_eq!(stored.response_body_limit_bytes, 2_097_152);
    assert_eq!(stored.response_preview_limit_bytes, 262_144);
    assert_eq!(
        harness.state().status_message.as_deref(),
        Some("Settings saved")
    );
    assert!(harness.query_by_label("Settings saved").is_some());
}

#[test]
fn sample_analysis_click_flow_disables_run_until_required_slots_are_present() {
    let root = tempdir().expect("tempdir");
    let mut harness = harness_for(app_paths(&root));

    harness
        .get_by_role_and_label(Role::Button, "Load Sample")
        .click();
    harness.run();

    assert!(harness.state().inputs.curl.contains("{{customer_id}}"));
    assert!(harness.state().candidate_drafts.is_empty());

    harness
        .get_by_role_and_label(Role::Button, "Analyze Sources")
        .click();
    harness.run();

    assert_eq!(harness.state().candidate_drafts.len(), 1);
    assert!(harness.state().working_draft.is_some());
    assert!(
        harness
            .query_by_label("Missing required slots: 2")
            .is_some()
    );

    let run_button = harness.get_by_role_and_label(Role::Button, "Run Request");
    assert!(
        run_button.accesskit_node().is_disabled(),
        "Run Request must be semantically disabled while required slots are missing"
    );
    run_button.click();
    harness.run();

    assert!(harness.state().last_execution.is_none());
    assert!(harness.state().attempts.is_empty());
    assert_eq!(
        harness.state().status_message.as_deref(),
        Some("Detected 1 candidate request(s)")
    );
}
