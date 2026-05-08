use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use eframe::egui;
use reqwest::blocking::Client;
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};

use crate::exec::client::{build_http_client, execute_request};
use crate::exec::redact::{
    redact_draft_for_storage, redact_free_text, redact_request, redact_response,
};
use crate::export::{curl::recipe_to_curl, json::recipe_to_json, markdown::recipe_to_markdown};
use crate::merge::merge_parsed_sources;
use crate::model::{
    AppSettings, AttemptListItem, ExecutionResult, Outcome, ParsedSource, Recipe, RecipeListItem,
    RequestAttempt, RequestDraft,
};
use crate::parse::{curl::parse_curl_input, docs::parse_docs_input, openapi::parse_openapi_input};
use crate::store::db::{AppPaths, open_database};
use crate::store::migrations::run_migrations;
use crate::store::repos::AppRepository;
use crate::store::secrets::{SecretStore, SecretStoreStatus, default_secret_store};
use crate::util::{SAMPLE_CURL, SAMPLE_DOCS, SAMPLE_OPENAPI};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopScreen {
    NewAttempt,
    Attempts,
    Recipes,
    Settings,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InputTab {
    #[default]
    Curl,
    Docs,
    OpenApi,
}

pub struct InputBuffers {
    pub curl: String,
    pub docs: String,
    pub openapi: String,
    pub active_tab: InputTab,
}

impl Default for InputBuffers {
    fn default() -> Self {
        Self {
            curl: String::new(),
            docs: String::new(),
            openapi: String::new(),
            active_tab: InputTab::Curl,
        }
    }
}

struct RunningExecution {
    receiver: Receiver<ExecutionResult>,
}

pub struct FirstCallApp {
    pub screen: TopScreen,
    pub inputs: InputBuffers,
    pub parsed_sources: Vec<ParsedSource>,
    pub candidate_drafts: Vec<RequestDraft>,
    pub selected_candidate: Option<usize>,
    pub working_draft: Option<RequestDraft>,
    pub last_execution: Option<ExecutionResult>,
    pub attempts: Vec<AttemptListItem>,
    pub recipes: Vec<RecipeListItem>,
    pub recipe_search: String,
    pub settings: AppSettings,
    pub paths: AppPaths,
    pub repository: AppRepository,
    pub secret_store: Box<dyn SecretStore>,
    pub secret_status: SecretStoreStatus,
    pub http_client: Client,
    pub status_message: Option<String>,
    pub bootstrap_warning: Option<String>,
    running_execution: Option<RunningExecution>,
}

impl FirstCallApp {
    pub fn bootstrap(_cc: &eframe::CreationContext<'_>) -> Self {
        let (paths, repository, bootstrap_warning) = bootstrap_repository();
        let settings = repository.load_settings().unwrap_or_default();
        let attempts = repository.list_attempts().unwrap_or_default();
        let recipes = repository.list_recipes().unwrap_or_default();
        let secret_store = default_secret_store();
        let secret_status = secret_store.status();
        let http_client = build_http_client(&settings).unwrap_or_else(|_| Client::new());

        Self {
            screen: TopScreen::NewAttempt,
            inputs: InputBuffers {
                active_tab: InputTab::Curl,
                ..InputBuffers::default()
            },
            parsed_sources: Vec::new(),
            candidate_drafts: Vec::new(),
            selected_candidate: None,
            working_draft: None,
            last_execution: None,
            attempts,
            recipes,
            recipe_search: String::new(),
            settings,
            paths,
            repository,
            secret_store,
            secret_status,
            http_client,
            status_message: bootstrap_warning.clone(),
            bootstrap_warning,
            running_execution: None,
        }
    }

    pub fn analyze_inputs(&mut self) {
        self.parsed_sources.clear();
        if !self.inputs.curl.trim().is_empty() {
            self.parsed_sources
                .push(parse_curl_input(&self.inputs.curl));
        }
        if !self.inputs.docs.trim().is_empty() {
            self.parsed_sources
                .push(parse_docs_input(&self.inputs.docs));
        }
        if !self.inputs.openapi.trim().is_empty() {
            self.parsed_sources
                .push(parse_openapi_input(&self.inputs.openapi));
        }
        self.candidate_drafts = merge_parsed_sources(&self.parsed_sources);
        self.selected_candidate = if self.candidate_drafts.is_empty() {
            None
        } else {
            Some(0)
        };
        self.working_draft = self
            .selected_candidate
            .and_then(|index| self.candidate_drafts.get(index).cloned());
        if let Some(draft) = &mut self.working_draft {
            hydrate_auth_slots(draft, self.secret_store.as_ref());
        }
        if self.candidate_drafts.is_empty() {
            self.status_message = Some("No operation candidates were found".to_string());
        } else {
            self.status_message = Some(format!(
                "Detected {} candidate request(s)",
                self.candidate_drafts.len()
            ));
        }
    }

    pub fn select_candidate(&mut self, index: usize) {
        if let Some(candidate) = self.candidate_drafts.get(index).cloned() {
            self.selected_candidate = Some(index);
            self.working_draft = Some(candidate);
            if let Some(draft) = &mut self.working_draft {
                hydrate_auth_slots(draft, self.secret_store.as_ref());
            }
        }
    }

    pub fn reset_inputs(&mut self) {
        self.inputs = InputBuffers {
            active_tab: InputTab::Curl,
            ..InputBuffers::default()
        };
        self.parsed_sources.clear();
        self.candidate_drafts.clear();
        self.selected_candidate = None;
        self.working_draft = None;
        self.last_execution = None;
    }

    pub fn load_sample_for_active_tab(&mut self) {
        match self.inputs.active_tab {
            InputTab::Curl => self.inputs.curl = SAMPLE_CURL.to_string(),
            InputTab::Docs => self.inputs.docs = SAMPLE_DOCS.to_string(),
            InputTab::OpenApi => self.inputs.openapi = SAMPLE_OPENAPI.to_string(),
        }
    }

    pub fn run_current_draft(&mut self) {
        if self.running_execution.is_some() {
            return;
        }
        let Some(draft) = self.working_draft.clone() else {
            self.status_message = Some("Select or build a request first".to_string());
            return;
        };
        sync_auth_slots(&draft, self.secret_store.as_mut());
        self.secret_status = self.secret_store.status();

        let settings = self.settings.clone();
        let client = self.http_client.clone();
        let (sender, receiver) = mpsc::channel();
        self.running_execution = Some(RunningExecution { receiver });
        self.status_message = Some("Running request...".to_string());
        std::thread::spawn(move || {
            let result = execute_request(&draft, &settings, &client);
            let _ = sender.send(result);
        });
    }

    pub fn poll_execution(&mut self) {
        let Some(running) = &self.running_execution else {
            return;
        };
        if let Ok(result) = running.receiver.try_recv() {
            self.last_execution = Some(result);
            self.running_execution = None;
            self.persist_latest_attempt();
            self.refresh_lists();
            if let Some(result) = &self.last_execution {
                self.status_message =
                    Some(format!("Request finished with {}", result.outcome.label()));
            }
        }
    }

    pub fn refresh_lists(&mut self) {
        self.attempts = self.repository.list_attempts().unwrap_or_default();
        self.recipes = self.repository.list_recipes().unwrap_or_default();
    }

    pub fn save_settings(&mut self) {
        if let Err(error) = self.repository.save_settings(&self.settings) {
            self.status_message = Some(format!("Could not save settings: {error}"));
            return;
        }
        match build_http_client(&self.settings) {
            Ok(client) => {
                self.http_client = client;
                self.status_message = Some("Settings saved".to_string());
            }
            Err(error) => {
                self.status_message = Some(format!(
                    "Settings saved, but client rebuild failed: {error}"
                ));
            }
        }
    }

    pub fn reopen_attempt(&mut self, id: i64) {
        if let Ok(Some(attempt)) = self.repository.get_attempt(id) {
            self.inputs.curl = attempt
                .source_inputs
                .iter()
                .find(|item| item.kind == crate::model::SourceKind::Curl)
                .map(|item| item.raw_text.clone())
                .unwrap_or_default();
            self.inputs.docs = attempt
                .source_inputs
                .iter()
                .find(|item| item.kind == crate::model::SourceKind::Docs)
                .map(|item| item.raw_text.clone())
                .unwrap_or_default();
            self.inputs.openapi = attempt
                .source_inputs
                .iter()
                .find(|item| item.kind == crate::model::SourceKind::OpenApi)
                .map(|item| item.raw_text.clone())
                .unwrap_or_default();
            self.working_draft = Some(attempt.request_draft_snapshot);
            self.last_execution = None;
            self.screen = TopScreen::NewAttempt;
        }
    }

    pub fn rerun_recipe(&mut self, id: i64) {
        if let Ok(Some(recipe)) = self.repository.get_recipe(id) {
            self.working_draft = Some(recipe_to_draft(recipe));
            if let Some(draft) = &mut self.working_draft {
                hydrate_auth_slots(draft, self.secret_store.as_ref());
            }
            self.screen = TopScreen::NewAttempt;
        }
    }

    pub fn save_current_recipe(&mut self) {
        let Some(draft) = self.working_draft.clone() else {
            self.status_message = Some("No draft selected".to_string());
            return;
        };
        let Some(result) = &self.last_execution else {
            self.status_message =
                Some("Run the request successfully before saving a recipe".to_string());
            return;
        };
        if result.outcome != Outcome::Success {
            self.status_message =
                Some("Only successful attempts can be saved as recipes by default".to_string());
            return;
        }

        let sanitized = redact_draft_for_storage(&draft);
        let recipe = Recipe {
            id: None,
            name: default_recipe_name(&sanitized),
            method: sanitized.method.clone(),
            url_template: build_recipe_url(&sanitized),
            headers_template: sanitized.headers.clone(),
            query_template: sanitized.query.clone(),
            body_template: sanitized.body.clone(),
            auth_style: sanitized.auth.clone(),
            slots: sanitized.slots.clone(),
            last_success_at: Some(Utc::now()),
            last_success_status: result
                .response_snapshot
                .as_ref()
                .and_then(|response| response.status),
        };
        match self.repository.insert_recipe(&recipe) {
            Ok(_) => {
                self.refresh_lists();
                self.status_message = Some("Recipe saved".to_string());
            }
            Err(error) => {
                self.status_message = Some(format!("Could not save recipe: {error}"));
            }
        }
    }

    pub fn copy_recipe_as_curl(&mut self, id: i64, ctx: &egui::Context) {
        match self.repository.get_recipe(id).and_then(|recipe| {
            recipe
                .context("Recipe not found")
                .and_then(|recipe| recipe_to_curl(&recipe))
        }) {
            Ok(text) => {
                ctx.copy_text(text);
                self.status_message = Some("Recipe curl copied to clipboard".to_string());
            }
            Err(error) => self.status_message = Some(format!("Could not copy curl: {error}")),
        }
    }

    pub fn export_recipe_markdown(&mut self, id: i64) {
        self.export_recipe_with(id, "md", recipe_to_markdown);
    }

    pub fn export_recipe_json(&mut self, id: i64) {
        self.export_recipe_with(id, "json", |recipe| {
            recipe_to_json(recipe).unwrap_or_default()
        });
    }

    fn export_recipe_with<F>(&mut self, id: i64, extension: &str, render: F)
    where
        F: Fn(&Recipe) -> String,
    {
        match self.repository.get_recipe(id) {
            Ok(Some(recipe)) => {
                let filename = format!("{}.{extension}", sanitize_filename(&recipe.name));
                let path = self.paths.exports_dir.join(filename);
                match std::fs::write(&path, render(&recipe)) {
                    Ok(_) => {
                        self.status_message =
                            Some(format!("Exported recipe to {}", path.display()));
                    }
                    Err(error) => {
                        self.status_message = Some(format!("Could not export recipe: {error}"));
                    }
                }
            }
            Ok(None) => self.status_message = Some("Recipe not found".to_string()),
            Err(error) => self.status_message = Some(format!("Could not export recipe: {error}")),
        }
    }

    fn persist_latest_attempt(&mut self) {
        let Some(draft) = self.working_draft.clone() else {
            return;
        };
        let Some(result) = self.last_execution.as_ref() else {
            return;
        };
        let request = redact_request(&result.rendered_request);
        let response = result.response_snapshot.as_ref().map(redact_response);
        let attempt = RequestAttempt {
            id: None,
            created_at: Utc::now(),
            source_inputs: current_source_inputs(&self.inputs)
                .into_iter()
                .map(|mut input| {
                    input.raw_text = redact_free_text(&input.raw_text);
                    input
                })
                .collect(),
            request_draft_snapshot: redact_draft_for_storage(&draft),
            rendered_request_redacted: request,
            response_snapshot_redacted: response,
            outcome: result.outcome.clone(),
            blocker: result.blocker.clone(),
            notes: result.notes.clone(),
            evidence_summary: draft
                .evidence
                .iter()
                .map(|item| format!("{} ({})", item.label, item.confidence.label()))
                .collect::<Vec<_>>()
                .join(", "),
        };
        if let Err(error) = self.repository.insert_attempt(&attempt) {
            self.status_message = Some(format!("Could not persist attempt: {error}"));
        }
    }
}

impl FirstCallApp {
    pub(crate) fn is_running(&self) -> bool {
        self.running_execution.is_some()
    }
}

impl eframe::App for FirstCallApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_execution();
        if self.is_running() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("top_nav").show_inside(root_ui, |ui| {
            ui.horizontal(|ui| {
                for (screen, label) in [
                    (TopScreen::NewAttempt, "New Attempt"),
                    (TopScreen::Attempts, "Attempts"),
                    (TopScreen::Recipes, "Recipes"),
                    (TopScreen::Settings, "Settings"),
                ] {
                    if ui.selectable_label(self.screen == screen, label).clicked() {
                        self.screen = screen;
                    }
                }
                ui.separator();
                if let Some(message) = &self.status_message {
                    ui.label(message);
                }
            });
        });

        match self.screen {
            TopScreen::NewAttempt => self.render_new_attempt(root_ui),
            TopScreen::Attempts => self.render_attempts(root_ui),
            TopScreen::Recipes => self.render_recipes(root_ui),
            TopScreen::Settings => self.render_settings(root_ui),
        }
    }
}

fn bootstrap_repository() -> (AppPaths, AppRepository, Option<String>) {
    let fallback_root = std::env::temp_dir().join("firstcall_fallback");
    let fallback_paths =
        AppPaths::from_root(&fallback_root.join("data"), &fallback_root.join("config"))
            .unwrap_or_else(|_| AppPaths {
                data_dir: fallback_root.join("data"),
                config_dir: fallback_root.join("config"),
                exports_dir: fallback_root.join("data").join("exports"),
                db_path: fallback_root.join("data").join("firstcall.sqlite3"),
            });

    match AppPaths::discover()
        .and_then(|paths| open_database(&paths).map(|connection| (paths, connection)))
    {
        Ok((paths, connection)) => (paths, AppRepository::new(connection), None),
        Err(error) => {
            let warning = format!(
                "Falling back to a temporary local database because app storage initialization failed: {error}"
            );
            let connection = Connection::open_in_memory().expect("in-memory sqlite");
            run_migrations(&connection).expect("migrations");
            (
                fallback_paths,
                AppRepository::new(connection),
                Some(warning),
            )
        }
    }
}

fn current_source_inputs(inputs: &InputBuffers) -> Vec<crate::model::SourceInput> {
    let mut sources = Vec::new();
    if !inputs.curl.trim().is_empty() {
        sources.push(crate::model::SourceInput {
            kind: crate::model::SourceKind::Curl,
            raw_text: inputs.curl.clone(),
        });
    }
    if !inputs.docs.trim().is_empty() {
        sources.push(crate::model::SourceInput {
            kind: crate::model::SourceKind::Docs,
            raw_text: inputs.docs.clone(),
        });
    }
    if !inputs.openapi.trim().is_empty() {
        sources.push(crate::model::SourceInput {
            kind: crate::model::SourceKind::OpenApi,
            raw_text: inputs.openapi.clone(),
        });
    }
    sources
}

fn build_recipe_url(draft: &RequestDraft) -> String {
    let base = draft.base_url.clone().unwrap_or_default();
    if base.is_empty() {
        draft.path.clone()
    } else if draft.path.starts_with('/') {
        format!("{}{}", base.trim_end_matches('/'), draft.path)
    } else {
        format!("{}/{}", base.trim_end_matches('/'), draft.path)
    }
}

fn default_recipe_name(draft: &RequestDraft) -> String {
    let host = draft
        .base_url
        .as_deref()
        .and_then(|url| url::Url::parse(url).ok())
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "local".to_string());
    format!("{} {}{}", draft.method, host, draft.path)
}

fn recipe_to_draft(recipe: Recipe) -> RequestDraft {
    RequestDraft {
        operation_id: format!("recipe-{}", recipe.id.unwrap_or_default()),
        name: recipe.name.clone(),
        method: recipe.method.clone(),
        base_url: split_recipe_url(&recipe.url_template).0,
        path: split_recipe_url(&recipe.url_template).1,
        headers: recipe.headers_template.clone(),
        query: recipe.query_template.clone(),
        body: recipe.body_template.clone(),
        auth: recipe.auth_style.clone(),
        slots: recipe.slots.clone(),
        evidence: Vec::new(),
        confidence: crate::model::FieldConfidence {
            overall: crate::model::Confidence::High,
            notes: "Loaded from saved recipe".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: Vec::new(),
    }
}

fn split_recipe_url(url_template: &str) -> (Option<String>, String) {
    if let Ok(url) = url::Url::parse(url_template) {
        let base = format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap_or_default(),
            url.port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        let path = if let Some(query) = url.query() {
            format!("{}?{query}", url.path())
        } else {
            url.path().to_string()
        };
        (Some(base), path)
    } else {
        (None, url_template.to_string())
    }
}

fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            if matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            ) {
                '_'
            } else {
                character
            }
        })
        .collect::<String>()
}

fn sync_auth_slots(draft: &RequestDraft, secret_store: &mut dyn SecretStore) {
    for slot in &draft.slots {
        if slot.location == crate::model::SlotLocation::Auth
            && let Some(value) = &slot.current_value
            && !value.trim().is_empty()
        {
            secret_store.set(&slot.name, SecretString::new(value.clone().into()));
        }
    }
}

fn hydrate_auth_slots(draft: &mut RequestDraft, secret_store: &dyn SecretStore) {
    for slot in &mut draft.slots {
        if slot.location == crate::model::SlotLocation::Auth
            && slot.current_value.as_deref().unwrap_or("").is_empty()
            && let Some(secret) = secret_store.get(&slot.name)
        {
            slot.current_value = Some(secret.expose_secret().to_string());
        }
    }
}
