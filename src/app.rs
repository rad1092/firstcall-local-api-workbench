use std::collections::BTreeMap;
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
    RequestAttempt, RequestDraft, RuntimeSlot, SlotLocation, SourceInput, SourceKind,
};
use crate::parse::{
    bruno::parse_bruno_input, curl::parse_curl_input, docs::parse_docs_input, har::parse_har_input,
    http_file::parse_http_file_input, hurl::parse_hurl_input, openapi::parse_openapi_input,
    postman::parse_postman_collection_input,
};
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
    PostmanCollection,
    Har,
    HttpFile,
    Hurl,
    Bruno,
}

impl InputTab {
    pub const ALL: [Self; 8] = [
        Self::Curl,
        Self::Docs,
        Self::OpenApi,
        Self::PostmanCollection,
        Self::Har,
        Self::HttpFile,
        Self::Hurl,
        Self::Bruno,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Docs => "Docs",
            Self::OpenApi => "OpenAPI",
            Self::PostmanCollection => "Postman Collection",
            Self::Har => "HAR",
            Self::HttpFile => ".http / .rest",
            Self::Hurl => "Hurl",
            Self::Bruno => "Bruno / OpenCollection",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Curl => "Paste a curl command. Curl evidence has highest merge precedence.",
            Self::Docs => "Paste docs prose. Docs are used as low-precedence supporting evidence.",
            Self::OpenApi => {
                "Paste OpenAPI JSON or YAML. Local refs are supported by core parsers."
            }
            Self::PostmanCollection => {
                "Static import only. Pre-request scripts and tests are ignored."
            }
            Self::Har => {
                "Browser capture import with aggressive redaction. Response bodies are not imported."
            }
            Self::HttpFile => {
                "Static .http/.rest request parsing. Environments and scripts are not executed."
            }
            Self::Hurl => "Request-only subset. Response asserts and captures are ignored.",
            Self::Bruno => {
                "Limited static Bruno/OpenCollection subset. Scripts and runtime hooks are ignored."
            }
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Curl => "Paste a curl command here",
            Self::Docs => "Paste API docs prose here",
            Self::OpenApi => "Paste OpenAPI JSON or YAML here",
            Self::PostmanCollection => "Paste a Postman Collection v2.1 JSON document here",
            Self::Har => "Paste a HAR JSON document here",
            Self::HttpFile => "Paste a JetBrains-style .http or .rest file here",
            Self::Hurl => "Paste a Hurl request-only file here",
            Self::Bruno => "Paste a .bru file or OpenCollection YAML request here",
        }
    }

    pub fn source_kind(self) -> SourceKind {
        match self {
            Self::Curl => SourceKind::Curl,
            Self::Docs => SourceKind::Docs,
            Self::OpenApi => SourceKind::OpenApi,
            Self::PostmanCollection => SourceKind::PostmanCollection,
            Self::Har => SourceKind::Har,
            Self::HttpFile => SourceKind::HttpFile,
            Self::Hurl => SourceKind::Hurl,
            Self::Bruno => SourceKind::Bruno,
        }
    }

    pub fn has_sample(self) -> bool {
        matches!(self, Self::Curl | Self::Docs | Self::OpenApi)
    }
}

pub struct InputBuffers {
    pub curl: String,
    pub docs: String,
    pub openapi: String,
    pub postman: String,
    pub har: String,
    pub http_file: String,
    pub hurl: String,
    pub bruno: String,
    pub active_tab: InputTab,
}

impl InputBuffers {
    pub fn buffer(&self, tab: InputTab) -> &str {
        match tab {
            InputTab::Curl => &self.curl,
            InputTab::Docs => &self.docs,
            InputTab::OpenApi => &self.openapi,
            InputTab::PostmanCollection => &self.postman,
            InputTab::Har => &self.har,
            InputTab::HttpFile => &self.http_file,
            InputTab::Hurl => &self.hurl,
            InputTab::Bruno => &self.bruno,
        }
    }

    pub fn buffer_mut(&mut self, tab: InputTab) -> &mut String {
        match tab {
            InputTab::Curl => &mut self.curl,
            InputTab::Docs => &mut self.docs,
            InputTab::OpenApi => &mut self.openapi,
            InputTab::PostmanCollection => &mut self.postman,
            InputTab::Har => &mut self.har,
            InputTab::HttpFile => &mut self.http_file,
            InputTab::Hurl => &mut self.hurl,
            InputTab::Bruno => &mut self.bruno,
        }
    }
}

impl Default for InputBuffers {
    fn default() -> Self {
        Self {
            curl: String::new(),
            docs: String::new(),
            openapi: String::new(),
            postman: String::new(),
            har: String::new(),
            http_file: String::new(),
            hurl: String::new(),
            bruno: String::new(),
            active_tab: InputTab::Curl,
        }
    }
}

struct RunningExecution {
    receiver: Receiver<ExecutionResult>,
    draft_snapshot: RequestDraft,
    source_inputs_snapshot: Vec<SourceInput>,
}

pub struct FirstCallApp {
    pub screen: TopScreen,
    pub inputs: InputBuffers,
    pub parsed_sources: Vec<ParsedSource>,
    pub candidate_drafts: Vec<RequestDraft>,
    pub selected_candidate: Option<usize>,
    pub working_draft: Option<RequestDraft>,
    pub last_execution: Option<ExecutionResult>,
    pub last_successful_draft: Option<RequestDraft>,
    pub attempts: Vec<AttemptListItem>,
    pub selected_attempt_id: Option<i64>,
    pub recipes: Vec<RecipeListItem>,
    pub recipe_search: String,
    pub auth_slot_inputs: BTreeMap<String, String>,
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
            last_successful_draft: None,
            attempts,
            selected_attempt_id: None,
            recipes,
            recipe_search: String::new(),
            auth_slot_inputs: BTreeMap::new(),
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
        if self.context_change_blocked_while_running() {
            return;
        }
        self.clear_completed_execution_state();
        self.parsed_sources = parse_input_buffers(&self.inputs);
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
            clear_visible_auth_slots(draft);
        }
        self.auth_slot_inputs.clear();
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
        if self.context_change_blocked_while_running() {
            return;
        }
        if let Some(candidate) = self.candidate_drafts.get(index).cloned() {
            self.clear_completed_execution_state();
            self.selected_candidate = Some(index);
            self.working_draft = Some(candidate);
            if let Some(draft) = &mut self.working_draft {
                clear_visible_auth_slots(draft);
            }
            self.auth_slot_inputs.clear();
        }
    }

    pub fn reset_inputs(&mut self) {
        if self.context_change_blocked_while_running() {
            return;
        }
        self.inputs = InputBuffers {
            active_tab: InputTab::Curl,
            ..InputBuffers::default()
        };
        self.parsed_sources.clear();
        self.candidate_drafts.clear();
        self.selected_candidate = None;
        self.working_draft = None;
        self.clear_completed_execution_state();
        self.auth_slot_inputs.clear();
    }

    pub fn load_sample_for_active_tab(&mut self) {
        if self.context_change_blocked_while_running() {
            return;
        }
        match self.inputs.active_tab {
            InputTab::Curl => self.inputs.curl = SAMPLE_CURL.to_string(),
            InputTab::Docs => self.inputs.docs = SAMPLE_DOCS.to_string(),
            InputTab::OpenApi => self.inputs.openapi = SAMPLE_OPENAPI.to_string(),
            InputTab::PostmanCollection
            | InputTab::Har
            | InputTab::HttpFile
            | InputTab::Hurl
            | InputTab::Bruno => {
                self.status_message = Some(
                    "Sample fixtures are currently available for curl, docs, and OpenAPI only."
                        .to_string(),
                );
            }
        }
    }

    pub fn run_current_draft(&mut self) {
        if self.running_execution.is_some() {
            return;
        }
        self.store_pending_auth_inputs();
        let Some(mut draft) = self.working_draft.clone() else {
            self.status_message = Some("Select or build a request first".to_string());
            return;
        };
        hydrate_auth_slots(&mut draft, self.secret_store.as_ref());
        self.secret_status = self.secret_store.status();
        let missing_slots = unresolved_required_slot_names(&draft);
        if !missing_slots.is_empty() {
            self.status_message = Some(format!(
                "Cannot run request: missing required runtime slot(s): {}",
                missing_slots.join(", ")
            ));
            return;
        }

        let safe_executed_draft_snapshot = safe_executed_draft_snapshot(&draft);
        let source_inputs_snapshot =
            safe_source_inputs_for_execution(&self.parsed_sources, &self.inputs);
        let settings = self.settings.clone();
        let client = self.http_client.clone();
        let (sender, receiver) = mpsc::channel();
        self.clear_completed_execution_state();
        self.running_execution = Some(RunningExecution {
            receiver,
            draft_snapshot: safe_executed_draft_snapshot,
            source_inputs_snapshot,
        });
        self.status_message = Some("Running request...".to_string());
        std::thread::spawn(move || {
            let result = execute_request(&draft, &settings, &client);
            let _ = sender.send(result);
        });
    }

    pub fn poll_execution(&mut self) {
        let received = {
            let Some(running) = &self.running_execution else {
                return;
            };
            running.receiver.try_recv().ok().map(|result| {
                (
                    running.draft_snapshot.clone(),
                    running.source_inputs_snapshot.clone(),
                    result,
                )
            })
        };

        if let Some((draft_snapshot, source_inputs_snapshot, result)) = received {
            self.running_execution = None;
            self.last_successful_draft = if result.outcome == Outcome::Success {
                Some(draft_snapshot.clone())
            } else {
                None
            };
            self.persist_latest_attempt(&draft_snapshot, &result, source_inputs_snapshot);
            self.last_execution = Some(result);
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
        if self.context_change_blocked_while_running() {
            return;
        }
        if let Ok(Some(attempt)) = self.repository.get_attempt(id) {
            self.clear_completed_execution_state();
            self.inputs = InputBuffers::default();
            let mut first_tab = None;
            for source in &attempt.source_inputs {
                if let Some(tab) = input_tab_for_source_kind(&source.kind) {
                    *self.inputs.buffer_mut(tab) = source.raw_text.clone();
                    first_tab.get_or_insert(tab);
                }
            }
            if let Some(tab) = first_tab {
                self.inputs.active_tab = tab;
            }
            self.working_draft = Some(attempt.request_draft_snapshot);
            if let Some(draft) = &mut self.working_draft {
                clear_visible_auth_slots(draft);
            }
            self.auth_slot_inputs.clear();
            self.screen = TopScreen::NewAttempt;
        }
    }

    pub fn rerun_recipe(&mut self, id: i64) {
        if self.context_change_blocked_while_running() {
            return;
        }
        if let Ok(Some(recipe)) = self.repository.get_recipe(id) {
            self.clear_completed_execution_state();
            self.working_draft = Some(recipe_to_draft(recipe));
            if let Some(draft) = &mut self.working_draft {
                clear_visible_auth_slots(draft);
            }
            self.auth_slot_inputs.clear();
            self.screen = TopScreen::NewAttempt;
        }
    }

    pub fn save_current_recipe(&mut self) {
        let Some(result) = &self.last_execution else {
            self.status_message =
                Some("Run the request successfully before saving a recipe.".to_string());
            return;
        };
        if result.outcome != Outcome::Success {
            self.status_message =
                Some("Only successful attempts can be saved as recipes by default".to_string());
            return;
        }
        let Some(draft) = &self.last_successful_draft else {
            self.status_message =
                Some("Run the request successfully before saving a recipe.".to_string());
            return;
        };

        let recipe = recipe_from_executed_draft(draft, result);
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

    fn persist_latest_attempt(
        &mut self,
        executed_draft: &RequestDraft,
        result: &ExecutionResult,
        source_inputs_snapshot: Vec<SourceInput>,
    ) {
        let attempt = attempt_from_executed_draft(executed_draft, result, source_inputs_snapshot);
        if let Err(error) = self.repository.insert_attempt(&attempt) {
            self.status_message = Some(format!("Could not persist attempt: {error}"));
        }
    }
}

impl FirstCallApp {
    pub(crate) fn is_running(&self) -> bool {
        self.running_execution.is_some()
    }

    pub(crate) fn missing_required_slot_count(&self, draft: &RequestDraft) -> usize {
        draft
            .slots
            .iter()
            .filter(|slot| {
                slot.required
                    && !slot_has_runtime_value(
                        slot,
                        self.secret_store.as_ref(),
                        &self.auth_slot_inputs,
                    )
            })
            .count()
    }

    pub(crate) fn auth_slot_is_stored(&self, slot_name: &str) -> bool {
        self.secret_store.get(slot_name).is_some()
    }

    pub(crate) fn store_auth_slot_value(&mut self, slot_name: &str, value: String) {
        if !value.trim().is_empty() {
            self.secret_store
                .set(slot_name, SecretString::new(value.into()));
            self.secret_status = self.secret_store.status();
            self.status_message = Some(format!("Stored secret for runtime slot `{slot_name}`"));
        }
    }

    fn store_pending_auth_inputs(&mut self) {
        let pending = std::mem::take(&mut self.auth_slot_inputs);
        for (slot_name, value) in pending {
            if !value.trim().is_empty() {
                self.secret_store
                    .set(&slot_name, SecretString::new(value.into()));
            }
        }
    }

    fn context_change_blocked_while_running(&mut self) -> bool {
        if self.is_running() {
            self.status_message = Some(
                "A request is currently running; wait for it to finish before changing inputs or candidates."
                    .to_string(),
            );
            return true;
        }
        false
    }

    fn clear_completed_execution_state(&mut self) {
        self.last_execution = None;
        self.last_successful_draft = None;
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

fn parse_input_buffers(inputs: &InputBuffers) -> Vec<ParsedSource> {
    let mut parsed = Vec::new();
    if !inputs.curl.trim().is_empty() {
        parsed.push(parse_curl_input(&inputs.curl));
    }
    if !inputs.docs.trim().is_empty() {
        parsed.push(parse_docs_input(&inputs.docs));
    }
    if !inputs.openapi.trim().is_empty() {
        parsed.push(parse_openapi_input(&inputs.openapi));
    }
    if !inputs.postman.trim().is_empty() {
        parsed.push(parse_postman_collection_input(&inputs.postman));
    }
    if !inputs.har.trim().is_empty() {
        parsed.push(parse_har_input(&inputs.har));
    }
    if !inputs.http_file.trim().is_empty() {
        parsed.push(parse_http_file_input(&inputs.http_file));
    }
    if !inputs.hurl.trim().is_empty() {
        parsed.push(parse_hurl_input(&inputs.hurl));
    }
    if !inputs.bruno.trim().is_empty() {
        parsed.push(parse_bruno_input(&inputs.bruno));
    }
    parsed
}

fn safe_source_inputs(parsed_sources: &[ParsedSource], inputs: &InputBuffers) -> Vec<SourceInput> {
    if !parsed_sources.is_empty() {
        return parsed_sources
            .iter()
            .map(|parsed| parsed.source.clone())
            .collect();
    }
    current_source_inputs(inputs)
}

fn current_source_inputs(inputs: &InputBuffers) -> Vec<crate::model::SourceInput> {
    let mut sources = Vec::new();
    for tab in InputTab::ALL {
        let raw_text = inputs.buffer(tab);
        if !raw_text.trim().is_empty() {
            sources.push(crate::model::SourceInput {
                kind: tab.source_kind(),
                raw_text: raw_text.to_string(),
            });
        }
    }
    sources
}

fn safe_source_inputs_for_execution(
    parsed_sources: &[ParsedSource],
    inputs: &InputBuffers,
) -> Vec<SourceInput> {
    safe_source_inputs(parsed_sources, inputs)
        .into_iter()
        .map(redact_source_input)
        .collect()
}

fn redact_source_input(mut input: SourceInput) -> SourceInput {
    input.raw_text = redact_free_text(&input.raw_text);
    input
}

fn input_tab_for_source_kind(kind: &SourceKind) -> Option<InputTab> {
    match kind {
        SourceKind::Curl => Some(InputTab::Curl),
        SourceKind::Docs => Some(InputTab::Docs),
        SourceKind::OpenApi => Some(InputTab::OpenApi),
        SourceKind::PostmanCollection => Some(InputTab::PostmanCollection),
        SourceKind::Har => Some(InputTab::Har),
        SourceKind::HttpFile => Some(InputTab::HttpFile),
        SourceKind::Hurl => Some(InputTab::Hurl),
        SourceKind::Bruno => Some(InputTab::Bruno),
        SourceKind::Graphql => None,
    }
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

fn safe_executed_draft_snapshot(execution_draft: &RequestDraft) -> RequestDraft {
    let mut snapshot = redact_draft_for_storage(execution_draft);
    clear_visible_auth_slots(&mut snapshot);
    snapshot
}

fn recipe_from_executed_draft(executed_draft: &RequestDraft, result: &ExecutionResult) -> Recipe {
    let sanitized = safe_executed_draft_snapshot(executed_draft);
    Recipe {
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
    }
}

fn attempt_from_executed_draft(
    executed_draft: &RequestDraft,
    result: &ExecutionResult,
    source_inputs: Vec<crate::model::SourceInput>,
) -> RequestAttempt {
    RequestAttempt {
        id: None,
        created_at: Utc::now(),
        source_inputs: source_inputs.into_iter().map(redact_source_input).collect(),
        request_draft_snapshot: safe_executed_draft_snapshot(executed_draft),
        rendered_request_redacted: redact_request(&result.rendered_request),
        response_snapshot_redacted: result.response_snapshot.as_ref().map(redact_response),
        outcome: result.outcome.clone(),
        blocker: result.blocker.clone(),
        notes: result.notes.clone(),
        evidence_summary: executed_draft
            .evidence
            .iter()
            .map(|item| format!("{} ({})", item.label, item.confidence.label()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn hydrate_auth_slots(draft: &mut RequestDraft, secret_store: &dyn SecretStore) {
    for slot in &mut draft.slots {
        if slot.location == SlotLocation::Auth
            && slot.current_value.as_deref().unwrap_or("").is_empty()
            && let Some(secret) = secret_store.get(&slot.name)
        {
            slot.current_value = Some(secret.expose_secret().to_string());
        }
    }
}

fn unresolved_required_slot_names(draft: &RequestDraft) -> Vec<String> {
    draft
        .unresolved_slots()
        .into_iter()
        .map(|slot| slot.name.clone())
        .collect()
}

fn clear_visible_auth_slots(draft: &mut RequestDraft) {
    for slot in &mut draft.slots {
        if slot.location == SlotLocation::Auth {
            slot.current_value = None;
        }
    }
}

fn slot_has_runtime_value(
    slot: &RuntimeSlot,
    secret_store: &dyn SecretStore,
    auth_slot_inputs: &BTreeMap<String, String>,
) -> bool {
    if slot.location == SlotLocation::Auth {
        auth_slot_inputs
            .get(&slot.name)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || secret_store.get(&slot.name).is_some()
    } else {
        !slot
            .current_value
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;

    use secrecy::SecretString;

    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, RenderedRequest,
        ResponseSnapshot, RuntimeSlot, SourceInput, SourceKind,
    };
    use crate::store::db::AppPaths;
    use crate::store::repos::AppRepository;
    use crate::store::secrets::MemorySecretStore;

    use super::*;

    #[test]
    fn unresolved_required_slot_names_reports_empty_required_slots() {
        let draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, None),
            runtime_slot("user_id", SlotLocation::Path, true, None),
            runtime_slot("page", SlotLocation::Query, false, None),
        ]);

        assert_eq!(
            unresolved_required_slot_names(&draft),
            vec!["bearer_token".to_string(), "user_id".to_string()]
        );
    }

    #[test]
    fn hydrated_auth_slot_is_not_unresolved_on_execution_clone() {
        let mut visible_draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, None),
            runtime_slot("user_id", SlotLocation::Path, true, Some("42")),
        ]);
        let mut secret_store = MemorySecretStore::default();
        secret_store.set(
            "bearer_token",
            SecretString::new("auth_secret_used_only_for_execution".to_string().into()),
        );

        let mut execution_draft = visible_draft.clone();
        hydrate_auth_slots(&mut execution_draft, &secret_store);

        assert!(unresolved_required_slot_names(&execution_draft).is_empty());
        assert!(
            execution_draft
                .slots
                .iter()
                .any(|slot| slot.name == "bearer_token" && slot.current_value.is_some())
        );

        clear_visible_auth_slots(&mut visible_draft);
        assert!(
            visible_draft
                .slots
                .iter()
                .any(|slot| slot.name == "bearer_token" && slot.current_value.is_none())
        );
    }

    #[test]
    fn clear_visible_auth_slots_only_clears_auth_values() {
        let mut draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, Some("secret")),
            runtime_slot("user_id", SlotLocation::Path, true, Some("42")),
        ]);

        clear_visible_auth_slots(&mut draft);

        assert!(
            draft
                .slots
                .iter()
                .any(|slot| slot.name == "bearer_token" && slot.current_value.is_none())
        );
        assert!(
            draft
                .slots
                .iter()
                .any(|slot| slot.name == "user_id" && slot.current_value.as_deref() == Some("42"))
        );
    }

    #[test]
    fn safe_executed_draft_snapshot_clears_auth_current_values_after_hydration() {
        let mut execution_draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, None),
            runtime_slot("user_id", SlotLocation::Path, true, Some("42")),
        ]);
        let mut secret_store = MemorySecretStore::default();
        secret_store.set(
            "bearer_token",
            SecretString::new(
                "safe_snapshot_auth_secret_should_not_leak"
                    .to_string()
                    .into(),
            ),
        );

        hydrate_auth_slots(&mut execution_draft, &secret_store);
        assert!(
            execution_draft
                .slots
                .iter()
                .any(|slot| slot.location == SlotLocation::Auth && slot.current_value.is_some())
        );

        let snapshot = safe_executed_draft_snapshot(&execution_draft);

        assert!(
            snapshot
                .slots
                .iter()
                .any(|slot| slot.location == SlotLocation::Auth && slot.current_value.is_none())
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .expect("snapshot json")
                .contains("safe_snapshot_auth_secret_should_not_leak")
        );
    }

    #[test]
    fn recipe_creation_uses_executed_snapshot_not_later_mutated_working_draft() {
        let executed_draft = safe_executed_draft_snapshot(&draft_with_path("/executed"));
        let mut edited_draft = draft_with_path("/edited");
        edited_draft.name = "Edited Builder Draft".to_string();
        let result = success_result("/executed");
        let mut app = app_with_working_draft(edited_draft);
        app.last_execution = Some(result);
        app.last_successful_draft = Some(executed_draft);

        app.save_current_recipe();

        let recipes = app.repository.list_recipes().expect("recipes");
        assert_eq!(recipes.len(), 1);
        let recipe = app
            .repository
            .get_recipe(recipes[0].id)
            .expect("recipe")
            .expect("saved recipe");
        assert!(recipe.url_template.ends_with("/executed"));
        assert!(!recipe.url_template.ends_with("/edited"));
    }

    #[test]
    fn attempt_construction_uses_provided_executed_snapshot_and_evidence() {
        let mut executed_draft = draft_with_path("/executed-attempt");
        executed_draft.evidence.push(EvidenceItem {
            source_kind: SourceKind::Curl,
            label: "executed evidence".to_string(),
            detail: "safe fixed evidence".to_string(),
            confidence: Confidence::High,
        });
        let result = success_result("/executed-attempt");

        let attempt = attempt_from_executed_draft(
            &executed_draft,
            &result,
            vec![SourceInput {
                kind: SourceKind::Curl,
                raw_text: "Authorization: Bearer attempt_secret_should_not_leak".to_string(),
            }],
        );

        assert_eq!(attempt.request_draft_snapshot.path, "/executed-attempt");
        assert!(attempt.evidence_summary.contains("executed evidence"));
        assert!(
            !serde_json::to_string(&attempt)
                .expect("attempt json")
                .contains("attempt_secret_should_not_leak")
        );
    }

    #[test]
    fn safe_source_inputs_for_execution_prefers_parsed_source_and_redacts() {
        let parsed_sources = vec![ParsedSource {
            source: SourceInput {
                kind: SourceKind::Har,
                raw_text: "Authorization: Bearer source_snapshot_secret_should_not_leak\nGET https://parsed.example.com".to_string(),
            },
            candidates: Vec::new(),
            notes: Vec::new(),
        }];
        let inputs = InputBuffers {
            curl: "GET https://fallback.example.com".to_string(),
            ..InputBuffers::default()
        };

        let snapshot = safe_source_inputs_for_execution(&parsed_sources, &inputs);

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].kind, SourceKind::Har);
        assert!(snapshot[0].raw_text.contains("parsed.example.com"));
        assert!(!snapshot[0].raw_text.contains("fallback.example.com"));
        assert!(
            !serde_json::to_string(&snapshot)
                .expect("snapshot json")
                .contains("source_snapshot_secret_should_not_leak")
        );
    }

    #[test]
    fn safe_source_inputs_for_execution_redacts_fallback_buffers() {
        let inputs = InputBuffers {
            curl: "Authorization: Bearer fallback_source_secret_should_not_leak\ncurl https://fallback.example.com".to_string(),
            ..InputBuffers::default()
        };

        let snapshot = safe_source_inputs_for_execution(&[], &inputs);

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].kind, SourceKind::Curl);
        assert!(snapshot[0].raw_text.contains("fallback.example.com"));
        assert!(
            !serde_json::to_string(&snapshot)
                .expect("snapshot json")
                .contains("fallback_source_secret_should_not_leak")
        );
    }

    #[test]
    fn poll_execution_persists_run_start_source_snapshot_after_buffers_mutate() {
        let executed_draft = safe_executed_draft_snapshot(&draft_with_path("/source-snapshot"));
        let run_start_inputs = InputBuffers {
            curl: "Authorization: Bearer run_start_source_secret_should_not_leak\ncurl https://run-start.example.com".to_string(),
            ..InputBuffers::default()
        };
        let source_inputs_snapshot = safe_source_inputs_for_execution(&[], &run_start_inputs);
        let (sender, receiver) = mpsc::channel();
        sender
            .send(success_result("/source-snapshot"))
            .expect("send result");

        let mut app = app_with_working_draft(draft_with_path("/edited-later"));
        app.inputs.curl = "Authorization: Bearer current_buffer_secret_should_not_leak\ncurl https://current-buffer.example.com".to_string();
        app.running_execution = Some(RunningExecution {
            receiver,
            draft_snapshot: executed_draft,
            source_inputs_snapshot,
        });

        app.poll_execution();

        assert!(app.running_execution.is_none());
        let attempts = app.repository.list_attempts().expect("attempts");
        assert_eq!(attempts.len(), 1);
        let attempt = app
            .repository
            .get_attempt(attempts[0].id)
            .expect("attempt")
            .expect("persisted attempt");
        let attempt_json = serde_json::to_string(&attempt).expect("attempt json");
        assert!(attempt_json.contains("run-start.example.com"));
        assert!(!attempt_json.contains("current-buffer.example.com"));
        assert!(!attempt_json.contains("run_start_source_secret_should_not_leak"));
        assert!(!attempt_json.contains("current_buffer_secret_should_not_leak"));
    }

    #[test]
    fn persist_latest_attempt_uses_provided_source_snapshot_not_current_buffers() {
        let mut app = app_with_working_draft(draft_with_path("/persist-source"));
        app.inputs.curl = "Authorization: Bearer persist_current_secret_should_not_leak\ncurl https://current-buffer.example.com".to_string();
        let source_inputs_snapshot = vec![SourceInput {
            kind: SourceKind::Curl,
            raw_text: "Authorization: Bearer persist_snapshot_secret_should_not_leak\ncurl https://provided-snapshot.example.com".to_string(),
        }];

        app.persist_latest_attempt(
            &draft_with_path("/persist-source"),
            &success_result("/persist-source"),
            source_inputs_snapshot,
        );

        let attempts = app.repository.list_attempts().expect("attempts");
        assert_eq!(attempts.len(), 1);
        let attempt = app
            .repository
            .get_attempt(attempts[0].id)
            .expect("attempt")
            .expect("persisted attempt");
        let attempt_json = serde_json::to_string(&attempt).expect("attempt json");
        assert!(attempt_json.contains("provided-snapshot.example.com"));
        assert!(!attempt_json.contains("current-buffer.example.com"));
        assert!(!attempt_json.contains("persist_snapshot_secret_should_not_leak"));
        assert!(!attempt_json.contains("persist_current_secret_should_not_leak"));
    }

    #[test]
    fn blocked_missing_slot_run_does_not_start_or_update_execution_state() {
        let draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, None),
            runtime_slot("user_id", SlotLocation::Path, true, None),
        ]);
        let mut app = app_with_working_draft(draft);

        app.run_current_draft();

        assert!(app.running_execution.is_none());
        assert!(app.last_execution.is_none());
        assert!(app.last_successful_draft.is_none());
        assert!(
            app.status_message
                .as_deref()
                .unwrap_or_default()
                .contains("Cannot run request: missing required runtime slot(s):")
        );
    }

    #[test]
    fn analyze_inputs_while_running_does_not_clear_running_execution() {
        let mut app = app_with_working_draft(draft_with_path("/running"));
        app.inputs.curl = "curl https://before.example.com".to_string();
        app.running_execution = Some(running_execution_with_path("/running"));

        app.analyze_inputs();

        assert!(app.running_execution.is_some());
        assert!(app.parsed_sources.is_empty());
        assert!(
            app.status_message
                .as_deref()
                .unwrap_or_default()
                .contains("A request is currently running")
        );
    }

    #[test]
    fn select_candidate_while_running_does_not_change_working_draft() {
        let current = draft_with_path("/current");
        let next = draft_with_path("/next");
        let mut app = app_with_working_draft(current);
        app.selected_candidate = Some(0);
        app.candidate_drafts = vec![draft_with_path("/current"), next];
        app.running_execution = Some(running_execution_with_path("/current"));

        app.select_candidate(1);

        assert!(app.running_execution.is_some());
        assert_eq!(app.selected_candidate, Some(0));
        assert_eq!(
            app.working_draft.as_ref().map(|draft| draft.path.as_str()),
            Some("/current")
        );
    }

    #[test]
    fn reset_inputs_while_running_does_not_drop_receiver_or_mutate_context() {
        let mut app = app_with_working_draft(draft_with_path("/running-reset"));
        app.inputs.curl = "curl https://before-reset.example.com".to_string();
        app.running_execution = Some(running_execution_with_path("/running-reset"));

        app.reset_inputs();

        assert!(app.running_execution.is_some());
        assert_eq!(app.inputs.curl, "curl https://before-reset.example.com");
        assert_eq!(
            app.working_draft.as_ref().map(|draft| draft.path.as_str()),
            Some("/running-reset")
        );
    }

    fn draft_with_slots(slots: Vec<RuntimeSlot>) -> RequestDraft {
        RequestDraft {
            operation_id: "test-operation".to_string(),
            name: "Test Operation".to_string(),
            method: "GET".to_string(),
            base_url: Some("https://api.example.com".to_string()),
            path: "/users/{{user_id}}".to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: BodyTemplate::None,
            auth: AuthStyle::Bearer {
                token_slot: "bearer_token".to_string(),
                header_name: "Authorization".to_string(),
            },
            slots,
            evidence: Vec::new(),
            confidence: FieldConfidence {
                overall: Confidence::High,
                notes: "test draft".to_string(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: vec![SourceKind::Curl],
        }
    }

    fn draft_with_path(path: &str) -> RequestDraft {
        let mut draft = draft_with_slots(vec![
            runtime_slot("bearer_token", SlotLocation::Auth, true, None),
            runtime_slot("user_id", SlotLocation::Path, true, Some("42")),
        ]);
        draft.path = path.to_string();
        draft
    }

    fn success_result(path: &str) -> ExecutionResult {
        ExecutionResult {
            rendered_request: RenderedRequest {
                method: "GET".to_string(),
                url: format!("https://api.example.com{path}"),
                headers: Vec::new(),
                body_preview: None,
            },
            response_snapshot: Some(ResponseSnapshot {
                status: Some(200),
                headers: Vec::new(),
                body_preview: "{}".to_string(),
                elapsed_ms: 1,
                validation_errors: Vec::new(),
                transport_error: None,
            }),
            outcome: Outcome::Success,
            blocker: None,
            notes: "Request executed".to_string(),
        }
    }

    fn app_with_working_draft(draft: RequestDraft) -> FirstCallApp {
        let connection = Connection::open_in_memory().expect("in-memory sqlite");
        run_migrations(&connection).expect("migrations");
        let secret_store = Box::new(MemorySecretStore::default());
        let secret_status = secret_store.status();

        FirstCallApp {
            screen: TopScreen::NewAttempt,
            inputs: InputBuffers::default(),
            parsed_sources: Vec::new(),
            candidate_drafts: Vec::new(),
            selected_candidate: None,
            working_draft: Some(draft),
            last_execution: None,
            last_successful_draft: None,
            attempts: Vec::new(),
            selected_attempt_id: None,
            recipes: Vec::new(),
            recipe_search: String::new(),
            auth_slot_inputs: BTreeMap::new(),
            settings: AppSettings::default(),
            paths: AppPaths {
                data_dir: PathBuf::new(),
                config_dir: PathBuf::new(),
                exports_dir: PathBuf::new(),
                db_path: PathBuf::new(),
            },
            repository: AppRepository::new(connection),
            secret_store,
            secret_status,
            http_client: Client::new(),
            status_message: None,
            bootstrap_warning: None,
            running_execution: None,
        }
    }

    fn running_execution_with_path(path: &str) -> RunningExecution {
        let (_sender, receiver) = mpsc::channel();
        RunningExecution {
            receiver,
            draft_snapshot: safe_executed_draft_snapshot(&draft_with_path(path)),
            source_inputs_snapshot: vec![SourceInput {
                kind: SourceKind::Curl,
                raw_text: "curl https://run-start.example.com".to_string(),
            }],
        }
    }

    fn runtime_slot(
        name: &str,
        location: SlotLocation,
        required: bool,
        current_value: Option<&str>,
    ) -> RuntimeSlot {
        RuntimeSlot {
            name: name.to_string(),
            location,
            required,
            current_value: current_value.map(str::to_string),
            description: String::new(),
            confidence: Confidence::High,
        }
    }
}
