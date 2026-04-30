use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use url::Url;

use crate::exec::client::{build_http_client, execute_request};
use crate::exec::redact::{REDACTED, is_secret_key, redact_body, redact_header_value};
use crate::export::agent_package::sanitized_agent_url_template;
use crate::model::{
    AppSettings, AuthStyle, BodyTemplate, Confidence, ExecutionResult, FieldConfidence,
    HeaderField, KeyValueField, Outcome, Recipe, RequestDraft, RuntimeSlot, SlotLocation,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyOptions {
    pub allow_mutating: bool,
}

#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub recipe_name: String,
    pub method: String,
    pub sanitized_url_template: String,
    pub status: Option<u16>,
    pub outcome: Outcome,
    pub blocker: Option<crate::model::Blocker>,
    pub verified_at: Option<DateTime<Utc>>,
    pub updated_recipe: Recipe,
}

#[derive(Clone, Debug)]
pub struct VerifyPreflightReport {
    pub recipe_name: String,
    pub method: String,
    pub sanitized_url_template: String,
    pub auth_style: String,
    pub body_kind: String,
    pub mutating_method: bool,
    pub allow_mutating: bool,
    pub would_execute_http: bool,
    pub required_env: Vec<PreflightEnv>,
    pub required_slots: Vec<PreflightSlot>,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightEnv {
    pub name: String,
    pub status: PreflightValueStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightValueStatus {
    Set,
    Missing,
}

impl PreflightValueStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightSlot {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub source: PreflightSlotSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightSlotSource {
    Current,
    Env,
    Missing,
    OptionalEmpty,
}

impl PreflightSlotSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Env => "env",
            Self::Missing => "missing",
            Self::OptionalEmpty => "optional-empty",
        }
    }
}

impl VerifyReport {
    pub fn success(&self) -> bool {
        self.outcome == Outcome::Success
    }
}

impl VerifyPreflightReport {
    pub fn ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

pub fn verify_recipe_with_process_env(
    recipe: &Recipe,
    options: VerifyOptions,
) -> Result<VerifyReport> {
    verify_recipe_with_env(recipe, options, |name| std::env::var(name).ok())
}

pub fn verify_recipe_preflight_with_process_env(
    recipe: &Recipe,
    options: VerifyOptions,
) -> VerifyPreflightReport {
    verify_recipe_preflight_with_env(recipe, options, |name| std::env::var(name).ok())
}

pub fn verify_recipe_preflight_with_env<F>(
    recipe: &Recipe,
    options: VerifyOptions,
    env: F,
) -> VerifyPreflightReport
where
    F: Fn(&str) -> Option<String>,
{
    let mut report = VerifyPreflightReport {
        recipe_name: recipe.name.clone(),
        method: recipe.method.to_ascii_uppercase(),
        sanitized_url_template: sanitized_agent_url_template(recipe),
        auth_style: recipe.auth_style.label().to_string(),
        body_kind: body_kind_label(&recipe.body_template).to_string(),
        mutating_method: is_mutating_method(&recipe.method),
        allow_mutating: options.allow_mutating,
        would_execute_http: false,
        required_env: Vec::new(),
        required_slots: Vec::new(),
        blockers: Vec::new(),
    };

    if report.mutating_method && !options.allow_mutating {
        report
            .blockers
            .push("mutating method requires --allow-mutating".to_string());
    }

    validate_url_template_for_preflight(recipe, &env, &mut report);
    validate_auth_for_preflight(recipe, &env, &mut report);
    validate_headers_for_preflight(recipe, &env, &mut report);
    validate_query_template_for_preflight(recipe, &env, &mut report);
    validate_body_for_preflight(recipe, &mut report);
    validate_slots_for_preflight(recipe, &env, &mut report);

    report
}

pub fn verify_recipe_with_env<F>(
    recipe: &Recipe,
    options: VerifyOptions,
    env: F,
) -> Result<VerifyReport>
where
    F: Fn(&str) -> Option<String>,
{
    ensure_method_allowed(&recipe.method, options.allow_mutating)?;
    let draft = prepare_draft_for_verify_with_env(recipe, &env)?;
    let settings = AppSettings::default();
    let client = build_http_client(&settings)?;
    let result = execute_request(&draft, &settings, &client);
    Ok(report_from_result(recipe, result))
}

pub fn prepare_draft_for_verify_with_env<F>(recipe: &Recipe, env: F) -> Result<RequestDraft>
where
    F: Fn(&str) -> Option<String>,
{
    let (base_url, path, mut query) = split_url_template_for_verify(&recipe.url_template, &env)?;
    query.extend(hydrate_query_template(recipe, &env)?);
    let headers = hydrate_headers(recipe, &env)?;
    let body = hydrate_body(&recipe.body_template)?;
    let slots = hydrate_slots(recipe, &env)?;

    let draft = RequestDraft {
        operation_id: format!("verify-{}", recipe.id.unwrap_or_default()),
        name: recipe.name.clone(),
        method: recipe.method.clone(),
        base_url: Some(base_url),
        path,
        headers,
        query,
        body,
        auth: recipe.auth_style.clone(),
        slots,
        evidence: Vec::new(),
        confidence: FieldConfidence {
            overall: Confidence::High,
            notes: "Loaded from recipe JSON for local verification".to_string(),
        },
        response_schema: None,
        unsupported_reason: None,
        source_kinds: Vec::new(),
    };
    ensure_no_redacted_values(&draft)?;
    Ok(draft)
}

pub fn slot_env_name(slot_name: &str) -> String {
    format!("FIRSTCALL_SLOT_{}", env_var_from_name(slot_name, "VALUE"))
}

pub fn secret_env_name(key: &str, value: &str) -> String {
    if key.eq_ignore_ascii_case("authorization") && value.to_ascii_lowercase().contains("bearer") {
        return "FIRSTCALL_BEARER_TOKEN".to_string();
    }
    let lower = key.to_ascii_lowercase();
    if lower.contains("api") {
        return "FIRSTCALL_API_KEY".to_string();
    }
    format!("FIRSTCALL_{}", env_var_from_name(key, "SECRET"))
}

pub fn redacted_recipe_for_verify_output(recipe: &Recipe) -> Recipe {
    let mut output = recipe.clone();
    output.url_template = redact_url_template_query(&output.url_template);
    output.headers_template = output
        .headers_template
        .iter()
        .map(redact_header_field)
        .collect();
    output.query_template = output
        .query_template
        .iter()
        .map(redact_key_value_field)
        .collect();
    output.body_template = redact_body_template(&output.body_template);
    output.slots = output.slots.iter().map(redact_slot).collect();
    output
}

fn report_from_result(recipe: &Recipe, result: ExecutionResult) -> VerifyReport {
    let status = result
        .response_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.status);
    let mut updated_recipe = redacted_recipe_for_verify_output(recipe);
    let verified_at = if result.outcome == Outcome::Success {
        let now = Utc::now();
        updated_recipe.last_success_at = Some(now);
        updated_recipe.last_success_status = status;
        Some(now)
    } else {
        None
    };

    VerifyReport {
        recipe_name: recipe.name.clone(),
        method: recipe.method.to_ascii_uppercase(),
        sanitized_url_template: sanitized_agent_url_template(recipe),
        status,
        outcome: result.outcome,
        blocker: result.blocker,
        verified_at,
        updated_recipe,
    }
}

fn validate_url_template_for_preflight<F>(
    recipe: &Recipe,
    env: &F,
    report: &mut VerifyPreflightReport,
) where
    F: Fn(&str) -> Option<String>,
{
    let (without_fragment, _) = recipe
        .url_template
        .split_once('#')
        .map_or((recipe.url_template.as_str(), None), |(before, after)| {
            (before, Some(after))
        });
    let Some(scheme_end) = without_fragment.find("://") else {
        report
            .blockers
            .push("URL template must be absolute".to_string());
        return;
    };
    let authority_start = scheme_end + 3;
    let rest_start = without_fragment[authority_start..]
        .find(['/', '?'])
        .map(|index| authority_start + index)
        .unwrap_or(without_fragment.len());
    let base_url = &without_fragment[..rest_start];
    if Url::parse(&format!("{base_url}/")).is_err() {
        report
            .blockers
            .push("URL template must include a valid absolute base URL".to_string());
        return;
    }

    let rest = &without_fragment[rest_start..];
    let (path, query) = if rest.is_empty() {
        ("/", None)
    } else if let Some(query) = rest.strip_prefix('?') {
        ("/", Some(query))
    } else if let Some((path, query)) = rest.split_once('?') {
        (path, Some(query))
    } else {
        (rest, None)
    };

    if is_redacted(path) {
        report
            .blockers
            .push("URL path contains redacted values and cannot be verified".to_string());
    }
    if let Some(query) = query {
        validate_url_query_for_preflight(query, env, report);
    }
}

fn validate_url_query_for_preflight<F>(query: &str, env: &F, report: &mut VerifyPreflightReport)
where
    F: Fn(&str) -> Option<String>,
{
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part
            .split_once('=')
            .map_or((part, ""), |(key, value)| (key, value));
        if is_secret_key(key) {
            add_required_env(
                report,
                secret_env_name(key, value),
                env_status(env, &secret_env_name(key, value)),
            );
        } else if is_redacted(value) {
            report.blockers.push(format!(
                "URL query parameter {key} contains redacted values and cannot be verified"
            ));
        }
    }
}

fn validate_auth_for_preflight<F>(recipe: &Recipe, env: &F, report: &mut VerifyPreflightReport)
where
    F: Fn(&str) -> Option<String>,
{
    match &recipe.auth_style {
        AuthStyle::None => {}
        AuthStyle::Bearer { .. } => {
            add_required_env(
                report,
                "FIRSTCALL_BEARER_TOKEN".to_string(),
                env_status(env, "FIRSTCALL_BEARER_TOKEN"),
            );
        }
        AuthStyle::Basic { .. } => {
            add_required_env(
                report,
                "FIRSTCALL_USERNAME".to_string(),
                env_status(env, "FIRSTCALL_USERNAME"),
            );
            add_required_env(
                report,
                "FIRSTCALL_PASSWORD".to_string(),
                env_status(env, "FIRSTCALL_PASSWORD"),
            );
        }
        AuthStyle::HeaderApiKey { .. } | AuthStyle::QueryApiKey { .. } => {
            add_required_env(
                report,
                "FIRSTCALL_API_KEY".to_string(),
                env_status(env, "FIRSTCALL_API_KEY"),
            );
        }
    }
}

fn validate_headers_for_preflight<F>(recipe: &Recipe, env: &F, report: &mut VerifyPreflightReport)
where
    F: Fn(&str) -> Option<String>,
{
    for header in &recipe.headers_template {
        if is_auth_generated_header(&recipe.auth_style, &header.key) {
            continue;
        }
        if is_secret_key(&header.key) {
            let env_name = secret_env_name(&header.key, &header.value);
            add_required_env(report, env_name.clone(), env_status(env, &env_name));
        } else if is_redacted(&header.value) {
            report.blockers.push(format!(
                "header {} contains redacted values and cannot be verified",
                header.key
            ));
        }
    }
}

fn validate_query_template_for_preflight<F>(
    recipe: &Recipe,
    env: &F,
    report: &mut VerifyPreflightReport,
) where
    F: Fn(&str) -> Option<String>,
{
    for item in &recipe.query_template {
        if is_auth_generated_query_param(&recipe.auth_style, &item.key) {
            continue;
        }
        if is_secret_key(&item.key) {
            let env_name = secret_env_name(&item.key, &item.value);
            add_required_env(report, env_name.clone(), env_status(env, &env_name));
        } else if is_redacted(&item.value) {
            report.blockers.push(format!(
                "query parameter {} contains redacted values and cannot be verified",
                item.key
            ));
        }
    }
}

fn validate_body_for_preflight(recipe: &Recipe, report: &mut VerifyPreflightReport) {
    if body_contains_redacted(&recipe.body_template) {
        report
            .blockers
            .push("body template contains redacted values and cannot be verified".to_string());
    }
}

fn validate_slots_for_preflight<F>(recipe: &Recipe, env: &F, report: &mut VerifyPreflightReport)
where
    F: Fn(&str) -> Option<String>,
{
    for slot in &recipe.slots {
        if slot.location == SlotLocation::Auth {
            continue;
        }
        let current = slot.current_value.as_deref().unwrap_or("").trim();
        let can_use_current =
            !current.is_empty() && !is_redacted(current) && !is_secret_key(&slot.name);
        let source = if can_use_current {
            PreflightSlotSource::Current
        } else {
            let env_name = slot_env_name(&slot.name);
            match env_status(env, &env_name) {
                PreflightValueStatus::Set => {
                    if slot.required {
                        add_required_env(report, env_name, PreflightValueStatus::Set);
                    }
                    PreflightSlotSource::Env
                }
                PreflightValueStatus::Missing if slot.required => {
                    add_required_env(report, env_name.clone(), PreflightValueStatus::Missing);
                    report.blockers.push(format!(
                        "missing required slot value: {} (env {env_name})",
                        slot.name
                    ));
                    PreflightSlotSource::Missing
                }
                PreflightValueStatus::Missing => PreflightSlotSource::OptionalEmpty,
            }
        };
        report.required_slots.push(PreflightSlot {
            name: slot.name.clone(),
            location: slot.location.label().to_string(),
            required: slot.required,
            source,
        });
    }
}

fn add_required_env(
    report: &mut VerifyPreflightReport,
    name: String,
    status: PreflightValueStatus,
) {
    if !report.required_env.iter().any(|item| item.name == name) {
        report.required_env.push(PreflightEnv {
            name: name.clone(),
            status,
        });
    }
    if status == PreflightValueStatus::Missing {
        let message = format!("missing required environment variable: {name}");
        if !report.blockers.iter().any(|item| item == &message) {
            report.blockers.push(message);
        }
    }
}

fn env_status<F>(env: &F, name: &str) -> PreflightValueStatus
where
    F: Fn(&str) -> Option<String>,
{
    if env(name).is_some_and(|value| !value.trim().is_empty()) {
        PreflightValueStatus::Set
    } else {
        PreflightValueStatus::Missing
    }
}

fn body_kind_label(body: &BodyTemplate) -> &'static str {
    match body {
        BodyTemplate::None => "none",
        BodyTemplate::Json { .. } => "json",
        BodyTemplate::Text { .. } => "text",
        BodyTemplate::Form { .. } => "form",
        BodyTemplate::Multipart { .. } => "multipart",
    }
}

fn is_mutating_method(method: &str) -> bool {
    !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
}

fn ensure_method_allowed(method: &str, allow_mutating: bool) -> Result<()> {
    let upper = method.to_ascii_uppercase();
    if allow_mutating || matches!(upper.as_str(), "GET" | "HEAD") {
        return Ok(());
    }
    bail!("Refusing to verify {upper} without --allow-mutating");
}

fn split_url_template_for_verify<F>(
    url_template: &str,
    env: &F,
) -> Result<(String, String, Vec<KeyValueField>)>
where
    F: Fn(&str) -> Option<String>,
{
    let (without_fragment, _) = url_template
        .split_once('#')
        .map_or((url_template, None), |(before, after)| {
            (before, Some(after))
        });
    let scheme_end = without_fragment
        .find("://")
        .context("Recipe URL template must be absolute")?;
    let authority_start = scheme_end + 3;
    let rest_start = without_fragment[authority_start..]
        .find(['/', '?'])
        .map(|index| authority_start + index)
        .unwrap_or(without_fragment.len());
    let base_url = without_fragment[..rest_start].to_string();
    Url::parse(&format!("{base_url}/"))
        .with_context(|| "Recipe URL template must include a valid absolute base URL")?;

    let rest = &without_fragment[rest_start..];
    let (path, query) = if rest.is_empty() {
        ("/".to_string(), None)
    } else if let Some(query) = rest.strip_prefix('?') {
        ("/".to_string(), Some(query))
    } else if let Some((path, query)) = rest.split_once('?') {
        (path.to_string(), Some(query))
    } else {
        (rest.to_string(), None)
    };

    let query = query
        .map(|value| hydrate_query_pairs(value, env))
        .transpose()?
        .unwrap_or_default();
    Ok((base_url, path, query))
}

fn hydrate_query_pairs<F>(query: &str, env: &F) -> Result<Vec<KeyValueField>>
where
    F: Fn(&str) -> Option<String>,
{
    if query.is_empty() {
        return Ok(Vec::new());
    }

    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part
                .split_once('=')
                .map_or((part, ""), |(key, value)| (key, value));
            Ok(KeyValueField {
                key: key.to_string(),
                value: hydrate_static_value("URL query parameter", key, value, env)?,
                required: true,
                description: "URL query parameter from recipe URL template".to_string(),
                confidence: Confidence::High,
            })
        })
        .collect()
}

fn hydrate_query_template<F>(recipe: &Recipe, env: &F) -> Result<Vec<KeyValueField>>
where
    F: Fn(&str) -> Option<String>,
{
    recipe
        .query_template
        .iter()
        .filter(|item| !is_auth_generated_query_param(&recipe.auth_style, &item.key))
        .map(|item| {
            let mut hydrated = item.clone();
            hydrated.value = hydrate_static_value("query parameter", &item.key, &item.value, env)?;
            Ok(hydrated)
        })
        .collect()
}

fn hydrate_headers<F>(recipe: &Recipe, env: &F) -> Result<Vec<HeaderField>>
where
    F: Fn(&str) -> Option<String>,
{
    recipe
        .headers_template
        .iter()
        .filter(|header| !is_auth_generated_header(&recipe.auth_style, &header.key))
        .map(|header| {
            let mut hydrated = header.clone();
            hydrated.value = hydrate_static_value("header", &header.key, &header.value, env)?;
            Ok(hydrated)
        })
        .collect()
}

fn hydrate_static_value<F>(label: &str, key: &str, value: &str, env: &F) -> Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    if is_secret_key(key) {
        let env_name = secret_env_name(key, value);
        return env_value(env, &env_name);
    }
    if is_redacted(value) {
        bail!("{label} {key} is redacted and cannot be verified");
    }
    Ok(value.to_string())
}

fn hydrate_body(body: &BodyTemplate) -> Result<BodyTemplate> {
    if body_contains_redacted(body) {
        bail!("Body template contains redacted values and cannot be verified");
    }
    Ok(body.clone())
}

fn hydrate_slots<F>(recipe: &Recipe, env: &F) -> Result<Vec<RuntimeSlot>>
where
    F: Fn(&str) -> Option<String>,
{
    let mut slots = Vec::new();
    for slot in &recipe.slots {
        if slot.location == SlotLocation::Auth {
            continue;
        }
        let mut hydrated = slot.clone();
        let current = hydrated.current_value.as_deref().unwrap_or("").trim();
        let can_use_current =
            !current.is_empty() && !is_redacted(current) && !is_secret_key(&hydrated.name);
        if !can_use_current {
            let env_name = slot_env_name(&hydrated.name);
            match env(&env_name) {
                Some(value) => hydrated.current_value = Some(value),
                None if hydrated.required => {
                    bail!("Missing required environment variable: {env_name}");
                }
                None => hydrated.current_value = None,
            }
        }
        slots.push(hydrated);
    }
    hydrate_auth_slots(&mut slots, &recipe.auth_style, env)?;
    Ok(slots)
}

fn hydrate_auth_slots<F>(slots: &mut Vec<RuntimeSlot>, auth: &AuthStyle, env: &F) -> Result<()>
where
    F: Fn(&str) -> Option<String>,
{
    match auth {
        AuthStyle::None => {}
        AuthStyle::Bearer { token_slot, .. } => set_or_add_slot(
            slots,
            token_slot,
            SlotLocation::Auth,
            env_value(env, "FIRSTCALL_BEARER_TOKEN")?,
        ),
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => {
            set_or_add_slot(
                slots,
                username_slot,
                SlotLocation::Auth,
                env_value(env, "FIRSTCALL_USERNAME")?,
            );
            set_or_add_slot(
                slots,
                password_slot,
                SlotLocation::Auth,
                env_value(env, "FIRSTCALL_PASSWORD")?,
            );
        }
        AuthStyle::HeaderApiKey { slot_name, .. } | AuthStyle::QueryApiKey { slot_name, .. } => {
            set_or_add_slot(
                slots,
                slot_name,
                SlotLocation::Auth,
                env_value(env, "FIRSTCALL_API_KEY")?,
            );
        }
    }
    Ok(())
}

fn set_or_add_slot(
    slots: &mut Vec<RuntimeSlot>,
    name: &str,
    location: SlotLocation,
    value: String,
) {
    if let Some(slot) = slots
        .iter_mut()
        .find(|slot| slot.name == name && slot.location == location)
    {
        slot.current_value = Some(value);
        return;
    }
    slots.push(RuntimeSlot {
        name: name.to_string(),
        location,
        required: true,
        current_value: Some(value),
        description: String::new(),
        confidence: Confidence::High,
    });
}

fn env_value<F>(env: &F, name: &str) -> Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    env(name)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("Missing required environment variable: {name}"))
}

fn ensure_no_redacted_values(draft: &RequestDraft) -> Result<()> {
    if is_redacted(&draft.path) {
        bail!("URL path contains redacted values and cannot be verified");
    }
    for header in &draft.headers {
        if is_redacted(&header.value) {
            bail!(
                "Header {} contains redacted values and cannot be verified",
                header.key
            );
        }
    }
    for query in &draft.query {
        if is_redacted(&query.value) {
            bail!(
                "Query parameter {} contains redacted values and cannot be verified",
                query.key
            );
        }
    }
    if body_contains_redacted(&draft.body) {
        bail!("Body template contains redacted values and cannot be verified");
    }
    for slot in &draft.slots {
        if slot.current_value.as_deref().is_some_and(is_redacted) {
            bail!(
                "Slot {} contains redacted values and cannot be verified",
                slot.name
            );
        }
    }
    Ok(())
}

fn is_auth_generated_header(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::Bearer { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::Basic { .. } => key.eq_ignore_ascii_case("authorization"),
        AuthStyle::HeaderApiKey { header_name, .. } => header_name.eq_ignore_ascii_case(key),
        AuthStyle::None | AuthStyle::QueryApiKey { .. } => false,
    }
}

fn is_auth_generated_query_param(auth: &AuthStyle, key: &str) -> bool {
    match auth {
        AuthStyle::QueryApiKey { param_name, .. } => param_name.eq_ignore_ascii_case(key),
        AuthStyle::None
        | AuthStyle::Bearer { .. }
        | AuthStyle::Basic { .. }
        | AuthStyle::HeaderApiKey { .. } => false,
    }
}

fn env_var_from_name(name: &str, fallback: &str) -> String {
    let mut output = String::new();
    let mut previous_underscore = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_uppercase());
            previous_underscore = false;
        } else if !previous_underscore {
            output.push('_');
            previous_underscore = true;
        }
    }
    let trimmed = output.trim_matches('_').to_string();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

fn is_redacted(value: &str) -> bool {
    value.contains(REDACTED)
}

fn body_contains_redacted(body: &BodyTemplate) -> bool {
    match body {
        BodyTemplate::None => false,
        BodyTemplate::Json { template } => is_redacted(template),
        BodyTemplate::Text { text } => is_redacted(text),
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields } => {
            fields.iter().any(|field| is_redacted(&field.value))
        }
    }
}

fn redact_header_field(field: &HeaderField) -> HeaderField {
    let mut field = field.clone();
    field.value = redact_header_value(&field.key, &field.value);
    field
}

fn redact_key_value_field(field: &KeyValueField) -> KeyValueField {
    let mut field = field.clone();
    if is_secret_key(&field.key) {
        field.value = REDACTED.to_string();
    }
    field
}

fn redact_slot(slot: &RuntimeSlot) -> RuntimeSlot {
    let mut slot = slot.clone();
    if (slot.location == SlotLocation::Auth || is_secret_key(&slot.name))
        && slot.current_value.is_some()
    {
        slot.current_value = Some(REDACTED.to_string());
    }
    slot
}

fn redact_body_template(body: &BodyTemplate) -> BodyTemplate {
    match body {
        BodyTemplate::None => BodyTemplate::None,
        BodyTemplate::Json { template } => BodyTemplate::Json {
            template: redact_body(template, Some("application/json")),
        },
        BodyTemplate::Text { text } => BodyTemplate::Text {
            text: redact_body(text, None),
        },
        BodyTemplate::Form { fields } => BodyTemplate::Form {
            fields: fields.iter().map(redact_key_value_field).collect(),
        },
        BodyTemplate::Multipart { fields } => BodyTemplate::Multipart {
            fields: fields.iter().map(redact_key_value_field).collect(),
        },
    }
}

fn redact_url_template_query(url_template: &str) -> String {
    let (without_fragment, fragment) = url_template
        .split_once('#')
        .map_or((url_template, None), |(before, after)| {
            (before, Some(after))
        });
    let Some((base, query)) = without_fragment.split_once('?') else {
        return url_template.to_string();
    };
    let redacted_query = query
        .split('&')
        .map(|part| {
            let Some((key, value)) = part.split_once('=') else {
                return part.to_string();
            };
            if is_secret_key(key) {
                format!("{key}={REDACTED}")
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    let mut output = format!("{base}?{redacted_query}");
    if let Some(fragment) = fragment {
        output.push('#');
        output.push_str(fragment);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};

    use super::{
        VerifyOptions, prepare_draft_for_verify_with_env, redacted_recipe_for_verify_output,
        secret_env_name, slot_env_name, verify_recipe_preflight_with_env,
    };
    use crate::exec::redact::redact_draft_for_storage;
    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, HeaderField, KeyValueField, Recipe, RuntimeSlot,
        SlotLocation,
    };

    const RAW_SECRET: &str = "raw_secret_for_unit_test";

    #[test]
    fn maps_verify_env_names() {
        assert_eq!(slot_env_name("user_id"), "FIRSTCALL_SLOT_USER_ID");
        assert_eq!(slot_env_name("email"), "FIRSTCALL_SLOT_EMAIL");
        assert_eq!(secret_env_name("api_key", ""), "FIRSTCALL_API_KEY");
        assert_eq!(
            secret_env_name("access_token", ""),
            "FIRSTCALL_ACCESS_TOKEN"
        );
    }

    #[test]
    fn resolves_recipe_with_injected_env_and_redacts_output() {
        let recipe = fake_recipe();
        let mut env = BTreeMap::new();
        env.insert("FIRSTCALL_BEARER_TOKEN".to_string(), RAW_SECRET.to_string());
        env.insert("FIRSTCALL_API_KEY".to_string(), RAW_SECRET.to_string());
        env.insert("FIRSTCALL_SLOT_USER_ID".to_string(), "user_123".to_string());

        let draft = prepare_draft_for_verify_with_env(&recipe, |name| env.get(name).cloned())
            .expect("draft");
        let serialized_draft =
            serde_json::to_string(&redact_draft_for_storage(&draft)).expect("draft json");
        let redacted_recipe = serde_json::to_string(&redacted_recipe_for_verify_output(&recipe))
            .expect("recipe json");

        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(draft.path, "/users/{{user_id}}");
        assert!(draft.query.iter().any(|item| item.key == "api_key"));
        assert!(!serialized_draft.contains(RAW_SECRET));
        assert!(!redacted_recipe.contains(RAW_SECRET));
    }

    #[test]
    fn preflight_discards_env_values_from_report() {
        let recipe = fake_recipe();
        let mut env = BTreeMap::new();
        env.insert("FIRSTCALL_BEARER_TOKEN".to_string(), RAW_SECRET.to_string());
        env.insert("FIRSTCALL_API_KEY".to_string(), RAW_SECRET.to_string());
        env.insert("FIRSTCALL_SLOT_USER_ID".to_string(), RAW_SECRET.to_string());

        let report = verify_recipe_preflight_with_env(&recipe, VerifyOptions::default(), |name| {
            env.get(name).cloned()
        });
        let debug = format!("{report:?}");
        let blockers = report.blockers.join("\n");

        assert!(report.ready(), "blockers: {:?}", report.blockers);
        assert!(!debug.contains(RAW_SECRET));
        assert!(!blockers.contains(RAW_SECRET));
    }

    fn fake_recipe() -> Recipe {
        Recipe {
            id: None,
            name: "Verify User".to_string(),
            method: "GET".to_string(),
            url_template: "https://api.example.com/users/{{user_id}}?api_key=<redacted>"
                .to_string(),
            headers_template: vec![HeaderField {
                key: "Authorization".to_string(),
                value: "Bearer <redacted>".to_string(),
                required: true,
                description: String::new(),
                confidence: Confidence::High,
            }],
            query_template: vec![KeyValueField {
                key: "q".to_string(),
                value: "{{user_id}}".to_string(),
                required: false,
                description: String::new(),
                confidence: Confidence::High,
            }],
            body_template: BodyTemplate::None,
            auth_style: AuthStyle::Bearer {
                token_slot: "bearer_token".to_string(),
                header_name: "Authorization".to_string(),
            },
            slots: vec![
                RuntimeSlot {
                    name: "user_id".to_string(),
                    location: SlotLocation::Path,
                    required: true,
                    current_value: None,
                    description: String::new(),
                    confidence: Confidence::High,
                },
                RuntimeSlot {
                    name: "bearer_token".to_string(),
                    location: SlotLocation::Auth,
                    required: true,
                    current_value: Some("<redacted>".to_string()),
                    description: String::new(),
                    confidence: Confidence::High,
                },
            ],
            last_success_at: Some(verified_time()),
            last_success_status: Some(200),
        }
    }

    fn verified_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-04-29T00:00:00Z")
            .expect("time")
            .with_timezone(&Utc)
    }
}
