use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Curl,
    Docs,
    OpenApi,
    PostmanCollection,
    Har,
    HttpFile,
    Hurl,
    Bruno,
    Graphql,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInput {
    pub kind: SourceKind,
    pub raw_text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldConfidence {
    pub overall: Confidence,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceItem {
    pub source_kind: SourceKind,
    pub label: String,
    pub detail: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderField {
    pub key: String,
    pub value: String,
    pub required: bool,
    pub description: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyValueField {
    pub key: String,
    pub value: String,
    pub required: bool,
    pub description: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyTemplate {
    None,
    Json { template: String },
    Text { text: String },
    Form { fields: Vec<KeyValueField> },
    Multipart { fields: Vec<KeyValueField> },
}

impl BodyTemplate {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Json { .. } => "json",
            Self::Text { .. } => "text",
            Self::Form { .. } => "x-www-form-urlencoded",
            Self::Multipart { .. } => "multipart",
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Json { template } => Some(template),
            Self::Text { text } => Some(text),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthStyle {
    None,
    Bearer {
        token_slot: String,
        header_name: String,
    },
    Basic {
        username_slot: String,
        password_slot: String,
    },
    HeaderApiKey {
        header_name: String,
        slot_name: String,
    },
    QueryApiKey {
        param_name: String,
        slot_name: String,
    },
}

impl AuthStyle {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
            Self::HeaderApiKey { .. } => "header api key",
            Self::QueryApiKey { .. } => "query api key",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SlotLocation {
    Path,
    Query,
    Header,
    Body,
    Auth,
}

impl SlotLocation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Body => "body",
            Self::Auth => "auth",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSlot {
    pub name: String,
    pub location: SlotLocation,
    pub required: bool,
    pub current_value: Option<String>,
    pub description: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaSpec {
    pub name: Option<String>,
    pub schema: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RequestDraft {
    pub operation_id: String,
    pub name: String,
    pub method: String,
    pub base_url: Option<String>,
    pub path: String,
    pub headers: Vec<HeaderField>,
    pub query: Vec<KeyValueField>,
    pub body: BodyTemplate,
    pub auth: AuthStyle,
    pub slots: Vec<RuntimeSlot>,
    pub evidence: Vec<EvidenceItem>,
    pub confidence: FieldConfidence,
    pub response_schema: Option<SchemaSpec>,
    pub unsupported_reason: Option<String>,
    pub source_kinds: Vec<SourceKind>,
}

impl RequestDraft {
    pub fn endpoint_summary(&self) -> String {
        let base = self
            .base_url
            .clone()
            .unwrap_or_else(|| "<base-url>".to_string());
        format!(
            "{} {}{}",
            self.method.to_uppercase(),
            base.trim_end_matches('/'),
            if self.path.starts_with('/') {
                self.path.clone()
            } else {
                format!("/{}", self.path)
            }
        )
    }

    pub fn unresolved_slots(&self) -> Vec<&RuntimeSlot> {
        self.slots
            .iter()
            .filter(|slot| {
                slot.required
                    && slot
                        .current_value
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .is_empty()
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderedHeader {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<RenderedHeader>,
    pub body_preview: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseSnapshot {
    pub status: Option<u16>,
    pub headers: Vec<RenderedHeader>,
    pub body_preview: String,
    #[serde(default)]
    pub body_truncated: bool,
    #[serde(default)]
    pub bytes_read: usize,
    pub elapsed_ms: u128,
    pub validation_errors: Vec<String>,
    pub transport_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Partial,
    Failure,
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Partial => "partial",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Blocker {
    AuthBlocked,
    MissingRuntimeValue,
    DocsUnclear,
    UnsupportedInput,
    NetworkBlocked,
    ResourceLimitExceeded,
    SchemaMismatch,
    UnknownFailure,
}

impl Blocker {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AuthBlocked => "auth_blocked",
            Self::MissingRuntimeValue => "missing_runtime_value",
            Self::DocsUnclear => "docs_unclear",
            Self::UnsupportedInput => "unsupported_input",
            Self::NetworkBlocked => "network_blocked",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::SchemaMismatch => "schema_mismatch",
            Self::UnknownFailure => "unknown_failure",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RequestAttempt {
    pub id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub source_inputs: Vec<SourceInput>,
    pub request_draft_snapshot: RequestDraft,
    pub rendered_request_redacted: RenderedRequest,
    pub response_snapshot_redacted: Option<ResponseSnapshot>,
    pub outcome: Outcome,
    pub blocker: Option<Blocker>,
    pub notes: String,
    pub evidence_summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipe {
    pub id: Option<i64>,
    pub name: String,
    pub method: String,
    pub url_template: String,
    pub headers_template: Vec<HeaderField>,
    pub query_template: Vec<KeyValueField>,
    pub body_template: BodyTemplate,
    pub auth_style: AuthStyle,
    pub slots: Vec<RuntimeSlot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<SchemaSpec>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_success_status: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppSettings {
    pub timeout_secs: u64,
    pub response_preview_limit_bytes: usize,
    #[serde(default = "default_response_body_limit_bytes")]
    pub response_body_limit_bytes: usize,
    pub success_status_min: u16,
    pub success_status_max: u16,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            response_preview_limit_bytes: 131_072,
            response_body_limit_bytes: default_response_body_limit_bytes(),
            success_status_min: 200,
            success_status_max: 299,
        }
    }
}

fn default_response_body_limit_bytes() -> usize {
    1_048_576
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttemptListItem {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub method: String,
    pub endpoint: String,
    pub http_status: Option<u16>,
    pub outcome: Outcome,
    pub blocker: Option<Blocker>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipeListItem {
    pub id: i64,
    pub name: String,
    pub method: String,
    pub url_template: String,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_success_status: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ParsedSource {
    pub source: SourceInput,
    pub candidates: Vec<RequestDraft>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExecutionResult {
    pub rendered_request: RenderedRequest,
    pub response_snapshot: Option<ResponseSnapshot>,
    pub outcome: Outcome,
    pub blocker: Option<Blocker>,
    pub notes: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AppSettings, Recipe, SchemaSpec};

    const LEGACY_RECIPE_JSON: &str = r#"{
        "id": null,
        "name": "Legacy recipe",
        "method": "GET",
        "url_template": "https://api.example.com/users",
        "headers_template": [],
        "query_template": [],
        "body_template": "none",
        "auth_style": "none",
        "slots": [],
        "last_success_at": null,
        "last_success_status": null
    }"#;

    #[test]
    fn schema_spec_implements_eq() {
        fn assert_eq<T: Eq>() {}
        assert_eq::<SchemaSpec>();
    }

    #[test]
    fn legacy_recipe_deserializes_without_response_schema() {
        let recipe: Recipe = serde_json::from_str(LEGACY_RECIPE_JSON).expect("legacy recipe");

        assert!(recipe.response_schema.is_none());
        let serialized = serde_json::to_value(&recipe).expect("serialize recipe");
        assert!(serialized.get("response_schema").is_none());
    }

    #[test]
    fn recipe_response_schema_round_trips() {
        let mut recipe: Recipe = serde_json::from_str(LEGACY_RECIPE_JSON).expect("legacy recipe");
        recipe.response_schema = Some(SchemaSpec {
            name: Some("response".to_string()),
            schema: json!({
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string" } }
            }),
        });

        let serialized = serde_json::to_string(&recipe).expect("serialize recipe");
        let round_trip: Recipe = serde_json::from_str(&serialized).expect("round-trip recipe");

        assert_eq!(round_trip, recipe);
    }

    #[test]
    fn legacy_settings_receive_a_bounded_response_default() {
        let settings: AppSettings = serde_json::from_value(json!({
            "timeout_secs": 30,
            "response_preview_limit_bytes": 131072,
            "success_status_min": 200,
            "success_status_max": 299
        }))
        .expect("legacy settings");

        assert_eq!(settings.response_body_limit_bytes, 1_048_576);
        assert!(settings.response_preview_limit_bytes <= settings.response_body_limit_bytes);
    }
}
