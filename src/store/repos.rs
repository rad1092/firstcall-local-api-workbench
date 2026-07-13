use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

use crate::exec::redact::sanitize_response_schema;
use crate::model::{
    AppSettings, AttemptListItem, Blocker, Outcome, Recipe, RecipeListItem, RequestAttempt,
};

pub struct AppRepository {
    connection: Connection,
}

impl AppRepository {
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        let payload = serde_json::to_string(settings)?;
        self.connection.execute(
            "INSERT INTO settings(id, payload_json) VALUES(1, ?1)
             ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
            params![payload],
        )?;
        Ok(())
    }

    pub fn load_settings(&self) -> Result<AppSettings> {
        let payload: Option<String> = self
            .connection
            .query_row(
                "SELECT payload_json FROM settings WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match payload {
            Some(payload) => Ok(serde_json::from_str(&payload)?),
            None => Ok(AppSettings::default()),
        }
    }

    pub fn insert_attempt(&self, attempt: &RequestAttempt) -> Result<i64> {
        let payload = serde_json::to_string(attempt)?;
        let response_status = attempt
            .response_snapshot_redacted
            .as_ref()
            .and_then(|response| response.status);
        self.connection.execute(
            "INSERT INTO attempts(created_at, method, endpoint, http_status, outcome, blocker, payload_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                attempt.created_at.to_rfc3339(),
                attempt.request_draft_snapshot.method,
                endpoint_from_attempt(attempt),
                response_status,
                attempt.outcome.label(),
                attempt.blocker.as_ref().map(Blocker::label),
                payload,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn list_attempts(&self) -> Result<Vec<AttemptListItem>> {
        let mut statement = self.connection.prepare(
            "SELECT id, created_at, method, endpoint, http_status, outcome, blocker
             FROM attempts
             ORDER BY id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let created_at: String = row.get(1)?;
            Ok(AttemptListItem {
                id: row.get(0)?,
                created_at: parse_datetime(&created_at),
                method: row.get(2)?,
                endpoint: row.get(3)?,
                http_status: row.get(4)?,
                outcome: parse_outcome(&row.get::<_, String>(5)?),
                blocker: row
                    .get::<_, Option<String>>(6)?
                    .as_deref()
                    .map(parse_blocker),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(anyhow::Error::from)
    }

    pub fn get_attempt(&self, id: i64) -> Result<Option<RequestAttempt>> {
        let payload: Option<String> = self
            .connection
            .query_row(
                "SELECT payload_json FROM attempts WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|payload| serde_json::from_str(&payload).context("Invalid attempt payload"))
            .transpose()
    }

    pub fn insert_recipe(&self, recipe: &Recipe) -> Result<i64> {
        let payload = safe_recipe_payload(recipe)?;
        self.connection.execute(
            "INSERT INTO recipes(name, method, url_template, last_success_at, last_success_status, payload_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                recipe.name,
                recipe.method,
                recipe.url_template,
                recipe.last_success_at.map(|value| value.to_rfc3339()),
                recipe.last_success_status,
                payload,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn update_recipe_verification(&self, id: i64, verified_recipe: &Recipe) -> Result<()> {
        // This persists verification metadata and the serialized recipe payload only.
        // Response schema annotations are sanitized defensively, but request fields are not;
        // callers must still pass an already-safe/redacted recipe.
        // Errors must not include recipe payloads, body contents, resolved secret URLs, or secret values.
        let payload = safe_recipe_payload(verified_recipe)?;
        let updated = self.connection.execute(
            "UPDATE recipes
             SET last_success_at = ?1, last_success_status = ?2, payload_json = ?3
             WHERE id = ?4",
            params![
                verified_recipe
                    .last_success_at
                    .map(|value| value.to_rfc3339()),
                verified_recipe.last_success_status,
                payload,
                id,
            ],
        )?;
        if updated == 0 {
            bail!("recipe not found: {id}");
        }
        Ok(())
    }

    pub fn list_recipes(&self) -> Result<Vec<RecipeListItem>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, method, url_template, last_success_at, last_success_status
             FROM recipes
             ORDER BY id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let last_success_at: Option<String> = row.get(4)?;
            Ok(RecipeListItem {
                id: row.get(0)?,
                name: row.get(1)?,
                method: row.get(2)?,
                url_template: row.get(3)?,
                last_success_at: last_success_at.as_deref().map(parse_datetime),
                last_success_status: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(anyhow::Error::from)
    }

    pub fn get_recipe(&self, id: i64) -> Result<Option<Recipe>> {
        let payload: Option<String> = self
            .connection
            .query_row(
                "SELECT payload_json FROM recipes WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|payload| serde_json::from_str(&payload).context("Invalid recipe payload"))
            .transpose()
    }
}

fn safe_recipe_payload(recipe: &Recipe) -> Result<String> {
    let mut safe = recipe.clone();
    safe.response_schema = recipe
        .response_schema
        .as_ref()
        .map(sanitize_response_schema);
    serde_json::to_string(&safe).map_err(anyhow::Error::from)
}

fn endpoint_from_attempt(attempt: &RequestAttempt) -> String {
    attempt.rendered_request_redacted.url.clone()
}

fn parse_datetime(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_outcome(value: &str) -> Outcome {
    match value {
        "success" => Outcome::Success,
        "partial" => Outcome::Partial,
        _ => Outcome::Failure,
    }
}

fn parse_blocker(value: &str) -> Blocker {
    match value {
        "auth_blocked" => Blocker::AuthBlocked,
        "missing_runtime_value" => Blocker::MissingRuntimeValue,
        "docs_unclear" => Blocker::DocsUnclear,
        "unsupported_input" => Blocker::UnsupportedInput,
        "network_blocked" => Blocker::NetworkBlocked,
        "schema_mismatch" => Blocker::SchemaMismatch,
        _ => Blocker::UnknownFailure,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use tempfile::tempdir;

    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, FieldConfidence, Recipe, RequestAttempt, RequestDraft,
        ResponseSnapshot, SchemaSpec, SourceInput, SourceKind,
    };
    use crate::store::db::{AppPaths, open_database};

    use super::AppRepository;

    #[test]
    fn sqlite_round_trip_attempt_and_settings() {
        let root = tempdir().expect("tempdir");
        let paths = AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
            .expect("paths");
        let repo = AppRepository::new(open_database(&paths).expect("db"));
        repo.save_settings(&crate::model::AppSettings::default())
            .expect("settings save");

        let draft = RequestDraft {
            operation_id: "op".to_string(),
            name: "Demo".to_string(),
            method: "GET".to_string(),
            base_url: Some("https://api.example.com".to_string()),
            path: "/v1/customers".to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: BodyTemplate::None,
            auth: AuthStyle::None,
            slots: Vec::new(),
            evidence: Vec::new(),
            confidence: FieldConfidence {
                overall: Confidence::High,
                notes: String::new(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: vec![SourceKind::Curl],
        };
        let attempt = RequestAttempt {
            id: None,
            created_at: Utc::now(),
            source_inputs: vec![SourceInput {
                kind: SourceKind::Curl,
                raw_text: "curl https://api.example.com".to_string(),
            }],
            request_draft_snapshot: draft.clone(),
            rendered_request_redacted: crate::model::RenderedRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/v1/customers".to_string(),
                headers: Vec::new(),
                body_preview: None,
            },
            response_snapshot_redacted: Some(ResponseSnapshot {
                status: Some(200),
                headers: Vec::new(),
                body_preview: "{}".to_string(),
                body_truncated: false,
                bytes_read: 2,
                elapsed_ms: 5,
                validation_errors: Vec::new(),
                transport_error: None,
            }),
            outcome: crate::model::Outcome::Success,
            blocker: None,
            notes: "ok".to_string(),
            evidence_summary: "curl".to_string(),
        };
        let id = repo.insert_attempt(&attempt).expect("insert");
        assert!(repo.get_attempt(id).expect("fetch").is_some());
        assert!(!repo.list_attempts().expect("list").is_empty());
        assert_eq!(repo.load_settings().expect("settings").timeout_secs, 30);
    }

    #[test]
    fn updates_recipe_verification_metadata_and_payload_for_existing_recipe() {
        let root = tempdir().expect("tempdir");
        let paths = AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
            .expect("paths");
        let repo = AppRepository::new(open_database(&paths).expect("db"));

        let original = test_recipe("GET", "https://api.example.com/users/{{user_id}}", None);
        let id = repo.insert_recipe(&original).expect("insert recipe");
        let verified_at = fixed_time();
        let mut verified = test_recipe(
            "POST",
            "https://api.example.com/changed/{{user_id}}",
            Some(verified_at),
        );
        verified.name = "Changed payload name".to_string();
        verified.last_success_status = Some(204);

        repo.update_recipe_verification(id, &verified)
            .expect("update verification");

        let fetched = repo
            .get_recipe(id)
            .expect("fetch recipe")
            .expect("recipe exists");
        assert_eq!(fetched.name, "Changed payload name");
        assert_eq!(fetched.method, "POST");
        assert_eq!(
            fetched.url_template,
            "https://api.example.com/changed/{{user_id}}"
        );
        assert_eq!(fetched.last_success_at, Some(verified_at));
        assert_eq!(fetched.last_success_status, Some(204));

        let summary = repo
            .list_recipes()
            .expect("list recipes")
            .into_iter()
            .find(|item| item.id == id)
            .expect("summary");
        assert_eq!(summary.name, original.name);
        assert_eq!(summary.method, original.method);
        assert_eq!(summary.url_template, original.url_template);
        assert_eq!(summary.last_success_at, Some(verified_at));
        assert_eq!(summary.last_success_status, Some(204));
    }

    #[test]
    fn sqlite_recipe_round_trip_preserves_sanitized_response_schema() {
        let root = tempdir().expect("tempdir");
        let paths = AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
            .expect("paths");
        let repo = AppRepository::new(open_database(&paths).expect("db"));
        let mut recipe = test_recipe("GET", "https://api.example.com/users", None);
        recipe.response_schema = Some(SchemaSpec {
            name: Some("response".to_string()),
            schema: json!({
                "type": "object",
                "default": { "token": "raw_default_secret" },
                "properties": {
                    "token": { "type": "string", "enum": ["raw_enum_secret"] },
                    "id": { "type": "string" }
                }
            }),
        });

        let id = repo.insert_recipe(&recipe).expect("insert recipe");
        let fetched = repo
            .get_recipe(id)
            .expect("fetch recipe")
            .expect("recipe exists");
        let schema = fetched.response_schema.expect("response schema");

        assert!(schema.schema.get("default").is_none());
        assert!(schema.schema["properties"]["token"].get("enum").is_none());
        assert_eq!(schema.schema["properties"]["id"]["type"], "string");
    }

    #[test]
    fn updating_missing_recipe_returns_error_without_creating_recipe_or_leaking_payload() {
        const RAW_SECRET: &str = "repo_update_raw_secret_marker";

        let root = tempdir().expect("tempdir");
        let paths = AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
            .expect("paths");
        let repo = AppRepository::new(open_database(&paths).expect("db"));
        let recipe = test_recipe(
            "GET",
            &format!("https://api.example.com/users?token={RAW_SECRET}"),
            Some(fixed_time()),
        );

        let error = repo
            .update_recipe_verification(404, &recipe)
            .expect_err("missing recipe should error");
        let message = format!("{error:#}");

        assert!(message.contains("recipe not found: 404"));
        assert!(!message.contains(RAW_SECRET));
        assert!(repo.list_recipes().expect("list recipes").is_empty());
    }

    fn test_recipe(
        method: &str,
        url_template: &str,
        last_success_at: Option<DateTime<Utc>>,
    ) -> Recipe {
        Recipe {
            id: None,
            name: "Stored Recipe".to_string(),
            method: method.to_string(),
            url_template: url_template.to_string(),
            headers_template: Vec::new(),
            query_template: Vec::new(),
            body_template: BodyTemplate::None,
            auth_style: AuthStyle::None,
            slots: Vec::new(),
            response_schema: None,
            last_success_at,
            last_success_status: last_success_at.map(|_| 200),
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-06T00:00:00Z")
            .expect("fixed time")
            .with_timezone(&Utc)
    }
}
