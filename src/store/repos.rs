use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

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
        let payload = serde_json::to_string(recipe)?;
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
    use chrono::Utc;
    use tempfile::tempdir;

    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, FieldConfidence, RequestAttempt, RequestDraft,
        ResponseSnapshot, SourceInput, SourceKind,
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
}
