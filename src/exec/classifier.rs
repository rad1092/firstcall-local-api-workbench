use crate::model::{AppSettings, Blocker, Outcome, ResponseSnapshot};

pub fn classify_outcome(
    preflight_blocker: Option<Blocker>,
    response: Option<&ResponseSnapshot>,
    unsupported_reason: Option<&str>,
    settings: &AppSettings,
) -> (Outcome, Option<Blocker>) {
    if let Some(blocker) = preflight_blocker {
        return (Outcome::Failure, Some(blocker));
    }

    if unsupported_reason.is_some() {
        return (Outcome::Failure, Some(Blocker::UnsupportedInput));
    }

    let Some(response) = response else {
        return (Outcome::Failure, Some(Blocker::UnknownFailure));
    };

    if let Some(error) = &response.transport_error {
        if looks_like_network_error(error) {
            return (Outcome::Failure, Some(Blocker::NetworkBlocked));
        }
        return (Outcome::Failure, Some(Blocker::UnknownFailure));
    }

    if let Some(status) = response.status {
        if status == 401 || status == 403 || looks_like_auth_error(&response.body_preview) {
            return (Outcome::Failure, Some(Blocker::AuthBlocked));
        }

        let success = (settings.success_status_min..=settings.success_status_max).contains(&status);
        if success && response.validation_errors.is_empty() {
            return (Outcome::Success, None);
        }
        if success && !response.validation_errors.is_empty() {
            return (Outcome::Partial, Some(Blocker::SchemaMismatch));
        }
        if !response.validation_errors.is_empty() {
            return (Outcome::Partial, Some(Blocker::SchemaMismatch));
        }
        return (Outcome::Failure, Some(Blocker::UnknownFailure));
    }

    (Outcome::Failure, Some(Blocker::UnknownFailure))
}

pub fn preflight_blocker(
    has_candidates: bool,
    unsupported_reason: Option<&str>,
    unresolved_slots: usize,
) -> Option<Blocker> {
    if unsupported_reason.is_some() {
        return Some(Blocker::UnsupportedInput);
    }
    if unresolved_slots > 0 {
        return Some(Blocker::MissingRuntimeValue);
    }
    if !has_candidates {
        return Some(Blocker::DocsUnclear);
    }
    None
}

fn looks_like_network_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "dns",
        "tls",
        "certificate",
        "connect",
        "timeout",
        "proxy",
        "connection refused",
        "network",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn looks_like_auth_error(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    [
        "unauthorized",
        "forbidden",
        "invalid api key",
        "invalid token",
        "missing token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use crate::model::{AppSettings, Blocker, ResponseSnapshot};

    use super::{classify_outcome, preflight_blocker};

    #[test]
    fn classifies_missing_runtime_values_before_run() {
        assert_eq!(
            preflight_blocker(true, None, 1),
            Some(Blocker::MissingRuntimeValue)
        );
    }

    #[test]
    fn classifies_schema_mismatch_as_partial() {
        let response = ResponseSnapshot {
            status: Some(200),
            headers: Vec::new(),
            body_preview: "{}".to_string(),
            elapsed_ms: 3,
            validation_errors: vec!["missing id".to_string()],
            transport_error: None,
        };
        let (outcome, blocker) =
            classify_outcome(None, Some(&response), None, &AppSettings::default());
        assert_eq!(outcome, crate::model::Outcome::Partial);
        assert_eq!(blocker, Some(Blocker::SchemaMismatch));
    }
}
