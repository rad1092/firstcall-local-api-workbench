use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, KeyValueField, ParsedSource, RequestDraft,
    RuntimeSlot, SourceKind,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    method: String,
    path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct KnownEndpointScope {
    scheme: String,
    host: String,
    effective_port: Option<u16>,
    base_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EndpointScopeKey {
    Known(KnownEndpointScope),
    Unresolved(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EndpointMergeKey {
    route: RouteKey,
    scope: EndpointScopeKey,
}

pub fn merge_parsed_sources(parsed_sources: &[ParsedSource]) -> Vec<RequestDraft> {
    let mut grouped = BTreeMap::<EndpointMergeKey, RequestDraft>::new();

    let mut drafts = parsed_sources
        .iter()
        .flat_map(|parsed| parsed.candidates.iter().cloned())
        .collect::<Vec<_>>();
    drafts.sort_by_key(precedence_rank_for_draft);
    let keys = endpoint_merge_keys(&drafts);

    for (draft, key) in drafts.into_iter().zip(keys) {
        if let Some(existing) = grouped.get(&key).cloned() {
            grouped.insert(key, merge_drafts(existing, draft));
        } else {
            grouped.insert(key, draft);
        }
    }

    grouped.into_values().collect()
}

pub(crate) fn endpoint_merge_keys(drafts: &[RequestDraft]) -> Vec<EndpointMergeKey> {
    let mut known_by_route = BTreeMap::<RouteKey, BTreeSet<KnownEndpointScope>>::new();
    for draft in drafts {
        if let Some(scope) = known_endpoint_scope(draft.base_url.as_deref()) {
            known_by_route
                .entry(route_key(draft))
                .or_default()
                .insert(scope);
        }
    }

    drafts
        .iter()
        .map(|draft| {
            let route = route_key(draft);
            let known_scopes = known_by_route.get(&route);
            let scope = if let Some(scope) = known_endpoint_scope(draft.base_url.as_deref()) {
                EndpointScopeKey::Known(scope)
            } else if draft
                .base_url
                .as_deref()
                .is_none_or(|base_url| base_url.trim().is_empty())
                && let Some(scope) = known_scopes
                    .filter(|scopes| scopes.len() == 1)
                    .and_then(|scopes| scopes.first().cloned())
            {
                EndpointScopeKey::Known(scope)
            } else {
                EndpointScopeKey::Unresolved(
                    draft
                        .base_url
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_string(),
                )
            };
            EndpointMergeKey { route, scope }
        })
        .collect()
}

fn route_key(draft: &RequestDraft) -> RouteKey {
    RouteKey {
        method: draft.method.trim().to_ascii_uppercase(),
        path: draft.path.clone(),
    }
}

fn known_endpoint_scope(base_url: Option<&str>) -> Option<KnownEndpointScope> {
    let url = url::Url::parse(base_url?.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    Some(KnownEndpointScope {
        scheme: url.scheme().to_ascii_lowercase(),
        host,
        effective_port: url.port_or_known_default(),
        base_path: url.path().trim_end_matches('/').to_string(),
    })
}

pub fn merge_drafts(lower: RequestDraft, higher: RequestDraft) -> RequestDraft {
    let method = if !higher.method.trim().is_empty() {
        higher.method.clone()
    } else {
        lower.method.clone()
    };
    let path = if !higher.path.trim().is_empty() {
        higher.path.clone()
    } else {
        lower.path.clone()
    };
    let base_url = merge_base_url(&lower.base_url, &higher.base_url);
    let headers = merge_headers(&lower.headers, &higher.headers);
    let query = merge_query(&lower.query, &higher.query);
    let body = if matches!(higher.body, BodyTemplate::None) {
        lower.body.clone()
    } else {
        higher.body.clone()
    };
    let auth = if matches!(higher.auth, AuthStyle::None) {
        lower.auth.clone()
    } else {
        higher.auth.clone()
    };
    let slots = merge_slots(&lower.slots, &higher.slots);
    let mut evidence = lower.evidence.clone();
    evidence.extend(higher.evidence.clone());
    let mut source_kinds = lower.source_kinds.clone();
    for source_kind in higher.source_kinds.clone() {
        if !source_kinds.contains(&source_kind) {
            source_kinds.push(source_kind);
        }
    }

    RequestDraft {
        operation_id: higher.operation_id.clone(),
        name: if !higher.name.trim().is_empty() {
            higher.name.clone()
        } else {
            lower.name.clone()
        },
        method,
        base_url,
        path,
        headers,
        query,
        body,
        auth,
        slots,
        evidence,
        confidence: higher.confidence.clone(),
        response_schema: higher
            .response_schema
            .clone()
            .or(lower.response_schema.clone()),
        unsupported_reason: higher
            .unsupported_reason
            .clone()
            .or(lower.unsupported_reason.clone()),
        source_kinds,
    }
}

fn merge_base_url(lower: &Option<String>, higher: &Option<String>) -> Option<String> {
    match (
        known_endpoint_scope(lower.as_deref()),
        known_endpoint_scope(higher.as_deref()),
    ) {
        (Some(_), None) => lower.clone(),
        _ => higher.clone().or(lower.clone()),
    }
}

fn merge_headers(lower: &[HeaderField], higher: &[HeaderField]) -> Vec<HeaderField> {
    let mut merged = lower.to_vec();
    for header in higher {
        if let Some(index) = merged
            .iter()
            .position(|existing| existing.key.eq_ignore_ascii_case(&header.key))
        {
            merged[index] = header.clone();
        } else {
            merged.push(header.clone());
        }
    }
    merged
}

fn merge_query(lower: &[KeyValueField], higher: &[KeyValueField]) -> Vec<KeyValueField> {
    let mut merged = lower.to_vec();
    for item in higher {
        if let Some(index) = merged
            .iter()
            .position(|existing| existing.key.eq_ignore_ascii_case(&item.key))
        {
            merged[index] = item.clone();
        } else {
            merged.push(item.clone());
        }
    }
    merged
}

fn merge_slots(lower: &[RuntimeSlot], higher: &[RuntimeSlot]) -> Vec<RuntimeSlot> {
    let mut merged = lower.to_vec();
    for slot in higher {
        if let Some(index) = merged
            .iter()
            .position(|existing| existing.name == slot.name && existing.location == slot.location)
        {
            let mut updated = merged[index].clone();
            updated.required = slot.required || updated.required;
            updated.description = if slot.description.is_empty() {
                updated.description
            } else {
                slot.description.clone()
            };
            updated.current_value = slot.current_value.clone().or(updated.current_value.clone());
            updated.confidence = stronger_confidence(&updated.confidence, &slot.confidence);
            merged[index] = updated;
        } else {
            merged.push(slot.clone());
        }
    }
    merged
}

fn stronger_confidence(left: &Confidence, right: &Confidence) -> Confidence {
    match (left, right) {
        (Confidence::High, _) | (_, Confidence::High) => Confidence::High,
        (Confidence::Medium, _) | (_, Confidence::Medium) => Confidence::Medium,
        _ => Confidence::Low,
    }
}

fn precedence_rank_for_draft(draft: &RequestDraft) -> usize {
    draft
        .source_kinds
        .iter()
        .map(precedence_rank)
        .min()
        .unwrap_or(usize::MAX)
}

fn precedence_rank(kind: &SourceKind) -> usize {
    match kind {
        SourceKind::Docs => 0,
        SourceKind::OpenApi
        | SourceKind::PostmanCollection
        | SourceKind::Har
        | SourceKind::HttpFile
        | SourceKind::Hurl
        | SourceKind::Bruno
        | SourceKind::Graphql => 1,
        SourceKind::Curl => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::merge_parsed_sources;
    use crate::model::{
        AuthStyle, BodyTemplate, Confidence, FieldConfidence, ParsedSource, RequestDraft,
        SourceInput, SourceKind,
    };

    #[test]
    fn unresolved_candidate_merges_only_when_route_has_one_known_scope() {
        let merged = merge_parsed_sources(&[
            parsed(
                SourceKind::Docs,
                vec![draft(None, "/users", SourceKind::Docs)],
            ),
            parsed(
                SourceKind::Curl,
                vec![draft(
                    Some("https://api.example.com"),
                    "/users",
                    SourceKind::Curl,
                )],
            ),
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert!(merged[0].source_kinds.contains(&SourceKind::Docs));
        assert!(merged[0].source_kinds.contains(&SourceKind::Curl));
    }

    #[test]
    fn multiple_known_scopes_keep_unresolved_candidate_separate() {
        let merged = merge_parsed_sources(&[
            parsed(
                SourceKind::Docs,
                vec![draft(None, "/users", SourceKind::Docs)],
            ),
            parsed(
                SourceKind::OpenApi,
                vec![draft(
                    Some("https://one.example.com"),
                    "/users",
                    SourceKind::OpenApi,
                )],
            ),
            parsed(
                SourceKind::Curl,
                vec![draft(
                    Some("https://two.example.com"),
                    "/users",
                    SourceKind::Curl,
                )],
            ),
        ]);

        assert_eq!(merged.len(), 3);
        let bases = merged
            .iter()
            .map(|draft| draft.base_url.clone().unwrap_or_default())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            bases,
            BTreeSet::from([
                String::new(),
                "https://one.example.com".to_string(),
                "https://two.example.com".to_string(),
            ])
        );
    }

    #[test]
    fn non_empty_dynamic_or_unparseable_base_identity_is_not_absorbed() {
        let merged = merge_parsed_sources(&[parsed(
            SourceKind::Docs,
            vec![
                draft(Some("https://api.example.com"), "/users", SourceKind::Docs),
                draft(Some("{{base_url}}"), "/users", SourceKind::Docs),
                draft(Some("not a URL"), "/users", SourceKind::Docs),
            ],
        )]);

        assert_eq!(merged.len(), 3);
        let bases = merged
            .iter()
            .map(|draft| draft.base_url.clone().unwrap_or_default())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            bases,
            BTreeSet::from([
                "https://api.example.com".to_string(),
                "not a URL".to_string(),
                "{{base_url}}".to_string(),
            ])
        );
    }

    #[test]
    fn known_scope_normalizes_origin_default_port_and_base_path_slash() {
        let merged = merge_parsed_sources(&[
            parsed(
                SourceKind::OpenApi,
                vec![draft(
                    Some("HTTPS://API.EXAMPLE.COM:443/v1/"),
                    "/users",
                    SourceKind::OpenApi,
                )],
            ),
            parsed(
                SourceKind::Curl,
                vec![draft(
                    Some("https://api.example.com/v1"),
                    "/users",
                    SourceKind::Curl,
                )],
            ),
        ]);

        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn scheme_port_base_path_and_request_path_remain_identity_boundaries() {
        let candidates = vec![
            draft(
                Some("http://api.example.com/v1"),
                "/users",
                SourceKind::Docs,
            ),
            draft(
                Some("https://api.example.com/v1"),
                "/users",
                SourceKind::Docs,
            ),
            draft(
                Some("https://api.example.com:8443/v1"),
                "/users",
                SourceKind::Docs,
            ),
            draft(
                Some("https://api.example.com/v2"),
                "/users",
                SourceKind::Docs,
            ),
            draft(
                Some("https://api.example.com/v1"),
                "/Users",
                SourceKind::Docs,
            ),
            draft(
                Some("https://api.example.com/v1"),
                "/users/",
                SourceKind::Docs,
            ),
        ];

        let merged = merge_parsed_sources(&[parsed(SourceKind::Docs, candidates)]);

        assert_eq!(merged.len(), 6);
    }

    fn parsed(kind: SourceKind, candidates: Vec<RequestDraft>) -> ParsedSource {
        ParsedSource {
            source: SourceInput {
                kind,
                raw_text: String::new(),
            },
            candidates,
            notes: Vec::new(),
        }
    }

    fn draft(base_url: Option<&str>, path: &str, source_kind: SourceKind) -> RequestDraft {
        RequestDraft {
            operation_id: format!("{source_kind:?}-{path}"),
            name: format!("GET {path}"),
            method: "GET".to_string(),
            base_url: base_url.map(str::to_string),
            path: path.to_string(),
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
            source_kinds: vec![source_kind],
        }
    }
}
