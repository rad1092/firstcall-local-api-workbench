use std::collections::BTreeMap;

use crate::model::{
    AuthStyle, BodyTemplate, Confidence, HeaderField, KeyValueField, ParsedSource, RequestDraft,
    RuntimeSlot, SourceKind,
};

pub fn merge_parsed_sources(parsed_sources: &[ParsedSource]) -> Vec<RequestDraft> {
    let mut grouped = BTreeMap::<String, RequestDraft>::new();

    let mut drafts = parsed_sources
        .iter()
        .flat_map(|parsed| parsed.candidates.iter().cloned())
        .collect::<Vec<_>>();
    drafts.sort_by_key(precedence_rank_for_draft);

    for draft in drafts {
        let key = format!("{} {}", draft.method, draft.path);
        if let Some(existing) = grouped.get(&key).cloned() {
            grouped.insert(key, merge_drafts(existing, draft));
        } else {
            grouped.insert(key, draft);
        }
    }

    grouped.into_values().collect()
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
    let base_url = higher.base_url.clone().or(lower.base_url.clone());
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
