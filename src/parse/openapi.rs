use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use openapiv3::{
    APIKeyLocation, Components, MediaType, OpenAPI, Operation, Parameter, ParameterData,
    ParameterSchemaOrContent, PathItem, ReferenceOr, RequestBody, Response, Schema, SecurityScheme,
    Server, StatusCode, StringFormat, VariantOrUnknownOrEmpty,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::exec::redact::{is_secret_key, redact_body};
use crate::exec::validation::{media_schema_to_template, openapi_schema_to_json_schema};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SchemaSpec, SlotLocation, SourceInput, SourceKind,
};
use crate::util::{extract_slot_names, slot_token};

pub fn parse_openapi_input(raw_text: &str) -> ParsedSource {
    parse_openapi_input_impl(raw_text, None)
}

pub fn parse_openapi_input_with_base_path(raw_text: &str, base_path: &Path) -> ParsedSource {
    parse_openapi_input_impl(raw_text, Some(base_path))
}

fn parse_openapi_input_impl(raw_text: &str, base_path: Option<&Path>) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::OpenApi,
        raw_text: "<openapi input redacted>".to_string(),
    };

    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    match parse_document(raw_text) {
        Ok((document, root_value, synthetic_note)) => {
            if let Some(note) = synthetic_note {
                notes.push(note);
            }
            let resolver = Resolver::new(&document, root_value, base_path);
            for (path, path_item_ref) in document.paths.iter() {
                let Some(path_item) = resolver.resolve_path_item(path_item_ref) else {
                    notes.push("Skipped unresolved OpenAPI path item ref".to_string());
                    continue;
                };
                candidates.extend(path_item_to_drafts(&document, &resolver, path, &path_item));
            }
            notes.extend(resolver.take_notes());
            if candidates.is_empty() {
                notes.push("OpenAPI input did not contain any concrete operations".to_string());
            }
        }
        Err(error) => notes.push(error.to_string()),
    }

    ParsedSource {
        source,
        candidates,
        notes,
    }
}

fn parse_document(raw_text: &str) -> Result<(OpenAPI, Value, Option<String>)> {
    let value: Value = serde_json::from_str(raw_text)
        .or_else(|_| yaml_serde::from_str(raw_text))
        .context("OpenAPI input is not valid JSON or YAML")?;
    let (wrapped, note) = wrap_fragment(value);
    let document: OpenAPI = serde_json::from_value(wrapped.clone())
        .context("Could not deserialize OpenAPI document")?;
    Ok((document, wrapped, note))
}

fn wrap_fragment(value: Value) -> (Value, Option<String>) {
    let Some(object) = value.as_object() else {
        return (value, None);
    };
    if object.contains_key("openapi") && object.contains_key("paths") {
        return (value, None);
    }
    if object.contains_key("paths") {
        return (
            json!({
                "openapi": "3.0.3",
                "info": { "title": "Synthetic OpenAPI", "version": "0.1.0" },
                "paths": object.get("paths").cloned().unwrap_or_else(|| json!({})),
                "components": object.get("components").cloned().unwrap_or_else(|| json!({}))
            }),
            Some("Wrapped fragment into a synthetic OpenAPI document".to_string()),
        );
    }
    if object.keys().all(|key| key.starts_with('/')) {
        return (
            json!({
                "openapi": "3.0.3",
                "info": { "title": "Synthetic OpenAPI", "version": "0.1.0" },
                "paths": value
            }),
            Some("Wrapped paths fragment into a synthetic OpenAPI document".to_string()),
        );
    }
    if contains_http_method_key(object) {
        return (
            json!({
                "openapi": "3.0.3",
                "info": { "title": "Synthetic OpenAPI", "version": "0.1.0" },
                "paths": {
                    "/inferred": value
                }
            }),
            Some("Wrapped path-item fragment into a synthetic OpenAPI document".to_string()),
        );
    }
    if object.contains_key("responses") {
        let method = if object.contains_key("requestBody") {
            "post"
        } else {
            "get"
        };
        return (
            json!({
                "openapi": "3.0.3",
                "info": { "title": "Synthetic OpenAPI", "version": "0.1.0" },
                "paths": {
                    "/inferred": {
                        method: value
                    }
                }
            }),
            Some("Wrapped single-operation fragment into a synthetic OpenAPI document".to_string()),
        );
    }
    (value, None)
}

fn contains_http_method_key(object: &serde_json::Map<String, Value>) -> bool {
    object.keys().any(|key| {
        matches!(
            key.as_str(),
            "get" | "put" | "post" | "delete" | "patch" | "head" | "options" | "trace"
        )
    })
}

fn path_item_to_drafts(
    document: &OpenAPI,
    resolver: &Resolver<'_>,
    path: &str,
    path_item: &PathItem,
) -> Vec<RequestDraft> {
    let mut drafts = Vec::new();
    for (method, operation) in path_item.iter() {
        drafts.push(operation_to_draft(
            document, resolver, path, path_item, method, operation,
        ));
    }
    drafts
}

fn operation_to_draft(
    document: &OpenAPI,
    resolver: &Resolver<'_>,
    path: &str,
    path_item: &PathItem,
    method: &str,
    operation: &Operation,
) -> RequestDraft {
    let mut slots = Vec::new();
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut unsupported_reason = None;

    let path_template = normalize_template(path);
    collect_slots_from_template(
        &mut slots,
        &path_template,
        SlotLocation::Path,
        true,
        "Path parameter",
    );

    for parameter in merge_parameters(path_item, operation, resolver) {
        let data = parameter.parameter_data_ref();
        let description = data.description.clone().unwrap_or_default();
        let required = data.required;
        let slot_value = parameter_placeholder(data, resolver);
        let value = slot_value.clone().unwrap_or_else(|| slot_token(&data.name));
        let confidence = if slot_value.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        };

        match parameter {
            Parameter::Path { .. } => {
                collect_slots_from_template(
                    &mut slots,
                    &slot_token(&data.name),
                    SlotLocation::Path,
                    true,
                    &description,
                );
            }
            Parameter::Query { .. } => {
                query.push(KeyValueField {
                    key: data.name.clone(),
                    value: value.clone(),
                    required,
                    description: description.clone(),
                    confidence: confidence.clone(),
                });
                collect_slots_from_template(
                    &mut slots,
                    &value,
                    SlotLocation::Query,
                    required,
                    &description,
                );
            }
            Parameter::Header { .. } => {
                headers.push(HeaderField {
                    key: data.name.clone(),
                    value: value.clone(),
                    required,
                    description: description.clone(),
                    confidence: confidence.clone(),
                });
                collect_slots_from_template(
                    &mut slots,
                    &value,
                    SlotLocation::Header,
                    required,
                    &description,
                );
            }
            Parameter::Cookie { .. } => {
                headers.push(HeaderField {
                    key: "Cookie".to_string(),
                    value: format!("{}={value}", data.name),
                    required,
                    description: format!("Cookie parameter {}", data.name),
                    confidence,
                });
            }
        }
    }

    let base_url = pick_server_url(operation, path_item, document, &mut slots);
    let (body, response_schema) = request_and_response(
        operation,
        resolver,
        &mut slots,
        &mut headers,
        &mut unsupported_reason,
    );
    let auth = infer_security(document, operation, resolver, &mut slots, &headers);
    dedupe_slots(&mut slots);

    RequestDraft {
        operation_id: operation
            .operation_id
            .clone()
            .unwrap_or_else(|| format!("{}-{}", method, path.trim_matches('/').replace('/', "-"))),
        name: operation
            .summary
            .clone()
            .or_else(|| operation.operation_id.clone())
            .unwrap_or_else(|| format!("{} {}", method.to_uppercase(), path)),
        method: method.to_uppercase(),
        base_url,
        path: path_template,
        headers,
        query,
        body,
        auth,
        slots,
        evidence: vec![EvidenceItem {
            source_kind: SourceKind::OpenApi,
            label: "openapi operation".to_string(),
            detail: format!("Resolved `{}` from OpenAPI", method.to_uppercase()),
            confidence: Confidence::High,
        }],
        confidence: FieldConfidence {
            overall: Confidence::High,
            notes: "Built from OpenAPI operation and resolved local refs".to_string(),
        },
        response_schema,
        unsupported_reason,
        source_kinds: vec![SourceKind::OpenApi],
    }
}

fn merge_parameters(
    path_item: &PathItem,
    operation: &Operation,
    resolver: &Resolver<'_>,
) -> Vec<Parameter> {
    let mut merged = BTreeMap::<String, Parameter>::new();
    for source in [&path_item.parameters, &operation.parameters] {
        for parameter in source {
            if let Some(parameter) = resolver.resolve_parameter(parameter) {
                let key = format!(
                    "{}:{:?}",
                    parameter.parameter_data_ref().name,
                    std::mem::discriminant(&parameter)
                );
                merged.insert(key, parameter);
            }
        }
    }
    merged.into_values().collect()
}

fn parameter_placeholder(data: &ParameterData, resolver: &Resolver<'_>) -> Option<String> {
    if is_secret_key(&data.name) {
        return Some(slot_token(&data.name));
    }
    if let Some(example) = &data.example {
        return Some(redact_body(&example_to_string(example), None));
    }
    match &data.format {
        ParameterSchemaOrContent::Schema(schema) => {
            resolver.resolve_schema(schema).and_then(|schema| {
                schema
                    .schema_data
                    .example
                    .map(|example| redact_body(&example_to_string(&example), None))
            })
        }
        ParameterSchemaOrContent::Content(content) => content
            .values()
            .find_map(|media_type| example_from_media_type(media_type, resolver)),
    }
}

fn request_and_response(
    operation: &Operation,
    resolver: &Resolver<'_>,
    slots: &mut Vec<RuntimeSlot>,
    headers: &mut Vec<HeaderField>,
    unsupported_reason: &mut Option<String>,
) -> (BodyTemplate, Option<SchemaSpec>) {
    let body = operation
        .request_body
        .as_ref()
        .and_then(|request_body| resolver.resolve_request_body(request_body))
        .map(|request_body| {
            request_body_to_body(&request_body, resolver, slots, headers, unsupported_reason)
        })
        .unwrap_or(BodyTemplate::None);
    let response_schema = response_schema(operation, resolver);
    (body, response_schema)
}

fn request_body_to_body(
    request_body: &RequestBody,
    resolver: &Resolver<'_>,
    slots: &mut Vec<RuntimeSlot>,
    headers: &mut Vec<HeaderField>,
    unsupported_reason: &mut Option<String>,
) -> BodyTemplate {
    if let Some(media_type) = request_body.content.get("application/json").or_else(|| {
        request_body
            .content
            .iter()
            .find(|(key, _)| key.contains("json"))
            .map(|(_, value)| value)
    }) {
        headers.push(HeaderField {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
            required: true,
            description: "OpenAPI request body content type".to_string(),
            confidence: Confidence::High,
        });
        if let Some(schema) = media_schema(media_type, resolver) {
            let template = media_schema_to_template(
                &schema,
                &|reference| resolver.resolve_schema(reference),
                "body",
            );
            let template = redact_body(&template, Some("application/json"));
            collect_slots_from_template(
                slots,
                &template,
                SlotLocation::Body,
                request_body.required,
                "Request body",
            );
            return BodyTemplate::Json { template };
        }
        if let Some(example) = example_from_media_type(media_type, resolver) {
            let example = redact_body(&example, Some("application/json"));
            collect_slots_from_template(
                slots,
                &example,
                SlotLocation::Body,
                request_body.required,
                "Request body",
            );
            return BodyTemplate::Json { template: example };
        }
    }

    if let Some(media_type) = request_body
        .content
        .get("application/x-www-form-urlencoded")
    {
        headers.push(HeaderField {
            key: "Content-Type".to_string(),
            value: "application/x-www-form-urlencoded".to_string(),
            required: true,
            description: "OpenAPI request body content type".to_string(),
            confidence: Confidence::High,
        });
        return form_fields_from_media_type(media_type, resolver, slots, SlotLocation::Body, false)
            .map(|fields| BodyTemplate::Form { fields })
            .unwrap_or(BodyTemplate::Form { fields: Vec::new() });
    }

    if let Some(media_type) = request_body.content.get("multipart/form-data") {
        headers.push(HeaderField {
            key: "Content-Type".to_string(),
            value: "multipart/form-data".to_string(),
            required: true,
            description: "OpenAPI request body content type".to_string(),
            confidence: Confidence::High,
        });
        let has_binary = multipart_has_binary(media_type, resolver);
        if has_binary {
            *unsupported_reason = Some(
                "Multipart file uploads are not supported in v1; non-file fields were parsed"
                    .to_string(),
            );
        }
        return form_fields_from_media_type(
            media_type,
            resolver,
            slots,
            SlotLocation::Body,
            has_binary,
        )
        .map(|fields| BodyTemplate::Multipart { fields })
        .unwrap_or(BodyTemplate::Multipart { fields: Vec::new() });
    }

    if let Some((content_type, media_type)) = request_body.content.iter().next() {
        headers.push(HeaderField {
            key: "Content-Type".to_string(),
            value: content_type.clone(),
            required: true,
            description: "OpenAPI request body content type".to_string(),
            confidence: Confidence::Medium,
        });
        if let Some(example) = example_from_media_type(media_type, resolver) {
            let example = redact_body(&example, Some(content_type));
            collect_slots_from_template(
                slots,
                &example,
                SlotLocation::Body,
                request_body.required,
                "Request body",
            );
            return BodyTemplate::Text { text: example };
        }
    }

    BodyTemplate::None
}

fn form_fields_from_media_type(
    media_type: &MediaType,
    resolver: &Resolver<'_>,
    slots: &mut Vec<RuntimeSlot>,
    location: SlotLocation,
    skip_file_fields: bool,
) -> Option<Vec<KeyValueField>> {
    let schema = media_schema(media_type, resolver)?;
    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(openapiv3::Type::Object(object_type)) => {
            let mut fields = Vec::new();
            for (name, property) in &object_type.properties {
                let Some(schema) = resolver.resolve_boxed_schema(property) else {
                    continue;
                };
                if skip_file_fields && schema_is_file_like(&schema) {
                    continue;
                }
                let value = if is_secret_key(name) {
                    slot_token(name)
                } else {
                    let template = media_schema_to_template(
                        &schema,
                        &|reference| resolver.resolve_schema(reference),
                        name,
                    )
                    .replace('\n', "");
                    redact_body(&template, Some("application/json"))
                };
                fields.push(KeyValueField {
                    key: name.clone(),
                    value: value.clone(),
                    required: object_type.required.iter().any(|required| required == name),
                    description: "OpenAPI form field".to_string(),
                    confidence: Confidence::Medium,
                });
                collect_slots_from_template(slots, &value, location.clone(), true, "Form field");
            }
            Some(fields)
        }
        _ => None,
    }
}

fn multipart_has_binary(media_type: &MediaType, resolver: &Resolver<'_>) -> bool {
    let Some(schema) = media_schema(media_type, resolver) else {
        return false;
    };
    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(openapiv3::Type::Object(object_type)) => object_type
            .properties
            .values()
            .filter_map(|schema| resolver.resolve_boxed_schema(schema))
            .any(|schema| schema_is_file_like(&schema)),
        _ => false,
    }
}

fn schema_is_file_like(schema: &Schema) -> bool {
    let format = match &schema.schema_kind {
        openapiv3::SchemaKind::Type(openapiv3::Type::String(string_type)) => &string_type.format,
        _ => return false,
    };
    matches!(
        format,
        VariantOrUnknownOrEmpty::Item(StringFormat::Binary)
            | VariantOrUnknownOrEmpty::Item(StringFormat::Byte)
    )
}

fn response_schema(operation: &Operation, resolver: &Resolver<'_>) -> Option<SchemaSpec> {
    let response = pick_response(operation, resolver)?;
    let media_type = response.content.get("application/json").or_else(|| {
        response
            .content
            .iter()
            .find(|(key, _)| key.contains("json"))
            .map(|(_, value)| value)
    })?;
    let schema = media_schema(media_type, resolver)?;
    Some(SchemaSpec {
        name: Some("response".to_string()),
        schema: openapi_schema_to_json_schema(&schema, &|reference| {
            resolver.resolve_schema(reference)
        }),
    })
}

fn pick_response(operation: &Operation, resolver: &Resolver<'_>) -> Option<Response> {
    for status in [200u16, 201, 202, 204] {
        if let Some(response) = operation.responses.responses.get(&StatusCode::Code(status))
            && let Some(response) = resolver.resolve_response(response)
        {
            return Some(response);
        }
    }
    for status_code in [2u16, 4u16, 5u16] {
        if let Some(response) = operation
            .responses
            .responses
            .get(&StatusCode::Range(status_code))
            && let Some(response) = resolver.resolve_response(response)
        {
            return Some(response);
        }
    }
    operation
        .responses
        .default
        .as_ref()
        .and_then(|response| resolver.resolve_response(response))
}

fn media_schema(media_type: &MediaType, resolver: &Resolver<'_>) -> Option<Schema> {
    media_type
        .schema
        .as_ref()
        .and_then(|schema| resolver.resolve_schema(schema))
}

fn example_from_media_type(media_type: &MediaType, resolver: &Resolver<'_>) -> Option<String> {
    if let Some(example) = &media_type.example {
        return Some(redact_body(&example_to_string(example), None));
    }
    if let Some(example) = media_type.examples.values().next() {
        match example {
            ReferenceOr::Item(example) => {
                if let Some(value) = &example.value {
                    return Some(redact_body(&example_to_string(value), None));
                }
            }
            ReferenceOr::Reference { .. } => {}
        }
    }
    media_schema(media_type, resolver).map(|schema| {
        let template = media_schema_to_template(
            &schema,
            &|reference| resolver.resolve_schema(reference),
            "body",
        );
        redact_body(&template, Some("application/json"))
    })
}

fn infer_security(
    document: &OpenAPI,
    operation: &Operation,
    resolver: &Resolver<'_>,
    slots: &mut Vec<RuntimeSlot>,
    headers: &[HeaderField],
) -> AuthStyle {
    let security_requirements = operation
        .security
        .as_ref()
        .or(document.security.as_ref())
        .cloned()
        .unwrap_or_default();
    for requirement in security_requirements {
        for scheme_name in requirement.keys() {
            if let Some(scheme) = resolver.resolve_security_scheme_name(scheme_name) {
                match scheme {
                    SecurityScheme::HTTP { scheme, .. }
                        if scheme.eq_ignore_ascii_case("bearer") =>
                    {
                        slots.push(RuntimeSlot {
                            name: "bearer_token".to_string(),
                            location: SlotLocation::Auth,
                            required: true,
                            current_value: None,
                            description: "Bearer token".to_string(),
                            confidence: Confidence::High,
                        });
                        return AuthStyle::Bearer {
                            token_slot: "bearer_token".to_string(),
                            header_name: "Authorization".to_string(),
                        };
                    }
                    SecurityScheme::HTTP { scheme, .. } if scheme.eq_ignore_ascii_case("basic") => {
                        slots.push(RuntimeSlot {
                            name: "basic_username".to_string(),
                            location: SlotLocation::Auth,
                            required: true,
                            current_value: None,
                            description: "Basic auth username".to_string(),
                            confidence: Confidence::High,
                        });
                        slots.push(RuntimeSlot {
                            name: "basic_password".to_string(),
                            location: SlotLocation::Auth,
                            required: true,
                            current_value: None,
                            description: "Basic auth password".to_string(),
                            confidence: Confidence::High,
                        });
                        return AuthStyle::Basic {
                            username_slot: "basic_username".to_string(),
                            password_slot: "basic_password".to_string(),
                        };
                    }
                    SecurityScheme::APIKey { location, name, .. } => {
                        let slot_name = name.to_ascii_lowercase().replace('-', "_");
                        slots.push(RuntimeSlot {
                            name: slot_name.clone(),
                            location: SlotLocation::Auth,
                            required: true,
                            current_value: None,
                            description: format!("Credential for {name}"),
                            confidence: Confidence::High,
                        });
                        return match location {
                            APIKeyLocation::Header => AuthStyle::HeaderApiKey {
                                header_name: name,
                                slot_name,
                            },
                            APIKeyLocation::Query => AuthStyle::QueryApiKey {
                                param_name: name,
                                slot_name,
                            },
                            APIKeyLocation::Cookie => {
                                let _ = headers;
                                AuthStyle::HeaderApiKey {
                                    header_name: "Cookie".to_string(),
                                    slot_name,
                                }
                            }
                        };
                    }
                    _ => {}
                }
            }
        }
    }

    if headers
        .iter()
        .any(|header| header.key.eq_ignore_ascii_case("authorization"))
    {
        slots.push(RuntimeSlot {
            name: "bearer_token".to_string(),
            location: SlotLocation::Auth,
            required: true,
            current_value: None,
            description: "Authorization header token".to_string(),
            confidence: Confidence::Low,
        });
        return AuthStyle::Bearer {
            token_slot: "bearer_token".to_string(),
            header_name: "Authorization".to_string(),
        };
    }

    AuthStyle::None
}

fn pick_server_url(
    operation: &Operation,
    path_item: &PathItem,
    document: &OpenAPI,
    slots: &mut Vec<RuntimeSlot>,
) -> Option<String> {
    let server = operation
        .servers
        .first()
        .or(path_item.servers.first())
        .or(document.servers.first());
    let base_url = server.map(server_url_template);
    if let Some(url) = &base_url {
        collect_slots_from_template(slots, url, SlotLocation::Path, true, "Server variable");
    }
    base_url.and_then(|url| if url == "/" { None } else { Some(url) })
}

fn server_url_template(server: &Server) -> String {
    normalize_template(&server.url)
}

fn normalize_template(value: &str) -> String {
    let mut normalized = value.to_string();
    let path_regex = regex::Regex::new(r"\{([a-zA-Z0-9_\-]+)\}").expect("template regex");
    for captures in path_regex.captures_iter(value) {
        let full = captures
            .get(0)
            .map(|item| item.as_str())
            .unwrap_or_default();
        let name = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or_default();
        normalized = normalized.replace(full, &slot_token(name));
    }
    normalized
}

fn collect_slots_from_template(
    slots: &mut Vec<RuntimeSlot>,
    template: &str,
    location: SlotLocation,
    required: bool,
    description: &str,
) {
    for name in extract_slot_names(template) {
        slots.push(RuntimeSlot {
            name,
            location: location.clone(),
            required,
            current_value: None,
            description: description.to_string(),
            confidence: Confidence::High,
        });
    }
}

fn dedupe_slots(slots: &mut Vec<RuntimeSlot>) {
    let mut unique = Vec::new();
    for slot in slots.drain(..) {
        if !unique.iter().any(|existing: &RuntimeSlot| {
            existing.name == slot.name && existing.location == slot.location
        }) {
            unique.push(slot);
        }
    }
    *slots = unique;
}

fn example_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

#[derive(Clone)]
struct ExternalDocument {
    value: Value,
    directory: PathBuf,
}

struct Resolver<'a> {
    document: &'a OpenAPI,
    root_value: Value,
    root_directory: Option<PathBuf>,
    notes: RefCell<Vec<String>>,
    external_documents: RefCell<BTreeMap<PathBuf, ExternalDocument>>,
    active_refs: RefCell<Vec<String>>,
    emitted_notes: RefCell<BTreeSet<String>>,
    max_depth: usize,
}

impl<'a> Resolver<'a> {
    fn new(document: &'a OpenAPI, root_value: Value, base_path: Option<&Path>) -> Self {
        let root_directory = base_path.and_then(|path| {
            let root = if path.is_file() {
                path.parent().unwrap_or(path)
            } else {
                path
            };
            root.canonicalize().ok()
        });
        Self {
            document,
            root_value,
            root_directory,
            notes: RefCell::new(Vec::new()),
            external_documents: RefCell::new(BTreeMap::new()),
            active_refs: RefCell::new(Vec::new()),
            emitted_notes: RefCell::new(BTreeSet::new()),
            max_depth: 16,
        }
    }

    fn take_notes(&self) -> Vec<String> {
        self.notes.borrow_mut().drain(..).collect()
    }

    fn resolve_path_item(&self, value: &ReferenceOr<PathItem>) -> Option<PathItem> {
        self.resolve_reference_or(value)
    }

    fn resolve_parameter(&self, value: &ReferenceOr<Parameter>) -> Option<Parameter> {
        self.resolve_reference_or(value)
    }

    fn resolve_request_body(&self, value: &ReferenceOr<RequestBody>) -> Option<RequestBody> {
        self.resolve_reference_or(value)
    }

    fn resolve_response(&self, value: &ReferenceOr<Response>) -> Option<Response> {
        self.resolve_reference_or(value)
    }

    fn resolve_schema(&self, value: &ReferenceOr<Schema>) -> Option<Schema> {
        self.resolve_reference_or(value)
    }

    fn resolve_boxed_schema(&self, value: &ReferenceOr<Box<Schema>>) -> Option<Schema> {
        match value {
            ReferenceOr::Item(item) => Some(item.as_ref().clone()),
            ReferenceOr::Reference { reference } => {
                let unboxed = ReferenceOr::<Schema>::Reference {
                    reference: reference.clone(),
                };
                self.resolve_schema(&unboxed)
            }
        }
    }

    fn resolve_security_scheme_name(&self, name: &str) -> Option<SecurityScheme> {
        let components: &Components = self.document.components.as_ref()?;
        self.resolve_reference_or(components.security_schemes.get(name)?)
    }

    fn resolve_reference_or<T>(&self, value: &ReferenceOr<T>) -> Option<T>
    where
        T: Clone + DeserializeOwned,
    {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => self.resolve_ref_as(reference),
        }
    }

    fn resolve_ref_as<T>(&self, reference: &str) -> Option<T>
    where
        T: DeserializeOwned,
    {
        let value = self.resolve_ref_value(
            reference,
            &self.root_value,
            self.root_directory.as_deref(),
            "<root>",
            0,
        )?;
        serde_json::from_value(value)
            .map_err(|_| self.note_unresolved())
            .ok()
    }

    fn resolve_ref_value(
        &self,
        reference: &str,
        current_document: &Value,
        current_directory: Option<&Path>,
        current_document_id: &str,
        depth: usize,
    ) -> Option<Value> {
        if depth > self.max_depth {
            self.note_once("Skipped OpenAPI ref after max depth");
            return None;
        }

        let (path_part, pointer) = split_ref(reference);
        let lower_path = path_part.to_ascii_lowercase();
        if lower_path.starts_with("http://") || lower_path.starts_with("https://") {
            self.note_once("Skipped remote OpenAPI ref");
            return None;
        }
        if has_unsupported_scheme(path_part) {
            self.note_once("Skipped unsupported OpenAPI ref scheme");
            return None;
        }

        let (document, directory, document_id) = if path_part.is_empty() {
            (
                current_document.clone(),
                current_directory.map(Path::to_path_buf),
                current_document_id.to_string(),
            )
        } else {
            let (path, external) = self.load_external_document(path_part, current_directory)?;
            (
                external.value,
                Some(external.directory),
                path.display().to_string(),
            )
        };

        let Some(pointer) = normalize_pointer(pointer) else {
            self.note_unresolved();
            return None;
        };
        let ref_key = format!("{document_id}#{pointer}");
        {
            let active_refs = self.active_refs.borrow();
            if active_refs.iter().any(|active| active == &ref_key) {
                self.note_once("Skipped cyclic OpenAPI ref");
                return None;
            }
        }

        self.active_refs.borrow_mut().push(ref_key);
        let selected = if pointer.is_empty() {
            Some(document.clone())
        } else {
            document.pointer(&pointer).cloned()
        };
        let result = selected
            .or_else(|| {
                self.note_unresolved();
                None
            })
            .map(|value| {
                self.expand_refs_in_value(
                    value,
                    &document,
                    directory.as_deref(),
                    &document_id,
                    depth + 1,
                )
            });
        self.active_refs.borrow_mut().pop();
        result
    }

    fn expand_refs_in_value(
        &self,
        value: Value,
        current_document: &Value,
        current_directory: Option<&Path>,
        current_document_id: &str,
        depth: usize,
    ) -> Value {
        if depth > self.max_depth {
            self.note_once("Skipped OpenAPI ref after max depth");
            return value;
        }

        match value {
            Value::Object(mut object) => {
                if let Some(Value::String(reference)) = object.get("$ref") {
                    return self
                        .resolve_ref_value(
                            reference,
                            current_document,
                            current_directory,
                            current_document_id,
                            depth + 1,
                        )
                        .unwrap_or_else(|| json!({}));
                }
                for item in object.values_mut() {
                    let original = std::mem::take(item);
                    *item = self.expand_refs_in_value(
                        original,
                        current_document,
                        current_directory,
                        current_document_id,
                        depth + 1,
                    );
                }
                Value::Object(object)
            }
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|item| {
                        self.expand_refs_in_value(
                            item,
                            current_document,
                            current_directory,
                            current_document_id,
                            depth + 1,
                        )
                    })
                    .collect(),
            ),
            _ => value,
        }
    }

    fn load_external_document(
        &self,
        path_part: &str,
        current_directory: Option<&Path>,
    ) -> Option<(PathBuf, ExternalDocument)> {
        let Some(current_directory) = current_directory.or(self.root_directory.as_deref()) else {
            self.note_unresolved();
            return None;
        };
        let Some(root_directory) = self.root_directory.as_ref() else {
            self.note_unresolved();
            return None;
        };
        let requested = Path::new(path_part);
        if requested.is_absolute() {
            self.note_once("Skipped OpenAPI ref outside resolver root");
            return None;
        }
        if !is_supported_ref_extension(requested) {
            self.note_once("Skipped unsupported OpenAPI ref extension");
            return None;
        }
        let target = current_directory.join(requested);
        let canonical = match target.canonicalize() {
            Ok(path) => path,
            Err(_) => {
                self.note_unresolved();
                return None;
            }
        };
        if !canonical.starts_with(root_directory) {
            self.note_once("Skipped OpenAPI ref outside resolver root");
            return None;
        }
        if let Some(cached) = self.external_documents.borrow().get(&canonical).cloned() {
            return Some((canonical, cached));
        }

        let raw = match fs::read_to_string(&canonical) {
            Ok(raw) => raw,
            Err(_) => {
                self.note_unresolved();
                return None;
            }
        };
        let value =
            match serde_json::from_str::<Value>(&raw).or_else(|_| yaml_serde::from_str(&raw)) {
                Ok(value) => value,
                Err(_) => {
                    self.note_once("Skipped malformed OpenAPI ref document");
                    return None;
                }
            };
        let directory = canonical
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root_directory.clone());
        let document = ExternalDocument { value, directory };
        self.external_documents
            .borrow_mut()
            .insert(canonical.clone(), document.clone());
        Some((canonical, document))
    }

    fn note_unresolved(&self) {
        self.note_once("Skipped unresolved OpenAPI ref");
    }

    fn note_once(&self, note: &str) {
        if self.emitted_notes.borrow_mut().insert(note.to_string()) {
            self.notes.borrow_mut().push(note.to_string());
        }
    }
}

fn split_ref(reference: &str) -> (&str, &str) {
    match reference.split_once('#') {
        Some((path, pointer)) => (path, pointer),
        None => (reference, ""),
    }
}

fn normalize_pointer(pointer: &str) -> Option<String> {
    if pointer.is_empty() {
        return Some(String::new());
    }
    if pointer.starts_with('/') {
        Some(pointer.to_string())
    } else {
        None
    }
}

fn has_unsupported_scheme(path_part: &str) -> bool {
    let lower = path_part.to_ascii_lowercase();
    lower.starts_with("file:") || (lower.contains("://") && !lower.starts_with("http"))
}

fn is_supported_ref_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "json" | "yaml" | "yml"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{parse_openapi_input, parse_openapi_input_with_base_path};
    use crate::model::{AuthStyle, BodyTemplate};

    #[test]
    fn parses_openapi_fragment_and_extracts_schema() {
        let input = r#"
openapi: 3.0.3
info:
  title: Demo
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /v1/customers/{customer_id}:
    post:
      summary: Create customer note
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: customer_id
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [note]
              properties:
                note:
                  type: string
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id:
                    type: string
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
"#;
        let parsed = parse_openapi_input(input);
        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert_eq!(draft.base_url.as_deref(), Some("https://api.example.com"));
        assert!(matches!(draft.auth, AuthStyle::Bearer { .. }));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.response_schema.is_some());
    }

    #[test]
    fn internal_component_schema_refs_still_resolve() {
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUser'
      responses:
        "200": { description: ok }
components:
  schemas:
    CreateUser:
      type: object
      properties:
        name:
          type: string
"#;
        let parsed = parse_openapi_input(input);
        assert!(parsed.notes.iter().all(|note| !note.contains("unresolved")));
        let draft = &parsed.candidates[0];
        let BodyTemplate::Json { template } = &draft.body else {
            panic!("expected json body");
        };
        assert!(template.contains("name"));
    }

    #[test]
    fn local_relative_schema_ref_resolves() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("schemas")).expect("schemas dir");
        fs::write(
            temp.path().join("schemas/user.yaml"),
            r#"
User:
  type: object
  properties:
    email:
      type: string
"#,
        )
        .expect("schema file");
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: './schemas/user.yaml#/User'
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input_with_base_path(input, temp.path());
        assert_eq!(parsed.candidates.len(), 1);
        let BodyTemplate::Json { template } = &parsed.candidates[0].body else {
            panic!("expected json body");
        };
        assert!(template.contains("email"));
    }

    #[test]
    fn local_relative_request_body_response_and_parameter_refs_resolve() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("components")).expect("components dir");
        fs::write(
            temp.path().join("components/request_bodies.yaml"),
            r#"
CreateUser:
  required: true
  content:
    application/json:
      schema:
        type: object
        properties:
          name:
            type: string
"#,
        )
        .expect("request body file");
        fs::write(
            temp.path().join("components/responses.yaml"),
            r#"
UserResponse:
  description: ok
  content:
    application/json:
      schema:
        type: object
        properties:
          id:
            type: string
"#,
        )
        .expect("response file");
        fs::write(
            temp.path().join("components/parameters.yaml"),
            r#"
UserId:
  in: query
  name: user_id
  schema:
    type: string
"#,
        )
        .expect("parameter file");
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /users:
    post:
      parameters:
        - $ref: './components/parameters.yaml#/UserId'
      requestBody:
        $ref: './components/request_bodies.yaml#/CreateUser'
      responses:
        "200":
          $ref: './components/responses.yaml#/UserResponse'
"#;
        let parsed = parse_openapi_input_with_base_path(input, temp.path());
        assert_eq!(parsed.candidates.len(), 1);
        let draft = &parsed.candidates[0];
        assert!(draft.query.iter().any(|field| field.key == "user_id"));
        assert!(matches!(draft.body, BodyTemplate::Json { .. }));
        assert!(draft.response_schema.is_some());
    }

    #[test]
    fn local_relative_path_item_ref_resolves() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("paths")).expect("paths dir");
        fs::write(
            temp.path().join("paths/user.yaml"),
            r#"
get:
  summary: Get user
  responses:
    "200":
      description: ok
"#,
        )
        .expect("path file");
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /users/{id}:
    $ref: './paths/user.yaml'
"#;
        let parsed = parse_openapi_input_with_base_path(input, temp.path());
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(parsed.candidates[0].method, "GET");
        assert_eq!(parsed.candidates[0].path, "/users/{{id}}");
    }

    #[test]
    fn nested_local_refs_resolve_relative_to_external_document_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("components")).expect("components dir");
        fs::create_dir(temp.path().join("schemas")).expect("schemas dir");
        fs::write(
            temp.path().join("components/request_bodies.yaml"),
            r#"
CreateUser:
  required: true
  content:
    application/json:
      schema:
        $ref: '../schemas/user.yaml#/User'
"#,
        )
        .expect("request body file");
        fs::write(
            temp.path().join("schemas/user.yaml"),
            r#"
User:
  type: object
  properties:
    nested_email:
      type: string
"#,
        )
        .expect("schema file");
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /users:
    post:
      requestBody:
        $ref: './components/request_bodies.yaml#/CreateUser'
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input_with_base_path(input, temp.path());
        let BodyTemplate::Json { template } = &parsed.candidates[0].body else {
            panic!("expected json body");
        };
        assert!(template.contains("nested_email"));
    }

    #[test]
    fn unsafe_or_unavailable_refs_are_skipped_with_sanitized_notes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        fs::create_dir(&root).expect("root dir");
        fs::write(temp.path().join("outside.yaml"), "User:\n  type: object\n")
            .expect("outside file");
        fs::write(root.join("bad.yaml"), "not: [valid").expect("bad file");
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /remote:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: 'https://example.com/openapi.yaml?token=openapi_remote_ref_secret_should_not_leak#/components/schemas/User'
      responses:
        "200": { description: ok }
  /unsupported:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: 'file:///etc/passwd#/User'
      responses:
        "200": { description: ok }
  /outside:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '../outside.yaml#/User'
      responses:
        "200": { description: ok }
  /bad:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: './bad.yaml#/User'
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input_with_base_path(input, &root);
        assert_eq!(parsed.candidates.len(), 4);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped remote OpenAPI ref")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped unsupported OpenAPI ref scheme")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped OpenAPI ref outside resolver root")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped malformed OpenAPI ref document")
        );
        let serialized = serde_json::to_string(&parsed).expect("serialize parsed");
        assert!(!serialized.contains("openapi_remote_ref_secret_should_not_leak"));
    }

    #[test]
    fn cyclic_and_deep_refs_do_not_panic() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("a.yaml"),
            "User:\n  allOf:\n    - $ref: './b.yaml#/User'\n",
        )
        .expect("a");
        fs::write(
            temp.path().join("b.yaml"),
            "User:\n  allOf:\n    - $ref: './a.yaml#/User'\n",
        )
        .expect("b");
        for index in 0..18 {
            let next = index + 1;
            let body = if index == 17 {
                "User:\n  type: object\n".to_string()
            } else {
                format!("User:\n  allOf:\n    - $ref: './d{next}.yaml#/User'\n")
            };
            fs::write(temp.path().join(format!("d{index}.yaml")), body).expect("depth file");
        }
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /cycle:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: './a.yaml#/User'
      responses:
        "200": { description: ok }
  /deep:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: './d0.yaml#/User'
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input_with_base_path(input, temp.path());
        assert_eq!(parsed.candidates.len(), 2);
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped cyclic OpenAPI ref")
        );
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note == "Skipped OpenAPI ref after max depth")
        );
    }

    #[test]
    fn multipart_non_file_fields_are_kept_and_file_fields_are_skipped() {
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /text-only:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              required: [title]
              properties:
                title:
                  type: string
                count:
                  type: integer
      responses:
        "200": { description: ok }
  /mixed:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                title:
                  type: string
                upload:
                  type: string
                  format: binary
      responses:
        "200": { description: ok }
  /binary-only:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                upload:
                  type: string
                  format: byte
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input(input);
        let text = parsed
            .candidates
            .iter()
            .find(|draft| draft.path == "/text-only")
            .expect("text-only draft");
        assert!(text.unsupported_reason.is_none());
        let BodyTemplate::Multipart { fields } = &text.body else {
            panic!("expected multipart");
        };
        assert!(fields.iter().any(|field| field.key == "title"));
        assert!(fields.iter().any(|field| field.key == "count"));

        let mixed = parsed
            .candidates
            .iter()
            .find(|draft| draft.path == "/mixed")
            .expect("mixed draft");
        assert_eq!(
            mixed.unsupported_reason.as_deref(),
            Some("Multipart file uploads are not supported in v1; non-file fields were parsed")
        );
        let BodyTemplate::Multipart { fields } = &mixed.body else {
            panic!("expected multipart");
        };
        assert!(fields.iter().any(|field| field.key == "title"));
        assert!(!fields.iter().any(|field| field.key == "upload"));

        let binary = parsed
            .candidates
            .iter()
            .find(|draft| draft.path == "/binary-only")
            .expect("binary draft");
        assert!(binary.unsupported_reason.is_some());
        let BodyTemplate::Multipart { fields } = &binary.body else {
            panic!("expected multipart");
        };
        assert!(fields.is_empty());
    }

    #[test]
    fn secret_examples_are_not_serialized() {
        let input = r#"
openapi: 3.0.3
info: { title: Demo, version: 1.0.0 }
paths:
  /secrets:
    post:
      parameters:
        - in: query
          name: api_key
          schema:
            type: string
          example: openapi_query_secret_should_not_leak
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                password:
                  type: string
                  example: openapi_body_secret_should_not_leak
                nested:
                  type: object
                  properties:
                    token:
                      type: string
                      example: openapi_local_ref_secret_should_not_leak
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                access_token:
                  type: string
                  example: openapi_multipart_field_secret_should_not_leak
      responses:
        "200": { description: ok }
  /multipart-secrets:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                api_key:
                  type: string
                  example: openapi_multipart_field_secret_should_not_leak
                upload:
                  type: string
                  format: binary
                  example: openapi_multipart_file_secret_should_not_leak
      responses:
        "200": { description: ok }
"#;
        let parsed = parse_openapi_input(input);
        let serialized = serde_json::to_string(&parsed).expect("serialize parsed");
        for canary in [
            "openapi_local_ref_secret_should_not_leak",
            "openapi_query_secret_should_not_leak",
            "openapi_body_secret_should_not_leak",
            "openapi_multipart_file_secret_should_not_leak",
            "openapi_multipart_field_secret_should_not_leak",
        ] {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
        assert!(serialized.contains("{{api_key}}"));
    }
}
