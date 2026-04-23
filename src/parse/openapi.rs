use std::collections::BTreeMap;

use anyhow::{Context, Result};
use openapiv3::{
    APIKeyLocation, Components, MediaType, OpenAPI, Operation, Parameter, ParameterData,
    ParameterSchemaOrContent, PathItem, ReferenceOr, RequestBody, Response, Schema, SecurityScheme,
    Server, StatusCode, StringFormat, VariantOrUnknownOrEmpty,
};
use serde_json::{Value, json};

use crate::exec::validation::{media_schema_to_template, openapi_schema_to_json_schema};
use crate::model::{
    AuthStyle, BodyTemplate, Confidence, EvidenceItem, FieldConfidence, HeaderField, KeyValueField,
    ParsedSource, RequestDraft, RuntimeSlot, SchemaSpec, SlotLocation, SourceInput, SourceKind,
};
use crate::util::{extract_slot_names, slot_token};

pub fn parse_openapi_input(raw_text: &str) -> ParsedSource {
    let source = SourceInput {
        kind: SourceKind::OpenApi,
        raw_text: raw_text.to_string(),
    };

    let mut notes = Vec::new();
    let mut candidates = Vec::new();

    match parse_document(raw_text) {
        Ok((document, synthetic_note)) => {
            if let Some(note) = synthetic_note {
                notes.push(note);
            }
            let resolver = Resolver::new(&document);
            for (path, path_item_ref) in document.paths.iter() {
                let Some(path_item) = resolver.resolve_path_item(path_item_ref) else {
                    notes.push(format!("Skipped unresolved path item ref for {path}"));
                    continue;
                };
                candidates.extend(path_item_to_drafts(&document, &resolver, path, &path_item));
            }
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

fn parse_document(raw_text: &str) -> Result<(OpenAPI, Option<String>)> {
    let value: Value = serde_json::from_str(raw_text)
        .or_else(|_| yaml_serde::from_str(raw_text))
        .context("OpenAPI input is not valid JSON or YAML")?;
    let (wrapped, note) = wrap_fragment(value);
    let document: OpenAPI =
        serde_json::from_value(wrapped).context("Could not deserialize OpenAPI document")?;
    Ok((document, note))
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
    if let Some(example) = &data.example {
        return Some(example_to_string(example));
    }
    match &data.format {
        ParameterSchemaOrContent::Schema(schema) => {
            resolver.resolve_schema(schema).and_then(|schema| {
                schema
                    .schema_data
                    .example
                    .map(|example| example_to_string(&example))
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
        return form_fields_from_media_type(media_type, resolver, slots, SlotLocation::Body)
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
        if multipart_has_binary(media_type, resolver) {
            *unsupported_reason =
                Some("Multipart file uploads are not supported in v1".to_string());
        }
        return form_fields_from_media_type(media_type, resolver, slots, SlotLocation::Body)
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
) -> Option<Vec<KeyValueField>> {
    let schema = media_schema(media_type, resolver)?;
    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(openapiv3::Type::Object(object_type)) => {
            let mut fields = Vec::new();
            for (name, property) in &object_type.properties {
                let value = if let Some(schema) = resolver.resolve_boxed_schema(property) {
                    media_schema_to_template(
                        &schema,
                        &|reference| resolver.resolve_schema(reference),
                        name,
                    )
                    .replace('\n', "")
                } else {
                    slot_token(name)
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
            .any(|schema| match &schema.schema_kind {
                openapiv3::SchemaKind::Type(openapiv3::Type::String(string_type)) => {
                    matches!(
                        string_type.format,
                        VariantOrUnknownOrEmpty::Item(StringFormat::Binary)
                    )
                }
                _ => false,
            }),
        _ => false,
    }
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
        return Some(example_to_string(example));
    }
    if let Some(example) = media_type.examples.values().next() {
        match example {
            ReferenceOr::Item(example) => {
                if let Some(value) = &example.value {
                    return Some(example_to_string(value));
                }
            }
            ReferenceOr::Reference { .. } => {}
        }
    }
    media_schema(media_type, resolver).map(|schema| {
        media_schema_to_template(
            &schema,
            &|reference| resolver.resolve_schema(reference),
            "body",
        )
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

struct Resolver<'a> {
    document: &'a OpenAPI,
}

impl<'a> Resolver<'a> {
    fn new(document: &'a OpenAPI) -> Self {
        Self { document }
    }

    fn resolve_path_item(&self, value: &ReferenceOr<PathItem>) -> Option<PathItem> {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => {
                let parts = parse_ref(reference)?;
                if *parts.first()? != "paths" {
                    return None;
                }
                let path = unescape_ref_token(parts.get(1)?);
                self.document.paths.paths.get(&path)?.as_item().cloned()
            }
        }
    }

    fn resolve_parameter(&self, value: &ReferenceOr<Parameter>) -> Option<Parameter> {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => {
                let name = parse_component_ref(reference, "parameters")?;
                self.document
                    .components
                    .as_ref()?
                    .parameters
                    .get(name)?
                    .as_item()
                    .cloned()
            }
        }
    }

    fn resolve_request_body(&self, value: &ReferenceOr<RequestBody>) -> Option<RequestBody> {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => {
                let name = parse_component_ref(reference, "requestBodies")?;
                self.document
                    .components
                    .as_ref()?
                    .request_bodies
                    .get(name)?
                    .as_item()
                    .cloned()
            }
        }
    }

    fn resolve_response(&self, value: &ReferenceOr<Response>) -> Option<Response> {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => {
                let name = parse_component_ref(reference, "responses")?;
                self.document
                    .components
                    .as_ref()?
                    .responses
                    .get(name)?
                    .as_item()
                    .cloned()
            }
        }
    }

    fn resolve_schema(&self, value: &ReferenceOr<Schema>) -> Option<Schema> {
        match value {
            ReferenceOr::Item(item) => Some(item.clone()),
            ReferenceOr::Reference { reference } => {
                let name = parse_component_ref(reference, "schemas")?;
                self.document
                    .components
                    .as_ref()?
                    .schemas
                    .get(name)?
                    .as_item()
                    .cloned()
            }
        }
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
        components.security_schemes.get(name)?.as_item().cloned()
    }
}

fn parse_component_ref<'a>(reference: &'a str, component: &str) -> Option<&'a str> {
    let parts = parse_ref(reference)?;
    if parts.len() == 3 && parts[0] == "components" && parts[1] == component {
        Some(parts[2])
    } else {
        None
    }
}

fn parse_ref(reference: &str) -> Option<Vec<&str>> {
    reference
        .strip_prefix("#/")
        .map(|value| value.split('/').collect())
}

fn unescape_ref_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
mod tests {
    use super::parse_openapi_input;
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
}
