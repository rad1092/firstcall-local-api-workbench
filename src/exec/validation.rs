use openapiv3::{
    AdditionalProperties, AnySchema, ReferenceOr, Schema, SchemaData, SchemaKind, Type,
};
use serde_json::{Map, Value, json};

use crate::model::ValidationResult;

pub fn validate_json_schema(schema: &Value, instance: &Value) -> ValidationResult {
    match jsonschema::validator_for(schema) {
        Ok(validator) => {
            let errors: Vec<String> = validator
                .iter_errors(instance)
                .map(|error| format!("{error}"))
                .collect();
            ValidationResult {
                valid: errors.is_empty(),
                errors,
            }
        }
        Err(error) => ValidationResult {
            valid: false,
            errors: vec![format!("Schema compilation failed: {error}")],
        },
    }
}

pub fn openapi_schema_to_json_schema<F>(schema: &Schema, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let mut converted = convert_schema(schema, resolver);
    if schema.schema_data.nullable {
        converted = json!({
            "anyOf": [
                converted,
                { "type": "null" }
            ]
        });
    }
    converted
}

pub fn media_schema_to_template<F>(schema: &Schema, resolver: &F, name_hint: &str) -> String
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let value = template_value_for_schema(schema, resolver, name_hint);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

fn convert_schema<F>(schema: &Schema, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let mut object = Map::new();
    add_schema_metadata(&schema.schema_data, &mut object);

    match &schema.schema_kind {
        SchemaKind::Type(typ) => merge_json_object(&mut object, convert_type(typ, resolver)),
        SchemaKind::OneOf { one_of } => {
            object.insert(
                "oneOf".to_string(),
                Value::Array(
                    one_of
                        .iter()
                        .filter_map(|item| resolve_value(item, resolver))
                        .collect(),
                ),
            );
        }
        SchemaKind::AnyOf { any_of } => {
            object.insert(
                "anyOf".to_string(),
                Value::Array(
                    any_of
                        .iter()
                        .filter_map(|item| resolve_value(item, resolver))
                        .collect(),
                ),
            );
        }
        SchemaKind::AllOf { all_of } => {
            object.insert(
                "allOf".to_string(),
                Value::Array(
                    all_of
                        .iter()
                        .filter_map(|item| resolve_value(item, resolver))
                        .collect(),
                ),
            );
        }
        SchemaKind::Not { not } => {
            if let Some(value) = resolve_value(not.as_ref(), resolver) {
                object.insert("not".to_string(), value);
            }
        }
        SchemaKind::Any(any) => merge_json_object(&mut object, convert_any(any, resolver)),
    }

    Value::Object(object)
}

fn add_schema_metadata(schema_data: &SchemaData, object: &mut Map<String, Value>) {
    if let Some(title) = &schema_data.title {
        object.insert("title".to_string(), Value::String(title.clone()));
    }
    if let Some(description) = &schema_data.description {
        object.insert(
            "description".to_string(),
            Value::String(description.clone()),
        );
    }
    if let Some(default) = &schema_data.default {
        object.insert("default".to_string(), default.clone());
    }
    if let Some(example) = &schema_data.example {
        object.insert("examples".to_string(), Value::Array(vec![example.clone()]));
    }
}

fn convert_type<F>(typ: &Type, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    match typ {
        Type::String(value) => {
            let mut object = Map::new();
            object.insert("type".to_string(), Value::String("string".to_string()));
            if !value.enumeration.is_empty() {
                object.insert(
                    "enum".to_string(),
                    Value::Array(
                        value
                            .enumeration
                            .iter()
                            .map(|item| item.clone().map(Value::String).unwrap_or(Value::Null))
                            .collect(),
                    ),
                );
            }
            if let Some(pattern) = &value.pattern {
                object.insert("pattern".to_string(), Value::String(pattern.clone()));
            }
            if let Some(min) = value.min_length {
                object.insert("minLength".to_string(), json!(min));
            }
            if let Some(max) = value.max_length {
                object.insert("maxLength".to_string(), json!(max));
            }
            Value::Object(object)
        }
        Type::Number(value) => {
            let mut object = number_like_schema("number");
            if let Some(multiple) = value.multiple_of {
                object.insert("multipleOf".to_string(), json!(multiple));
            }
            if let Some(min) = value.minimum {
                object.insert(
                    if value.exclusive_minimum {
                        "exclusiveMinimum".to_string()
                    } else {
                        "minimum".to_string()
                    },
                    json!(min),
                );
            }
            if let Some(max) = value.maximum {
                object.insert(
                    if value.exclusive_maximum {
                        "exclusiveMaximum".to_string()
                    } else {
                        "maximum".to_string()
                    },
                    json!(max),
                );
            }
            if !value.enumeration.is_empty() {
                object.insert(
                    "enum".to_string(),
                    Value::Array(
                        value
                            .enumeration
                            .iter()
                            .map(|item| item.map(Value::from).unwrap_or(Value::Null))
                            .collect(),
                    ),
                );
            }
            Value::Object(object)
        }
        Type::Integer(value) => {
            let mut object = number_like_schema("integer");
            if let Some(multiple) = value.multiple_of {
                object.insert("multipleOf".to_string(), json!(multiple));
            }
            if let Some(min) = value.minimum {
                object.insert(
                    if value.exclusive_minimum {
                        "exclusiveMinimum".to_string()
                    } else {
                        "minimum".to_string()
                    },
                    json!(min),
                );
            }
            if let Some(max) = value.maximum {
                object.insert(
                    if value.exclusive_maximum {
                        "exclusiveMaximum".to_string()
                    } else {
                        "maximum".to_string()
                    },
                    json!(max),
                );
            }
            if !value.enumeration.is_empty() {
                object.insert(
                    "enum".to_string(),
                    Value::Array(
                        value
                            .enumeration
                            .iter()
                            .map(|item| item.map(Value::from).unwrap_or(Value::Null))
                            .collect(),
                    ),
                );
            }
            Value::Object(object)
        }
        Type::Boolean(value) => {
            let mut object = Map::new();
            object.insert("type".to_string(), Value::String("boolean".to_string()));
            if !value.enumeration.is_empty() {
                object.insert(
                    "enum".to_string(),
                    Value::Array(
                        value
                            .enumeration
                            .iter()
                            .map(|item| item.map(Value::Bool).unwrap_or(Value::Null))
                            .collect(),
                    ),
                );
            }
            Value::Object(object)
        }
        Type::Object(value) => object_schema(value, resolver),
        Type::Array(value) => array_schema(value, resolver),
    }
}

fn object_schema<F>(value: &openapiv3::ObjectType, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let mut object = Map::new();
    object.insert("type".to_string(), Value::String("object".to_string()));
    if !value.properties.is_empty() {
        let mut properties = Map::new();
        for (name, property) in &value.properties {
            if let Some(schema) = resolve_boxed_value(property, resolver) {
                properties.insert(name.clone(), schema);
            }
        }
        object.insert("properties".to_string(), Value::Object(properties));
    }
    if !value.required.is_empty() {
        object.insert(
            "required".to_string(),
            Value::Array(value.required.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(additional) = &value.additional_properties {
        match additional {
            AdditionalProperties::Any(flag) => {
                object.insert("additionalProperties".to_string(), Value::Bool(*flag));
            }
            AdditionalProperties::Schema(schema) => {
                if let Some(value) = resolve_value(schema.as_ref(), resolver) {
                    object.insert("additionalProperties".to_string(), value);
                }
            }
        }
    }
    if let Some(min) = value.min_properties {
        object.insert("minProperties".to_string(), json!(min));
    }
    if let Some(max) = value.max_properties {
        object.insert("maxProperties".to_string(), json!(max));
    }
    Value::Object(object)
}

fn array_schema<F>(value: &openapiv3::ArrayType, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let mut object = Map::new();
    object.insert("type".to_string(), Value::String("array".to_string()));
    if let Some(items) = &value.items
        && let Some(schema) = resolve_boxed_value(items, resolver)
    {
        object.insert("items".to_string(), schema);
    }
    if let Some(min) = value.min_items {
        object.insert("minItems".to_string(), json!(min));
    }
    if let Some(max) = value.max_items {
        object.insert("maxItems".to_string(), json!(max));
    }
    if value.unique_items {
        object.insert("uniqueItems".to_string(), Value::Bool(true));
    }
    Value::Object(object)
}

fn number_like_schema(type_name: &str) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("type".to_string(), Value::String(type_name.to_string()));
    object
}

fn convert_any<F>(any: &AnySchema, resolver: &F) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    let mut object = Map::new();
    if let Some(typ) = &any.typ {
        object.insert("type".to_string(), Value::String(typ.clone()));
    }
    if !any.properties.is_empty() {
        let mut properties = Map::new();
        for (name, schema) in &any.properties {
            if let Some(value) = resolve_boxed_value(schema, resolver) {
                properties.insert(name.clone(), value);
            }
        }
        object.insert("properties".to_string(), Value::Object(properties));
    }
    if !any.required.is_empty() {
        object.insert(
            "required".to_string(),
            Value::Array(any.required.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(additional) = &any.additional_properties {
        match additional {
            AdditionalProperties::Any(flag) => {
                object.insert("additionalProperties".to_string(), Value::Bool(*flag));
            }
            AdditionalProperties::Schema(schema) => {
                if let Some(value) = resolve_value(schema.as_ref(), resolver) {
                    object.insert("additionalProperties".to_string(), value);
                }
            }
        }
    }
    if let Some(items) = &any.items
        && let Some(value) = resolve_boxed_value(items, resolver)
    {
        object.insert("items".to_string(), value);
    }
    if let Some(pattern) = &any.pattern {
        object.insert("pattern".to_string(), Value::String(pattern.clone()));
    }
    if let Some(multiple) = any.multiple_of {
        object.insert("multipleOf".to_string(), json!(multiple));
    }
    if let Some(minimum) = any.minimum {
        object.insert("minimum".to_string(), json!(minimum));
    }
    if let Some(maximum) = any.maximum {
        object.insert("maximum".to_string(), json!(maximum));
    }
    if let Some(min_items) = any.min_items {
        object.insert("minItems".to_string(), json!(min_items));
    }
    if let Some(max_items) = any.max_items {
        object.insert("maxItems".to_string(), json!(max_items));
    }
    if any.unique_items.unwrap_or(false) {
        object.insert("uniqueItems".to_string(), Value::Bool(true));
    }
    if let Some(min_properties) = any.min_properties {
        object.insert("minProperties".to_string(), json!(min_properties));
    }
    if let Some(max_properties) = any.max_properties {
        object.insert("maxProperties".to_string(), json!(max_properties));
    }
    if let Some(min_length) = any.min_length {
        object.insert("minLength".to_string(), json!(min_length));
    }
    if let Some(max_length) = any.max_length {
        object.insert("maxLength".to_string(), json!(max_length));
    }
    if !any.one_of.is_empty() {
        object.insert(
            "oneOf".to_string(),
            Value::Array(
                any.one_of
                    .iter()
                    .filter_map(|item| resolve_value(item, resolver))
                    .collect(),
            ),
        );
    }
    if !any.any_of.is_empty() {
        object.insert(
            "anyOf".to_string(),
            Value::Array(
                any.any_of
                    .iter()
                    .filter_map(|item| resolve_value(item, resolver))
                    .collect(),
            ),
        );
    }
    if !any.all_of.is_empty() {
        object.insert(
            "allOf".to_string(),
            Value::Array(
                any.all_of
                    .iter()
                    .filter_map(|item| resolve_value(item, resolver))
                    .collect(),
            ),
        );
    }
    if let Some(not) = &any.not
        && let Some(value) = resolve_value(not.as_ref(), resolver)
    {
        object.insert("not".to_string(), value);
    }
    if !any.enumeration.is_empty() {
        object.insert("enum".to_string(), Value::Array(any.enumeration.clone()));
    }
    Value::Object(object)
}

fn resolve_value<F>(reference: &ReferenceOr<Schema>, resolver: &F) -> Option<Value>
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    match reference {
        ReferenceOr::Item(schema) => Some(openapi_schema_to_json_schema(schema, resolver)),
        ReferenceOr::Reference { .. } => {
            resolver(reference).map(|schema| openapi_schema_to_json_schema(&schema, resolver))
        }
    }
}

fn resolve_boxed_value<F>(reference: &ReferenceOr<Box<Schema>>, resolver: &F) -> Option<Value>
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    match reference {
        ReferenceOr::Item(schema) => Some(openapi_schema_to_json_schema(schema.as_ref(), resolver)),
        ReferenceOr::Reference { reference } => {
            let unboxed = ReferenceOr::<Schema>::Reference {
                reference: reference.clone(),
            };
            resolver(&unboxed).map(|schema| openapi_schema_to_json_schema(&schema, resolver))
        }
    }
}

fn merge_json_object(into: &mut Map<String, Value>, value: Value) {
    if let Value::Object(map) = value {
        into.extend(map);
    }
}

fn template_value_for_schema<F>(schema: &Schema, resolver: &F, name_hint: &str) -> Value
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    if let Some(example) = &schema.schema_data.example {
        return example.clone();
    }
    if let Some(default) = &schema.schema_data.default {
        return default.clone();
    }

    match &schema.schema_kind {
        SchemaKind::Type(typ) => match typ {
            Type::String(string_type) => string_type
                .enumeration
                .iter()
                .flatten()
                .next()
                .map(|value| Value::String(value.clone()))
                .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
            Type::Number(number_type) => number_type
                .enumeration
                .iter()
                .flatten()
                .next()
                .map(|value| json!(value))
                .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
            Type::Integer(integer_type) => integer_type
                .enumeration
                .iter()
                .flatten()
                .next()
                .map(|value| json!(value))
                .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
            Type::Boolean(boolean_type) => boolean_type
                .enumeration
                .iter()
                .flatten()
                .next()
                .map(|value| Value::Bool(*value))
                .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
            Type::Array(array_type) => {
                if let Some(items) = &array_type.items {
                    if let Some(value) =
                        resolve_boxed_template(items, resolver, &format!("{name_hint}_item"))
                    {
                        Value::Array(vec![value])
                    } else {
                        Value::Array(Vec::new())
                    }
                } else {
                    Value::Array(Vec::new())
                }
            }
            Type::Object(object_type) => {
                let mut object = Map::new();
                for (property_name, property_schema) in &object_type.properties {
                    if let Some(value) =
                        resolve_boxed_template(property_schema, resolver, property_name)
                    {
                        object.insert(property_name.clone(), value);
                    }
                }
                Value::Object(object)
            }
        },
        SchemaKind::OneOf { one_of } => one_of
            .iter()
            .find_map(|schema| resolve_template(schema, resolver, name_hint))
            .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
        SchemaKind::AnyOf { any_of } => any_of
            .iter()
            .find_map(|schema| resolve_template(schema, resolver, name_hint))
            .unwrap_or_else(|| Value::String(format!("{{{{{name_hint}}}}}"))),
        SchemaKind::AllOf { all_of } => {
            let mut object = Map::new();
            for schema in all_of {
                if let Some(Value::Object(map)) = resolve_template(schema, resolver, name_hint) {
                    object.extend(map);
                }
            }
            Value::Object(object)
        }
        SchemaKind::Not { .. } => Value::String(format!("{{{{{name_hint}}}}}")),
        SchemaKind::Any(any) => {
            if !any.properties.is_empty() {
                let mut object = Map::new();
                for (property_name, schema) in &any.properties {
                    if let Some(value) = resolve_boxed_template(schema, resolver, property_name) {
                        object.insert(property_name.clone(), value);
                    }
                }
                Value::Object(object)
            } else if let Some(typ) = &any.typ {
                Value::String(format!("{{{{{name_hint}_{typ}}}}}"))
            } else {
                Value::String(format!("{{{{{name_hint}}}}}"))
            }
        }
    }
}

fn resolve_template<F>(
    reference: &ReferenceOr<Schema>,
    resolver: &F,
    name_hint: &str,
) -> Option<Value>
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    match reference {
        ReferenceOr::Item(schema) => Some(template_value_for_schema(schema, resolver, name_hint)),
        ReferenceOr::Reference { .. } => resolver(reference)
            .map(|schema| template_value_for_schema(&schema, resolver, name_hint)),
    }
}

fn resolve_boxed_template<F>(
    reference: &ReferenceOr<Box<Schema>>,
    resolver: &F,
    name_hint: &str,
) -> Option<Value>
where
    F: Fn(&ReferenceOr<Schema>) -> Option<Schema>,
{
    match reference {
        ReferenceOr::Item(schema) => Some(template_value_for_schema(
            schema.as_ref(),
            resolver,
            name_hint,
        )),
        ReferenceOr::Reference { reference } => {
            let unboxed = ReferenceOr::<Schema>::Reference {
                reference: reference.clone(),
            };
            resolver(&unboxed).map(|schema| template_value_for_schema(&schema, resolver, name_hint))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_json_schema;

    #[test]
    fn validates_json_schema_and_reports_error() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "string" }
            }
        });
        let good = validate_json_schema(&schema, &json!({ "id": "cus_123" }));
        assert!(good.valid);
        let bad = validate_json_schema(&schema, &json!({ "id": 42 }));
        assert!(!bad.valid);
        assert!(!bad.errors.is_empty());
    }
}
