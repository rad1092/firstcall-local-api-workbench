use std::collections::BTreeSet;

use eframe::egui;

use crate::app::{FirstCallApp, InputTab, primary_button};
use crate::exec::redact::{redact_request, redact_response};
use crate::model::{BodyTemplate, HeaderField, KeyValueField, Outcome, SlotLocation, SourceKind};

impl FirstCallApp {
    pub(crate) fn render_new_attempt(&mut self, root_ui: &mut egui::Ui) {
        let is_running = self.is_running();
        egui::Panel::left("new_attempt_inputs")
            .resizable(true)
            .default_size(350.0)
            .min_size(280.0)
            .max_size(460.0)
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(247, 249, 253)).inner_margin(18))
            .show_inside(root_ui, |ui| {
                egui::ScrollArea::vertical().id_salt("source-panel-scroll").show(ui, |ui| {
                ui.label(egui::RichText::new("Request source").size(21.0).strong());
                ui.small("Start with a request you want your AI to use.");
                ui.add_space(4.0);
                ui.add_enabled_ui(!is_running, |ui| {
                    egui::ComboBox::from_label("Source kind")
                        .selected_text(self.inputs.active_tab.label())
                        .show_ui(ui, |ui| {
                            for tab in [InputTab::Curl, InputTab::OpenApi] {
                                ui.selectable_value(&mut self.inputs.active_tab, tab, tab.label());
                            }
                            ui.separator();
                            ui.label("Other request formats");
                            for tab in InputTab::ALL.into_iter().filter(|tab| !matches!(tab, InputTab::Curl | InputTab::OpenApi)) {
                                ui.selectable_value(&mut self.inputs.active_tab, tab, tab.label());
                            }
                        });
                });
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            !is_running && self.inputs.active_tab.has_sample(),
                            egui::Button::new("Try an example"),
                        )
                        .clicked()
                    {
                        self.load_sample_for_active_tab();
                        self.analyze_inputs();
                    }
                    if ui
                        .add_enabled(!is_running, egui::Button::new("Reset"))
                        .clicked()
                    {
                        self.reset_inputs();
                    }
                });
                let active_tab = self.inputs.active_tab;
                let hint = active_tab.hint();
                let buffer = self.inputs.buffer_mut(active_tab);
                ui.add_enabled_ui(!is_running, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(buffer)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(12)
                            .margin(12.0)
                            .hint_text(hint),
                    );
                });
                if ui.add_enabled(!is_running, primary_button("Read request")).clicked() { self.analyze_inputs(); }
                ui.small("The request is read locally. Nothing is sent until you choose Send and verify.");
                ui.add_space(10.0);
                ui.collapsing("Import details", |ui| {
                        if self.parsed_sources.is_empty() {
                            ui.small("Read a request to see parser notes and supported operations.");
                        }
                        for parsed in &self.parsed_sources {
                            ui.horizontal(|ui| {
                                ui.strong(source_kind_label(&parsed.source.kind));
                                ui.label(format!("{} candidate(s)", parsed.candidates.len()));
                            });
                            if parsed.notes.is_empty() {
                                ui.small("No parser notes.");
                            } else {
                                for note in &parsed.notes {
                                    ui.label(format!("- {note}"));
                                }
                            }
                            ui.separator();
                        }
                });
                });
            });

        egui::Panel::right("new_attempt_runtime")
            .resizable(true)
            .default_size(330.0)
            .min_size(280.0)
            .max_size(430.0)
            .frame(
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(247, 249, 253))
                    .inner_margin(18),
            )
            .show_inside(root_ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("verify-panel-scroll")
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Verification").size(21.0).strong());
                        ui.small("Use real inputs to confirm this operation works.");
                        if let Some(draft) = self.working_draft.as_ref() {
                            let missing_required = self.missing_required_slot_count(draft);
                            ui.small(format!("Authentication · {}", draft.auth.label()));
                            let missing_text = if missing_required == 0 {
                                "Required inputs are ready".to_string()
                            } else {
                                format!("{missing_required} required input(s) need a value")
                            };
                            if missing_required > 0 {
                                ui.colored_label(
                                    egui::Color32::from_rgb(153, 88, 15),
                                    missing_text,
                                );
                            } else {
                                ui.colored_label(
                                    egui::Color32::from_rgb(31, 117, 95),
                                    missing_text,
                                );
                            }
                        }

                        if let Some(draft) = self.working_draft.as_ref() {
                            let slots = draft.slots.clone();
                            let stored_auth_slots: BTreeSet<String> = slots
                                .iter()
                                .filter(|slot| slot.location == SlotLocation::Auth)
                                .filter(|slot| self.auth_slot_is_stored(&slot.name))
                                .map(|slot| slot.name.clone())
                                .collect();
                            let mut slot_updates = Vec::<(usize, Option<String>)>::new();
                            let mut auth_saves = Vec::<(String, String)>::new();

                            ui.separator();
                            egui::ScrollArea::vertical()
                                .max_height(290.0)
                                .show(ui, |ui| {
                                    for location in [
                                        SlotLocation::Auth,
                                        SlotLocation::Path,
                                        SlotLocation::Query,
                                        SlotLocation::Header,
                                        SlotLocation::Body,
                                    ] {
                                        let indexes = slots
                                            .iter()
                                            .enumerate()
                                            .filter(|(_, slot)| slot.location == location)
                                            .map(|(index, _)| index)
                                            .collect::<Vec<_>>();
                                        if indexes.is_empty() {
                                            continue;
                                        }

                                        ui.strong(format!("{} inputs", location.label()));
                                        for index in indexes {
                                            let slot = &slots[index];
                                            ui.horizontal(|ui| {
                                                ui.label(&slot.name);
                                                ui.small(if slot.required {
                                                    "required"
                                                } else {
                                                    "optional"
                                                });
                                            });

                                            if location == SlotLocation::Auth {
                                                let stored = stored_auth_slots.contains(&slot.name);
                                                if stored {
                                                    ui.small(format!(
                                                        "Stored in {}. Value is not displayed.",
                                                        self.secret_status.backend
                                                    ));
                                                }
                                                let entry = self
                                                    .auth_slot_inputs
                                                    .entry(slot.name.clone())
                                                    .or_default();
                                                ui.vertical(|ui| {
                                                    ui.add_enabled(
                                                        !is_running,
                                                        egui::TextEdit::singleline(entry)
                                                            .password(true)
                                                            .desired_width(f32::INFINITY)
                                                            .hint_text("enter secret value"),
                                                    );
                                                    if ui
                                                        .add_enabled(
                                                            !is_running && !entry.trim().is_empty(),
                                                            egui::Button::new("Save secret"),
                                                        )
                                                        .clicked()
                                                    {
                                                        auth_saves.push((
                                                            slot.name.clone(),
                                                            entry.clone(),
                                                        ));
                                                    }
                                                });
                                            } else {
                                                let mut value =
                                                    slot.current_value.clone().unwrap_or_default();
                                                if ui
                                                    .add_enabled(
                                                        !is_running,
                                                        egui::TextEdit::singleline(&mut value)
                                                            .desired_width(f32::INFINITY),
                                                    )
                                                    .changed()
                                                {
                                                    let next_value = if value.trim().is_empty() {
                                                        None
                                                    } else {
                                                        Some(value)
                                                    };
                                                    slot_updates.push((index, next_value));
                                                }
                                            }

                                            if !slot.description.is_empty() {
                                                ui.small(&slot.description);
                                            }
                                            ui.separator();
                                        }
                                    }
                                });

                            if let Some(draft) = &mut self.working_draft {
                                for (index, value) in slot_updates {
                                    if let Some(slot) = draft.slots.get_mut(index) {
                                        slot.current_value = value;
                                    }
                                }
                            }
                            for (slot_name, value) in auth_saves {
                                self.store_auth_slot_value(&slot_name, value);
                                self.auth_slot_inputs.remove(&slot_name);
                            }

                            if ui
                                .add_enabled(
                                    !is_running,
                                    primary_button(if is_running {
                                        "Sending request…"
                                    } else {
                                        "Send and verify"
                                    }),
                                )
                                .clicked()
                            {
                                self.run_current_draft();
                            }
                            if ui
                                .add_enabled(
                                    !is_running
                                        && self.last_successful_draft.is_some()
                                        && self.last_execution.as_ref().is_some_and(|result| {
                                            result.outcome == Outcome::Success
                                        }),
                                    primary_button("Continue to MCP tool"),
                                )
                                .clicked()
                            {
                                self.save_current_recipe();
                            }
                        } else {
                            ui.label("Read a request and choose an operation to verify it.");
                        }

                        ui.separator();
                        render_result(ui, self.last_execution.as_ref());
                    });
            });

        egui::CentralPanel::default().frame(egui::Frame::new().fill(egui::Color32::WHITE).inner_margin(20)).show_inside(root_ui, |ui| {
            egui::ScrollArea::vertical().id_salt("operation-panel-scroll").show(ui, |ui| {
            ui.label(egui::RichText::new("Operation").size(21.0).strong());
            ui.small("Review the API before sending a request.");
            ui.add_space(4.0);
            egui::ScrollArea::vertical()
                .max_height(145.0)
                .show(ui, |ui| {
                    for index in 0..self.candidate_drafts.len() {
                        let candidate = &self.candidate_drafts[index];
                        let selected = self.selected_candidate == Some(index);
                        let source_kinds = candidate
                            .source_kinds
                            .iter()
                            .map(source_kind_label)
                            .collect::<Vec<_>>()
                            .join(", ");
                        if ui
                            .add_enabled_ui(!is_running, |ui| {
                                ui.selectable_label(
                                    selected,
                                    format!("{}  {}", candidate.method, candidate.name),
                                )
                                .on_hover_text(format!("{} · {}", candidate.endpoint_summary(), source_kinds))
                                .clicked()
                            })
                            .inner
                        {
                            self.select_candidate(index);
                        }
                    }
                });

            ui.separator();
            if let Some(draft) = &mut self.working_draft {
                ui.label(egui::RichText::new(draft.endpoint_summary()).monospace().size(14.0));
                ui.small(format!(
                    "Sources: {}",
                    draft
                        .source_kinds
                        .iter()
                        .map(source_kind_label)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                if let Some(reason) = &draft.unsupported_reason {
                    ui.colored_label(egui::Color32::from_rgb(153, 88, 15), format!("Unsupported: {reason}"));
                }
                ui.separator();

                ui.add_enabled_ui(!is_running, |ui| {
                    ui.label("Operation name");
                    ui.add(egui::TextEdit::singleline(&mut draft.name).desired_width(f32::INFINITY));
                    ui.horizontal(|ui| { ui.label("Method"); ui.add(egui::TextEdit::singleline(&mut draft.method).desired_width(90.0)); });
                    ui.label("Base URL");
                        if draft.base_url.is_none() {
                            draft.base_url = Some(String::new());
                        }
                        if let Some(base_url) = &mut draft.base_url {
                            ui.add(egui::TextEdit::singleline(base_url).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                        }
                    ui.label("Path");
                    ui.add(egui::TextEdit::singleline(&mut draft.path).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));

                    ui.collapsing("Headers", |ui| {
                        edit_headers(ui, &mut draft.headers);
                    });
                    ui.collapsing("Query", |ui| {
                        edit_query(ui, &mut draft.query);
                    });
                    ui.collapsing("Body", |ui| {
                        edit_body(ui, &mut draft.body);
                    });
                });

                ui.separator();
                ui.collapsing("How this request was read", |ui| {
                ui.small(format!("{} · {}", draft.confidence.overall.label(), draft.confidence.notes));
                for item in &draft.evidence {
                    ui.small(format!(
                        "- {} [{}:{}] {}",
                        item.label,
                        source_kind_label(&item.source_kind),
                        item.confidence.label(),
                        item.detail
                    ));
                }
                });
            } else {
                ui.add_space(24.0);
                ui.strong("Your API operation will appear here");
                ui.label("Paste a request on the left, or try the public GitHub example to start without credentials.");
            }
            });
        });
    }
}

fn render_result(ui: &mut egui::Ui, result: Option<&crate::model::ExecutionResult>) {
    ui.label(egui::RichText::new("Response").size(19.0).strong());
    let Some(result) = result else {
        ui.small("The API response will appear here after verification.");
        return;
    };

    let request = redact_request(&result.rendered_request);
    ui.small(format!("{} {}", request.method, request.url));
    let (label, color) = match result.outcome {
        Outcome::Success => (
            "Verified successfully",
            egui::Color32::from_rgb(31, 117, 95),
        ),
        Outcome::Partial => (
            "Response needs attention",
            egui::Color32::from_rgb(153, 88, 15),
        ),
        Outcome::Failure => (
            "Request could not be verified",
            egui::Color32::from_rgb(173, 44, 56),
        ),
    };
    ui.label(egui::RichText::new(label).strong().color(color));
    if let Some(blocker) = &result.blocker {
        ui.small(blocker.label());
    }
    if !result.notes.is_empty() {
        ui.small(&result.notes);
    }

    if let Some(response) = result.response_snapshot.as_ref().map(redact_response) {
        ui.label(format!(
            "HTTP {} · {} ms",
            response
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "—".to_string()),
            response.elapsed_ms
        ));
        if let Some(error) = &response.transport_error {
            ui.colored_label(egui::Color32::from_rgb(173, 44, 56), error);
        }
        if !response.validation_errors.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(153, 88, 15), "Validation details");
            for error in &response.validation_errors {
                ui.label(format!("- {error}"));
            }
        }
        ui.collapsing("Response headers", |ui| {
            for header in &response.headers {
                ui.small(format!("{}: {}", header.key, header.value));
            }
        });
        ui.separator();
        ui.label("Body preview");
        let mut preview = serde_json::from_str::<serde_json::Value>(&response.body_preview)
            .ok()
            .and_then(|value| serde_json::to_string_pretty(&value).ok())
            .unwrap_or(response.body_preview);
        ui.add(
            egui::TextEdit::multiline(&mut preview)
                .code_editor()
                .desired_width(f32::INFINITY)
                .desired_rows(8)
                .margin(10)
                .interactive(false),
        );
    } else if result.outcome == Outcome::Failure {
        ui.label(&result.notes);
    }
}

fn source_kind_label(kind: &SourceKind) -> &'static str {
    match kind {
        SourceKind::Curl => "curl",
        SourceKind::Docs => "docs",
        SourceKind::OpenApi => "openapi",
        SourceKind::PostmanCollection => "postman",
        SourceKind::Har => "har",
        SourceKind::HttpFile => "http",
        SourceKind::Hurl => "hurl",
        SourceKind::Bruno => "bruno",
        SourceKind::Graphql => "graphql",
    }
}

fn edit_headers(ui: &mut egui::Ui, headers: &mut Vec<HeaderField>) {
    let mut remove = None;
    for (index, header) in headers.iter_mut().enumerate() {
        ui.group(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut header.key)
                    .hint_text("Header name")
                    .desired_width(f32::INFINITY),
            );
            ui.add(
                egui::TextEdit::singleline(&mut header.value)
                    .hint_text("Header value")
                    .desired_width(f32::INFINITY),
            );
            if ui.small_button("Remove").clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        headers.remove(index);
    }
    if ui.button("+ Header").clicked() {
        headers.push(HeaderField {
            key: String::new(),
            value: String::new(),
            required: false,
            description: String::new(),
            confidence: crate::model::Confidence::Low,
        });
    }
}

fn edit_query(ui: &mut egui::Ui, query: &mut Vec<KeyValueField>) {
    let mut remove = None;
    for (index, item) in query.iter_mut().enumerate() {
        ui.group(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut item.key)
                    .hint_text("Parameter name")
                    .desired_width(f32::INFINITY),
            );
            ui.add(
                egui::TextEdit::singleline(&mut item.value)
                    .hint_text("Parameter value")
                    .desired_width(f32::INFINITY),
            );
            if ui.small_button("Remove").clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        query.remove(index);
    }
    if ui.button("+ Query").clicked() {
        query.push(KeyValueField {
            key: String::new(),
            value: String::new(),
            required: false,
            description: String::new(),
            confidence: crate::model::Confidence::Low,
        });
    }
}

fn edit_body(ui: &mut egui::Ui, body: &mut BodyTemplate) {
    let mut current = match body {
        BodyTemplate::None => "none",
        BodyTemplate::Json { .. } => "json",
        BodyTemplate::Text { .. } => "text",
        BodyTemplate::Form { .. } => "form",
        BodyTemplate::Multipart { .. } => "multipart",
    }
    .to_string();

    egui::ComboBox::from_label("Body Type")
        .selected_text(&current)
        .show_ui(ui, |ui| {
            for option in ["none", "json", "text", "form", "multipart"] {
                ui.selectable_value(&mut current, option.to_string(), option);
            }
        });

    match current.as_str() {
        "none" => *body = BodyTemplate::None,
        "json" => {
            let template = match body {
                BodyTemplate::Json { template } => template.clone(),
                _ => "{}".to_string(),
            };
            *body = BodyTemplate::Json { template };
            if let BodyTemplate::Json { template } = body {
                ui.add(
                    egui::TextEdit::multiline(template)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(8)
                        .margin(10),
                );
            }
        }
        "text" => {
            let text = match body {
                BodyTemplate::Text { text } => text.clone(),
                _ => String::new(),
            };
            *body = BodyTemplate::Text { text };
            if let BodyTemplate::Text { text } = body {
                ui.add(
                    egui::TextEdit::multiline(text)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(8)
                        .margin(10),
                );
            }
        }
        "form" => {
            let mut fields = match body {
                BodyTemplate::Form { fields } => fields.clone(),
                _ => Vec::new(),
            };
            edit_query(ui, &mut fields);
            *body = BodyTemplate::Form { fields };
        }
        "multipart" => {
            let mut fields = match body {
                BodyTemplate::Multipart { fields } => fields.clone(),
                _ => Vec::new(),
            };
            edit_query(ui, &mut fields);
            *body = BodyTemplate::Multipart { fields };
        }
        _ => {}
    }
}
