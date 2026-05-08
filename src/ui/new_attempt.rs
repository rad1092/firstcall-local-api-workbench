use std::collections::BTreeSet;

use eframe::egui;

use crate::app::{FirstCallApp, InputTab};
use crate::exec::redact::{redact_request, redact_response};
use crate::model::{BodyTemplate, HeaderField, KeyValueField, Outcome, SlotLocation, SourceKind};

impl FirstCallApp {
    pub(crate) fn render_new_attempt(&mut self, root_ui: &mut egui::Ui) {
        let is_running = self.is_running();
        egui::Panel::left("new_attempt_inputs")
            .resizable(true)
            .default_size(360.0)
            .show_inside(root_ui, |ui| {
                ui.heading("Request Sources");
                ui.add_enabled_ui(!is_running, |ui| {
                    egui::ComboBox::from_label("Source kind")
                        .selected_text(self.inputs.active_tab.label())
                        .show_ui(ui, |ui| {
                            for tab in InputTab::ALL {
                                ui.selectable_value(&mut self.inputs.active_tab, tab, tab.label());
                            }
                        });
                });
                ui.small(self.inputs.active_tab.description());
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !is_running && self.inputs.active_tab.has_sample(),
                            egui::Button::new("Load Sample"),
                        )
                        .clicked()
                    {
                        self.load_sample_for_active_tab();
                    }
                    if ui
                        .add_enabled(!is_running, egui::Button::new("Analyze Sources"))
                        .clicked()
                    {
                        self.analyze_inputs();
                    }
                    if ui
                        .add_enabled(!is_running, egui::Button::new("Reset"))
                        .clicked()
                    {
                        self.reset_inputs();
                    }
                });
                ui.separator();
                let active_tab = self.inputs.active_tab;
                let hint = active_tab.hint();
                let buffer = self.inputs.buffer_mut(active_tab);
                ui.add_enabled_ui(!is_running, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(buffer)
                            .desired_rows(24)
                            .hint_text(hint),
                    );
                });
                ui.separator();
                ui.label("Parse notes");
                egui::ScrollArea::vertical()
                    .max_height(190.0)
                    .show(ui, |ui| {
                        if self.parsed_sources.is_empty() {
                            ui.small("Analyze one or more source buffers to see parser notes.");
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

        egui::Panel::right("new_attempt_runtime")
            .resizable(true)
            .default_size(380.0)
            .show_inside(root_ui, |ui| {
                ui.heading("Run");
                if let Some(draft) = self.working_draft.as_ref() {
                    let missing_required = self.missing_required_slot_count(draft);
                    ui.label(format!("Auth: {}", draft.auth.label()));
                    let missing_text = format!("Missing required slots: {missing_required}");
                    if missing_required > 0 {
                        ui.colored_label(egui::Color32::YELLOW, missing_text);
                    } else {
                        ui.label(missing_text);
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

                                ui.strong(format!("{} slots", location.label()));
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
                                        ui.horizontal(|ui| {
                                            ui.add_enabled(
                                                !is_running,
                                                egui::TextEdit::singleline(entry)
                                                    .password(true)
                                                    .hint_text("enter secret value"),
                                            );
                                            if ui
                                                .add_enabled(
                                                    !is_running && !entry.trim().is_empty(),
                                                    egui::Button::new("Save secret"),
                                                )
                                                .clicked()
                                            {
                                                auth_saves.push((slot.name.clone(), entry.clone()));
                                            }
                                        });
                                    } else {
                                        let mut value =
                                            slot.current_value.clone().unwrap_or_default();
                                        if ui
                                            .add_enabled(
                                                !is_running,
                                                egui::TextEdit::singleline(&mut value),
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
                        .add_enabled(!is_running, egui::Button::new("Run Request"))
                        .clicked()
                    {
                        self.run_current_draft();
                    }
                    if ui
                        .add_enabled(!is_running, egui::Button::new("Save Successful Recipe"))
                        .clicked()
                    {
                        self.save_current_recipe();
                    }
                } else {
                    ui.label("Analyze input and select a candidate to run.");
                }

                ui.separator();
                render_result(ui, self.last_execution.as_ref());
            });

        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Candidates And Builder");
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(format!("Candidates: {}", self.candidate_drafts.len()));
                if let Some(index) = self.selected_candidate {
                    ui.label(format!("Selected: {}", index + 1));
                }
            });
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
                                    format!(
                                        "{} [{}] {}",
                                        candidate.endpoint_summary(),
                                        candidate.confidence.overall.label(),
                                        source_kinds
                                    ),
                                )
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
                ui.strong(format!("{} {}", draft.method, draft.endpoint_summary()));
                ui.small(format!(
                    "Sources: {}",
                    draft
                        .source_kinds
                        .iter()
                        .map(source_kind_label)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                ui.small(format!(
                    "Confidence: {} - {}",
                    draft.confidence.overall.label(),
                    draft.confidence.notes
                ));
                if let Some(reason) = &draft.unsupported_reason {
                    ui.colored_label(egui::Color32::YELLOW, format!("Unsupported: {reason}"));
                }
                ui.separator();

                ui.add_enabled_ui(!is_running, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(&mut draft.name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Method");
                        ui.text_edit_singleline(&mut draft.method);
                        ui.label("Base URL");
                        if draft.base_url.is_none() {
                            draft.base_url = Some(String::new());
                        }
                        if let Some(base_url) = &mut draft.base_url {
                            ui.text_edit_singleline(base_url);
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Path");
                        ui.text_edit_singleline(&mut draft.path);
                    });

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
                ui.label("Evidence");
                for item in &draft.evidence {
                    ui.label(format!(
                        "- {} [{}:{}] {}",
                        item.label,
                        source_kind_label(&item.source_kind),
                        item.confidence.label(),
                        item.detail
                    ));
                }
            } else {
                ui.label("No candidate selected.");
            }
        });
    }
}

fn render_result(ui: &mut egui::Ui, result: Option<&crate::model::ExecutionResult>) {
    ui.heading("Result");
    let Some(result) = result else {
        ui.label("No request has been executed yet.");
        return;
    };

    let request = redact_request(&result.rendered_request);
    ui.label(format!("Request: {} {}", request.method, request.url));
    ui.label(format!("Outcome: {}", result.outcome.label()));
    if let Some(blocker) = &result.blocker {
        ui.label(format!("Blocker: {}", blocker.label()));
    }
    if !result.notes.is_empty() {
        ui.small(&result.notes);
    }

    if let Some(response) = result.response_snapshot.as_ref().map(redact_response) {
        ui.label(format!(
            "Status: {}",
            response
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ));
        ui.label(format!("Elapsed: {} ms", response.elapsed_ms));
        if let Some(error) = &response.transport_error {
            ui.colored_label(egui::Color32::YELLOW, error);
        }
        if !response.validation_errors.is_empty() {
            ui.colored_label(egui::Color32::YELLOW, "Validation errors");
            for error in &response.validation_errors {
                ui.label(format!("- {error}"));
            }
        }
        ui.separator();
        ui.label("Headers");
        egui::ScrollArea::vertical()
            .max_height(90.0)
            .show(ui, |ui| {
                for header in &response.headers {
                    ui.label(format!("{}: {}", header.key, header.value));
                }
            });
        ui.separator();
        ui.label("Body preview");
        let mut preview = response.body_preview;
        ui.add(
            egui::TextEdit::multiline(&mut preview)
                .desired_rows(14)
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
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut header.key);
            ui.text_edit_singleline(&mut header.value);
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
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut item.key);
            ui.text_edit_singleline(&mut item.value);
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
                ui.add(egui::TextEdit::multiline(template).desired_rows(12));
            }
        }
        "text" => {
            let text = match body {
                BodyTemplate::Text { text } => text.clone(),
                _ => String::new(),
            };
            *body = BodyTemplate::Text { text };
            if let BodyTemplate::Text { text } = body {
                ui.add(egui::TextEdit::multiline(text).desired_rows(8));
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
