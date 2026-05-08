use eframe::egui;
use secrecy::SecretString;

use crate::app::{FirstCallApp, InputTab};
use crate::model::{BodyTemplate, HeaderField, KeyValueField, Outcome};

impl FirstCallApp {
    pub(crate) fn render_new_attempt(&mut self, root_ui: &mut egui::Ui) {
        egui::Panel::left("new_attempt_inputs")
            .resizable(true)
            .default_size(330.0)
            .show_inside(root_ui, |ui| {
                ui.heading("Inputs");
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (InputTab::Curl, "Paste curl"),
                        (InputTab::Docs, "Paste docs"),
                        (InputTab::OpenApi, "Paste OpenAPI"),
                    ] {
                        if ui
                            .selectable_label(self.inputs.active_tab == tab, label)
                            .clicked()
                        {
                            self.inputs.active_tab = tab;
                        }
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Load Sample").clicked() {
                        self.load_sample_for_active_tab();
                    }
                    if ui.button("Analyze Inputs").clicked() {
                        self.analyze_inputs();
                    }
                    if ui.button("Reset").clicked() {
                        self.reset_inputs();
                    }
                });
                ui.separator();
                let buffer = match self.inputs.active_tab {
                    InputTab::Curl => &mut self.inputs.curl,
                    InputTab::Docs => &mut self.inputs.docs,
                    InputTab::OpenApi => &mut self.inputs.openapi,
                };
                ui.add(
                    egui::TextEdit::multiline(buffer)
                        .desired_rows(28)
                        .hint_text("Paste curl, docs, or OpenAPI here"),
                );
                ui.separator();
                ui.label("Extraction notes");
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .show(ui, |ui| {
                        for parsed in &self.parsed_sources {
                            ui.strong(match parsed.source.kind {
                                crate::model::SourceKind::Curl => "curl",
                                crate::model::SourceKind::Docs => "docs",
                                crate::model::SourceKind::OpenApi => "openapi",
                                crate::model::SourceKind::PostmanCollection => "postman",
                                crate::model::SourceKind::Har => "har",
                                crate::model::SourceKind::HttpFile => "http",
                                crate::model::SourceKind::Hurl => "hurl",
                                crate::model::SourceKind::Bruno => "bruno",
                                crate::model::SourceKind::Graphql => "graphql",
                            });
                            for note in &parsed.notes {
                                ui.label(format!("- {note}"));
                            }
                        }
                    });
            });

        egui::Panel::right("new_attempt_runtime")
            .resizable(true)
            .default_size(360.0)
            .show_inside(root_ui, |ui| {
                ui.heading("Run");
                if let Some(draft) = &mut self.working_draft {
                    ui.label(format!("Auth: {}", draft.auth.label()));
                    ui.label(format!(
                        "Unresolved required slots: {}",
                        draft.unresolved_slots().len()
                    ));
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            for slot in &mut draft.slots {
                                ui.horizontal(|ui| {
                                    ui.label(format!(
                                        "{} ({}, {})",
                                        slot.name,
                                        slot.location.label(),
                                        if slot.required {
                                            "required"
                                        } else {
                                            "optional"
                                        }
                                    ));
                                });
                                let response = ui.text_edit_singleline(
                                    slot.current_value.get_or_insert_with(String::new),
                                );
                                if response.changed()
                                    && slot.location == crate::model::SlotLocation::Auth
                                    && let Some(value) = &slot.current_value
                                    && !value.trim().is_empty()
                                {
                                    self.secret_store
                                        .set(&slot.name, SecretString::new(value.clone().into()));
                                    self.secret_status = self.secret_store.status();
                                }
                                if !slot.description.is_empty() {
                                    ui.small(&slot.description);
                                }
                                ui.separator();
                            }
                        });
                    let can_run = !self.is_running();
                    if ui
                        .add_enabled(can_run, egui::Button::new("Run Request"))
                        .clicked()
                    {
                        self.run_current_draft();
                    }
                    if ui.button("Save Successful Recipe").clicked() {
                        self.save_current_recipe();
                    }
                } else {
                    ui.label("Analyze input and select a candidate to run.");
                }

                ui.separator();
                ui.heading("Result");
                if let Some(result) = &self.last_execution {
                    ui.label(format!("Outcome: {}", result.outcome.label()));
                    if let Some(blocker) = &result.blocker {
                        ui.label(format!("Blocker: {}", blocker.label()));
                    }
                    if let Some(response) = &result.response_snapshot {
                        ui.label(format!(
                            "Status: {}",
                            response
                                .status
                                .map(|status| status.to_string())
                                .unwrap_or_else(|| "n/a".to_string())
                        ));
                        ui.label(format!("Elapsed: {} ms", response.elapsed_ms));
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
                        let mut preview = response.body_preview.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut preview)
                                .desired_rows(16)
                                .interactive(false),
                        );
                    } else if result.outcome == Outcome::Failure {
                        ui.label(&result.notes);
                    }
                } else {
                    ui.label("No request has been executed yet.");
                }
            });

        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Candidates And Builder");
            ui.separator();
            egui::ScrollArea::vertical()
                .max_height(140.0)
                .show(ui, |ui| {
                    for index in 0..self.candidate_drafts.len() {
                        let candidate = &self.candidate_drafts[index];
                        let selected = self.selected_candidate == Some(index);
                        if ui
                            .selectable_label(
                                selected,
                                format!(
                                    "{} [{}]",
                                    candidate.endpoint_summary(),
                                    candidate.confidence.overall.label()
                                ),
                            )
                            .clicked()
                        {
                            self.select_candidate(index);
                        }
                    }
                });

            ui.separator();
            if let Some(draft) = &mut self.working_draft {
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

                ui.separator();
                ui.label("Evidence");
                for item in &draft.evidence {
                    ui.label(format!(
                        "- {} [{}] {}",
                        item.label,
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
