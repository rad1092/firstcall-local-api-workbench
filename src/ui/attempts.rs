use eframe::egui;

use crate::app::FirstCallApp;

impl FirstCallApp {
    pub(crate) fn render_attempts(&mut self, root_ui: &mut egui::Ui) {
        egui::Panel::left("attempts_list")
            .resizable(true)
            .default_size(390.0)
            .show_inside(root_ui, |ui| {
                ui.heading("Attempts");
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for attempt in self.attempts.clone() {
                        let selected = self.selected_attempt_id == Some(attempt.id);
                        ui.group(|ui| {
                            if ui
                                .selectable_label(
                                    selected,
                                    format!(
                                        "#{} {} {}",
                                        attempt.id, attempt.method, attempt.endpoint
                                    ),
                                )
                                .clicked()
                            {
                                self.selected_attempt_id = Some(attempt.id);
                            }
                            ui.horizontal_wrapped(|ui| {
                                ui.label(format!(
                                    "status {}",
                                    attempt
                                        .http_status
                                        .map(|status| status.to_string())
                                        .unwrap_or_else(|| "n/a".to_string())
                                ));
                                ui.label(attempt.outcome.label());
                                if let Some(blocker) = &attempt.blocker {
                                    ui.label(blocker.label());
                                }
                            });
                            ui.small(attempt.created_at.to_rfc3339());
                            ui.horizontal(|ui| {
                                if ui.button("Reopen").clicked() {
                                    self.reopen_attempt(attempt.id);
                                }
                                if ui.button("Retry").clicked() {
                                    self.reopen_attempt(attempt.id);
                                    self.run_current_draft();
                                }
                            });
                        });
                        ui.separator();
                    }
                });
            });

        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Attempt Detail");
            ui.separator();
            let Some(id) = self.selected_attempt_id else {
                ui.label("Select an attempt to review the redacted request and response summary.");
                return;
            };

            match self.repository.get_attempt(id) {
                Ok(Some(attempt)) => {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(format!(
                            "{} {}",
                            attempt.rendered_request_redacted.method,
                            attempt.rendered_request_redacted.url
                        ));
                    });
                    ui.label(format!("Created: {}", attempt.created_at.to_rfc3339()));
                    ui.label(format!("Outcome: {}", attempt.outcome.label()));
                    if let Some(blocker) = &attempt.blocker {
                        ui.label(format!("Blocker: {}", blocker.label()));
                    }
                    if !attempt.notes.is_empty() {
                        ui.label(format!("Notes: {}", attempt.notes));
                    }
                    if !attempt.evidence_summary.is_empty() {
                        ui.label(format!("Evidence: {}", attempt.evidence_summary));
                    }
                    ui.separator();
                    ui.label("Request headers");
                    egui::ScrollArea::vertical()
                        .max_height(95.0)
                        .show(ui, |ui| {
                            for header in &attempt.rendered_request_redacted.headers {
                                ui.label(format!("{}: {}", header.key, header.value));
                            }
                        });
                    if let Some(body_preview) = &attempt.rendered_request_redacted.body_preview {
                        ui.label("Request body preview");
                        let mut preview = body_preview.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut preview)
                                .desired_rows(6)
                                .interactive(false),
                        );
                    }
                    ui.separator();
                    if let Some(response) = &attempt.response_snapshot_redacted {
                        ui.label(format!(
                            "Response status: {}",
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
                        ui.label("Response body preview");
                        let mut preview = response.body_preview.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut preview)
                                .desired_rows(12)
                                .interactive(false),
                        );
                    } else {
                        ui.label("No response snapshot was captured.");
                    }
                }
                Ok(None) => {
                    ui.label("Attempt not found.");
                }
                Err(error) => {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        format!("Could not load attempt: {error}"),
                    );
                }
            }
        });
    }
}
