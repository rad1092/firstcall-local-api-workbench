use eframe::egui;

use crate::app::FirstCallApp;

impl FirstCallApp {
    pub(crate) fn render_attempts(&mut self, root_ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Attempts");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for attempt in self.attempts.clone() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "{} {}",
                                attempt.method,
                                attempt
                                    .http_status
                                    .map(|status| status.to_string())
                                    .unwrap_or_else(|| "n/a".to_string())
                            ));
                            ui.label(attempt.created_at.to_rfc3339());
                            ui.label(attempt.outcome.label());
                            if let Some(blocker) = &attempt.blocker {
                                ui.label(blocker.label());
                            }
                        });
                        ui.label(&attempt.endpoint);
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
    }
}
