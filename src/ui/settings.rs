use eframe::egui;

use crate::app::FirstCallApp;

impl FirstCallApp {
    pub(crate) fn render_settings(&mut self, root_ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Settings");
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Timeout (seconds)");
                ui.add(egui::DragValue::new(&mut self.settings.timeout_secs).range(1..=300));
            });
            ui.horizontal(|ui| {
                ui.label("Response preview limit (bytes)");
                ui.add(
                    egui::DragValue::new(&mut self.settings.response_preview_limit_bytes)
                        .range(1024..=1_048_576),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Success status min");
                ui.add(
                    egui::DragValue::new(&mut self.settings.success_status_min).range(100..=599),
                );
                ui.label("max");
                ui.add(
                    egui::DragValue::new(&mut self.settings.success_status_max).range(100..=599),
                );
            });
            if ui.button("Save Settings").clicked() {
                self.save_settings();
            }

            ui.separator();
            ui.label(format!("Database: {}", self.paths.db_path.display()));
            ui.label(format!("Data dir: {}", self.paths.data_dir.display()));
            ui.label(format!("Exports dir: {}", self.paths.exports_dir.display()));
            ui.separator();
            ui.heading("Secret Storage");
            ui.label(format!("Secret storage: {}", self.secret_status.backend));
            if let Some(warning) = &self.secret_status.warning {
                ui.colored_label(egui::Color32::YELLOW, warning);
            }
            ui.small("session-memory keeps entered GUI secrets only for the current desktop session.");
            ui.small("native-keyring is optional and feature-gated by the native-keyring Cargo feature; it may fall back to session-memory when unavailable.");
            ui.small("firstcall-cli verification remains environment-first and does not read GUI keyring or session-memory secrets.");
            if let Some(warning) = &self.bootstrap_warning {
                ui.colored_label(egui::Color32::YELLOW, warning);
            }
        });
    }
}
