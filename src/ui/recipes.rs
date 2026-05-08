use eframe::egui;

use crate::app::FirstCallApp;

impl FirstCallApp {
    pub(crate) fn render_recipes(&mut self, root_ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.heading("Recipes");
            ui.horizontal(|ui| {
                ui.label("Search");
                ui.text_edit_singleline(&mut self.recipe_search);
            });
            ui.small("Package validation, inspection, import, and recipe-id automation remain CLI-first. These commands are hints only and are not executed by the GUI.");
            ui.separator();
            let query = self.recipe_search.to_ascii_lowercase();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for recipe in self.recipes.clone().into_iter().filter(|recipe| {
                    let haystack = format!(
                        "{} {} {} {} {}",
                        recipe.id,
                        recipe.name,
                        recipe.method,
                        recipe.url_template,
                        recipe
                            .last_success_status
                            .map(|status| status.to_string())
                            .unwrap_or_default()
                    )
                    .to_ascii_lowercase();
                    query.is_empty() || haystack.contains(&query)
                }) {
                    ui.group(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(format!("#{} {}", recipe.id, recipe.name));
                            ui.label(&recipe.method);
                            ui.label(format!(
                                "last status {}",
                                recipe
                                    .last_success_status
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "n/a".to_string())
                            ));
                        });
                        ui.small(format!(
                            "last success {}",
                            recipe
                                .last_success_at
                                .map(|value| value.to_rfc3339())
                                .unwrap_or_else(|| "not verified locally".to_string())
                        ));
                        ui.monospace(&recipe.url_template);
                        ui.horizontal(|ui| {
                            if ui.button("Rerun").clicked() {
                                self.rerun_recipe(recipe.id);
                            }
                            if ui.button("Copy As Curl").clicked() {
                                self.copy_recipe_as_curl(recipe.id, ui.ctx());
                            }
                            if ui.button("Export Markdown").clicked() {
                                self.export_recipe_markdown(recipe.id);
                            }
                            if ui.button("Export JSON").clicked() {
                                self.export_recipe_json(recipe.id);
                            }
                        });
                        ui.collapsing("CLI lifecycle hints", |ui| {
                            let out_dir = format!("./dist/recipe-{}", recipe.id);
                            ui.monospace(format!(
                                "cargo run --bin firstcall-cli -- package --recipe-id {} --out {}",
                                recipe.id, out_dir
                            ));
                            ui.monospace(format!(
                                "cargo run --bin firstcall-cli -- validate-package --dir {} --json",
                                out_dir
                            ));
                            ui.monospace(format!(
                                "cargo run --bin firstcall-cli -- inspect-package --dir {} --json",
                                out_dir
                            ));
                            ui.monospace(format!(
                                "cargo run --bin firstcall-cli -- verify --recipe-id {} --dry-run --json",
                                recipe.id
                            ));
                        });
                    });
                    ui.separator();
                }
            });
        });
    }
}
