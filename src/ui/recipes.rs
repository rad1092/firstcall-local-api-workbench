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
            ui.separator();
            let query = self.recipe_search.to_ascii_lowercase();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for recipe in self.recipes.clone().into_iter().filter(|recipe| {
                    query.is_empty()
                        || recipe.name.to_ascii_lowercase().contains(&query)
                        || recipe.url_template.to_ascii_lowercase().contains(&query)
                }) {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.strong(&recipe.name);
                            ui.label(&recipe.method);
                            ui.label(
                                recipe
                                    .last_success_status
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "n/a".to_string()),
                            );
                        });
                        ui.label(&recipe.url_template);
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
                    });
                    ui.separator();
                }
            });
        });
    }
}
