use crate::app::{FirstCallApp, primary_button};
use crate::export::native_package::{is_mutating_recipe, validate_tool_definition};
use eframe::egui;

impl FirstCallApp {
    pub(crate) fn render_recipes(&mut self, root_ui: &mut egui::Ui) {
        if self.tool_editor.is_some() {
            self.render_tool_editor(root_ui);
            return;
        }
        let is_running = self.is_running();
        let export_directory = self
            .last_native_export
            .as_ref()
            .map(|exported| exported.directory.clone());
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(247, 249, 253)).inner_margin(28))
            .show_inside(root_ui, |ui| {
            egui::ScrollArea::vertical().id_salt(("verified-requests-result", export_directory)).show(ui, |ui| {
                ui.set_max_width(920.0);
                if let Some(exported) = self.last_native_export.clone() {
                    ui.heading(if exported.required_environment.is_empty() {
                        "Your MCP tool is ready to connect"
                    } else {
                        "Package created — add credentials to connect"
                    });
                    ui.label(format!("{} · package validated", exported.tool_name));
                    ui.label("Add this server entry to your AI client's local MCP settings, then restart its connection. The next tool call sends a new API request.");
                    if exported.required_environment.is_empty() {
                        ui.label("This request needs no authentication environment variables.");
                    } else {
                        ui.label("Fill these empty environment values in your client's settings:");
                        for name in &exported.required_environment { ui.monospace(name); }
                        ui.small("Only variable names were exported. Your API credentials stay out of the package.");
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(primary_button("Copy connection configuration")).clicked() {
                            ui.ctx().copy_text(exported.client_config.clone());
                            self.status_message = Some("Connection configuration copied. Add it to your AI client's MCP settings.".to_string());
                        }
                        if ui.button("Open package folder").clicked() { self.open_native_export_folder(); }
                    });
                    ui.monospace(exported.directory.display().to_string());
                    ui.collapsing("Connection configuration", |ui| {
                        let mut config = exported.client_config.clone();
                        ui.add(egui::TextEdit::multiline(&mut config).code_editor().interactive(false).desired_rows(12).desired_width(f32::INFINITY).margin(12));
                    });
                    ui.small("Keep the application and package at these locations. If either moves, export a new configuration.");
                    ui.add_space(20.0);
                    ui.separator();
                }
                ui.heading("Verified requests");
                ui.label("Turn a request that worked into a tool your AI client can call.");
                ui.horizontal_wrapped(|ui| { ui.add(egui::TextEdit::singleline(&mut self.recipe_search)
                    .hint_text("Search verified requests")
                    .desired_width(ui.available_width().min(520.0))); });
                ui.separator();
                if self.recipes.is_empty() {
                    ui.label("Your successfully verified requests will appear here.");
                    if ui.add(primary_button("Create your first tool")).clicked() { self.screen = crate::app::TopScreen::NewAttempt; }
                }
                let query = self.recipe_search.to_ascii_lowercase();
                for recipe in self.recipes.clone().into_iter().filter(|recipe| {
                    format!("{} {} {} {}", recipe.id, recipe.name, recipe.method, recipe.url_template).to_ascii_lowercase().contains(&query)
                }) {
                    egui::Frame::new()
                        .fill(egui::Color32::WHITE)
                        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(213, 222, 235)))
                        .corner_radius(10)
                        .inner_margin(16)
                        .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(&recipe.name); ui.label(&recipe.method);
                            if let Some(status) = recipe.last_success_status { ui.label(format!("HTTP {status}")); }
                        });
                        ui.monospace(&recipe.url_template);
                        ui.small(recipe.last_success_at.map(|time| format!("Last verified {}", time.format("%Y-%m-%d %H:%M UTC"))).unwrap_or_else(|| "Needs local verification".to_string()));
                        ui.horizontal_wrapped(|ui| {
                            if ui.add_enabled(!is_running && recipe.last_success_at.is_some(), primary_button("Create MCP tool")).clicked() { self.prepare_native_tool(recipe.id); }
                            if ui.add_enabled(!is_running, egui::Button::new("Verify again")).clicked() { self.rerun_recipe(recipe.id); }
                            if ui.button("Copy curl").clicked() { self.copy_recipe_as_curl(recipe.id, ui.ctx()); }
                        });
                        ui.collapsing("Other exports", |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.button("Markdown").clicked() { self.export_recipe_markdown(recipe.id); }
                                if ui.button("Recipe JSON").clicked() { self.export_recipe_json(recipe.id); }
                            });
                        });
                    });
                    ui.add_space(8.0);
                }
            });
        });
    }

    fn render_tool_editor(&mut self, root_ui: &mut egui::Ui) {
        let Some(mut editor) = self.tool_editor.take() else {
            return;
        };
        let mut cancel = false;
        let mut export = false;
        let recipe = self.repository.get_recipe(editor.recipe_id).ok().flatten();
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(247, 249, 253)).inner_margin(28))
            .show_inside(root_ui, |ui| {
            egui::ScrollArea::vertical().id_salt(("mcp-tool-editor", editor.recipe_id)).show(ui, |ui| {
                ui.set_max_width(920.0);
                ui.heading("Describe your MCP tool");
                ui.label("Help your AI client choose this tool and supply the right inputs.");
                ui.add_space(12.0);
                if let Some(recipe) = &recipe {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("Verified HTTP {}", recipe.last_success_status.unwrap_or_default()));
                        ui.monospace(format!("{} {}", recipe.method, crate::export::agent_package::sanitized_agent_url_template(recipe)));
                    });
                }
                ui.separator();
                ui.label("Tool name");
                ui.add(egui::TextEdit::singleline(&mut editor.definition.name).hint_text("find_customer").desired_width(ui.available_width().min(600.0)));
                ui.small("Letters, numbers, underscores, and hyphens. This is the name the AI will call.");
                ui.add_space(8.0);
                ui.label("Readable title");
                ui.add(egui::TextEdit::singleline(&mut editor.definition.title).hint_text("Find a customer").desired_width(ui.available_width()));
                ui.add_space(8.0);
                ui.label("When should the AI use it, and what does it return?");
                ui.add(egui::TextEdit::multiline(&mut editor.definition.description).hint_text("Find a customer by their ID. Returns their name, account status, and subscription so you can answer account questions.").desired_rows(3).desired_width(ui.available_width()).margin(10));
                ui.add_space(12.0);
                ui.label(egui::RichText::new("Inputs the AI supplies").size(20.0).strong());
                ui.small("Describe each value. Authentication comes separately from your client's environment.");
                let required = editor.definition.input_schema["required"].as_array().cloned().unwrap_or_default();
                if let Some(properties) = editor.definition.input_schema["properties"].as_object_mut() {
                    if properties.is_empty() { ui.label("No inputs are needed. This tool calls the verified operation as it is."); }
                    for (name, field) in properties {
                        egui::Frame::new()
                        .fill(egui::Color32::WHITE)
                        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(213, 222, 235)))
                        .corner_radius(10)
                        .inner_margin(16)
                        .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                            ui.horizontal_wrapped(|ui| {
                                ui.strong(name);
                                ui.small(if required.iter().any(|item| item.as_str() == Some(name)) { "required" } else { "optional" });
                                let mut kind = field["type"].as_str().unwrap_or("string").to_string();
                                egui::ComboBox::from_id_salt(("mcp-input-type", name)).selected_text(&kind).show_ui(ui, |ui| {
                                    for value in ["string", "integer", "number", "boolean"] { ui.selectable_value(&mut kind, value.to_string(), value); }
                                });
                                field["type"] = kind.into();
                            });
                            let mut description = field["description"].as_str().unwrap_or_default().to_string();
                            ui.add(egui::TextEdit::singleline(&mut description).hint_text("Explain this input in the API's terms").desired_width(ui.available_width()));
                            field["description"] = description.into();
                        });
                    }
                }
                ui.add_space(16.0);
                let mutating = recipe.as_ref().is_some_and(is_mutating_recipe);
                if mutating {
                    egui::Frame::new()
                        .fill(egui::Color32::WHITE)
                        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(213, 222, 235)))
                        .corner_radius(10)
                        .inner_margin(16)
                        .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.strong("This tool can change remote data");
                        ui.label("Each AI tool call will send this write request to the API. Enable it only when you intend to let the connected client perform this operation.");
                        ui.checkbox(&mut editor.allow_mutating, "Allow this MCP tool to send write requests");
                    });
                    ui.add_space(8.0);
                }
                let readiness = recipe.as_ref().map(|recipe| validate_tool_definition(recipe, &editor.definition)).unwrap_or_else(|| Err(anyhow::anyhow!("Saved request not found")));
                if let Err(error) = &readiness { ui.colored_label(egui::Color32::from_rgb(153, 88, 15), error.to_string()); }
                ui.small(format!("Creates a new {} folder with the verified request, tool definition, and connection configuration. FirstCall runs it directly; no npm or build step.", editor.definition.name));
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(readiness.is_ok() && (!mutating || editor.allow_mutating) && !self.is_running(), primary_button("Export MCP package")).clicked() { export = true; }
                    if ui.button("Back to verified requests").clicked() { cancel = true; }
                });
            });
        });
        if !cancel {
            self.tool_editor = Some(editor);
        }
        if export {
            self.choose_native_export_folder();
        }
    }
}
