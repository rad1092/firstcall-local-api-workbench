use std::path::Path;

use eframe::NativeOptions;
use firstcall::app::{BootstrapOptions, FirstCallApp, InputTab, TopScreen};
use firstcall::store::db::AppPaths;
use tracing_subscriber::EnvFilter;

fn main() {
    let options = match parse_args(std::env::args().skip(1).collect()) {
        Ok(ParsedArgs::Run(options)) => options,
        Ok(ParsedArgs::PrintAndExit(message)) => {
            println!("{message}");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let native_options = NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([1050.0, 700.0]),
        ..NativeOptions::default()
    };
    if let Err(error) = eframe::run_native(
        "FirstCall",
        native_options,
        Box::new(|cc| {
            firstcall::app::configure_theme(&cc.egui_ctx);
            Ok(Box::new(FirstCallApp::bootstrap_with_options(options)))
        }),
    ) {
        eprintln!("FirstCall failed to start: {error}");
    }
}

enum ParsedArgs {
    Run(BootstrapOptions),
    PrintAndExit(String),
}

fn parse_args(args: Vec<String>) -> anyhow::Result<ParsedArgs> {
    let mut data_dir = None;
    let mut config_dir = None;
    let mut screen = None;
    let mut sample_tab = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => return Ok(ParsedArgs::PrintAndExit(usage())),
            "--version" | "-V" => {
                return Ok(ParsedArgs::PrintAndExit(format!(
                    "firstcall {}",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            "--data-dir" => {
                index += 1;
                data_dir = args.get(index).cloned();
                if data_dir.is_none() {
                    anyhow::bail!("--data-dir requires a path");
                }
            }
            "--config-dir" => {
                index += 1;
                config_dir = args.get(index).cloned();
                if config_dir.is_none() {
                    anyhow::bail!("--config-dir requires a path");
                }
            }
            "--screen" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    anyhow::bail!("--screen requires one of: new, attempts, recipes, settings");
                };
                screen = Some(parse_screen(value)?);
            }
            "--sample" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    anyhow::bail!("--sample requires one of: curl, docs, openapi");
                };
                sample_tab = Some(parse_sample_tab(value)?);
            }
            value => anyhow::bail!("unknown argument: {value}"),
        }
        index += 1;
    }

    let paths = match (data_dir, config_dir) {
        (Some(data_dir), Some(config_dir)) => Some(AppPaths::from_root(
            Path::new(&data_dir),
            Path::new(&config_dir),
        )?),
        (None, None) => None,
        _ => anyhow::bail!("--data-dir and --config-dir must be provided together"),
    };

    Ok(ParsedArgs::Run(BootstrapOptions {
        paths,
        initial_screen: screen,
        sample_tab,
    }))
}

fn parse_screen(value: &str) -> anyhow::Result<TopScreen> {
    match value {
        "new" | "new-attempt" => Ok(TopScreen::NewAttempt),
        "attempts" => Ok(TopScreen::Attempts),
        "recipes" => Ok(TopScreen::Recipes),
        "settings" => Ok(TopScreen::Settings),
        _ => anyhow::bail!("--screen requires one of: new, attempts, recipes, settings"),
    }
}

fn parse_sample_tab(value: &str) -> anyhow::Result<InputTab> {
    match value {
        "curl" => Ok(InputTab::Curl),
        "docs" => Ok(InputTab::Docs),
        "openapi" | "open-api" => Ok(InputTab::OpenApi),
        _ => anyhow::bail!("--sample requires one of: curl, docs, openapi"),
    }
}

fn usage() -> String {
    [
        "Usage:",
        "  firstcall [--data-dir PATH --config-dir PATH] [--screen new|attempts|recipes|settings] [--sample curl|docs|openapi]",
        "  firstcall --version",
        "  firstcall --help",
    ]
    .join("\n")
}
