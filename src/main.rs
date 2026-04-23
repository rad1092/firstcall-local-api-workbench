use eframe::NativeOptions;
use firstcall::app::FirstCallApp;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let native_options = NativeOptions::default();
    if let Err(error) = eframe::run_native(
        "FirstCall",
        native_options,
        Box::new(|cc| Ok(Box::new(FirstCallApp::bootstrap(cc)))),
    ) {
        eprintln!("FirstCall failed to start: {error}");
    }
}
