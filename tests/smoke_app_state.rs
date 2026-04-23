use tempfile::tempdir;

use firstcall::store::db::{AppPaths, open_database};
use firstcall::store::repos::AppRepository;

#[test]
fn app_state_storage_bootstrap_smoke() {
    let root = tempdir().expect("tempdir");
    let paths =
        AppPaths::from_root(&root.path().join("data"), &root.path().join("config")).expect("paths");
    let repository = AppRepository::new(open_database(&paths).expect("db"));
    let settings = repository.load_settings().expect("settings");
    assert_eq!(settings.timeout_secs, 30);
    assert!(paths.db_path.exists());
}
