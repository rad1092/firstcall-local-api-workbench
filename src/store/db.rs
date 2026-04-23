use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use rusqlite::Connection;

use crate::store::migrations::run_migrations;

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub db_path: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "rad1092", "FirstCall")
            .context("Could not determine platform storage directory")?;
        Self::from_root(dirs.data_local_dir(), dirs.config_dir())
    }

    pub fn from_root(data_dir: &Path, config_dir: &Path) -> Result<Self> {
        let exports_dir = data_dir.join("exports");
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            config_dir: config_dir.to_path_buf(),
            exports_dir,
            db_path: data_dir.join("firstcall.sqlite3"),
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.exports_dir)?;
        Ok(())
    }
}

pub fn open_database(paths: &AppPaths) -> Result<Connection> {
    paths.ensure_dirs()?;
    let connection = Connection::open(&paths.db_path)?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    run_migrations(&connection)?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{AppPaths, open_database};

    #[test]
    fn initializes_paths_and_database() {
        let root = tempdir().expect("tempdir");
        let paths = AppPaths::from_root(&root.path().join("data"), &root.path().join("config"))
            .expect("paths");
        let connection = open_database(&paths).expect("database should open");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'attempts'",
                [],
                |row| row.get(0),
            )
            .expect("table query");
        assert_eq!(count, 1);
    }
}
