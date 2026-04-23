use rusqlite::{Connection, params};

pub fn run_migrations(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY
        )",
        [],
    )?;

    let current_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;

    if current_version < 1 {
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                http_status INTEGER,
                outcome TEXT NOT NULL,
                blocker TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                method TEXT NOT NULL,
                url_template TEXT NOT NULL,
                last_success_at TEXT,
                last_success_status INTEGER,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload_json TEXT NOT NULL
            );
            ",
        )?;
        connection.execute(
            "INSERT INTO schema_migrations(version) VALUES (?1)",
            params![1],
        )?;
    }

    Ok(())
}
