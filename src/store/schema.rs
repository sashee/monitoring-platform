//! Connection setup and forward-only migrations (SPEC §6.1, §6.2).

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Schema version this binary understands. Tracked in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

const MIGRATIONS: &[&str] = &[
    // → version 1
    r#"
    CREATE TABLE measurement (
      id             INTEGER PRIMARY KEY,
      event_time     INTEGER NOT NULL,
      processed_time INTEGER NOT NULL,
      type           TEXT    NOT NULL,
      body           TEXT,
      attributes     TEXT    NOT NULL DEFAULT '{}'
    ) STRICT;

    CREATE INDEX measurement_type_event_time_idx ON measurement (type, event_time DESC, id DESC);
    CREATE INDEX measurement_event_time_idx      ON measurement (event_time DESC, id DESC);
    "#,
];

/// No `foreign_keys` pragma: the schema has one table and no foreign keys, so enabling it would
/// imply a constraint that does not exist.
fn apply_pragmas(conn: &Connection) -> Result<()> {
    // journal_mode returns a row, so it needs query_row rather than execute.
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .context("setting journal_mode = WAL")?;
    if !mode.eq_ignore_ascii_case("wal") {
        bail!("could not enable WAL mode (got {mode:?})");
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    Ok(())
}

/// Opens the single write connection and brings the schema up to date.
pub fn open_write(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening database {}", path.display()))?;
    apply_pragmas(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// Opens a short-lived read-only connection (SPEC §6.4).
pub fn open_read(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening database {} read-only", path.display()))?;
    // WAL mode is a property of the file, not the connection, so it is not set here. busy_timeout
    // is per-connection and still worth having.
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    Ok(conn)
}

/// Runs any migrations the database has not seen, in one transaction.
///
/// A database from a *newer* binary is a fatal error rather than a downgrade attempt: continuing
/// would risk writing rows that the newer schema cannot represent.
pub fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

    if current > SCHEMA_VERSION {
        bail!(
            "database schema version {current} is newer than this binary supports \
             ({SCHEMA_VERSION}); refusing to downgrade"
        );
    }
    if current == SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<()> {
        for (i, migration) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            tracing::info!(to_version = i + 1, "applying migration");
            conn.execute_batch(migration)
                .with_context(|| format!("applying migration to version {}", i + 1))?;
        }
        // pragma_update cannot be parameterised, and SCHEMA_VERSION is a compile-time constant.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_from_empty_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA_VERSION);

        // Running again must be a no-op rather than re-applying CREATE TABLE.
        migrate(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE name='measurement'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn refuses_a_database_from_a_newer_binary() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        let err = migrate(&conn).unwrap_err().to_string();
        assert!(err.contains("newer than this binary"), "unexpected error: {err}");
    }

    /// STRICT is what makes the column types enforced rather than advisory.
    #[test]
    fn schema_is_strict() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let err = conn
            .execute(
                "INSERT INTO measurement (event_time, processed_time, type, attributes) \
                 VALUES ('not-a-number', 1, 't', '{}')",
                [],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot store TEXT value in INTEGER column"),
            "STRICT should have refused the insert; got: {err}"
        );
    }
}
