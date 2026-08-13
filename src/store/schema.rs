//! Connection setup and forward-only migrations (SPEC §6.1, §6.2).

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Schema version this binary understands. Tracked in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 3;

const MIGRATIONS: &[&str] = &[
    // → version 1: the original table, keyed by rowid.
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
    // → version 2: content-addressed ids (SPEC §6.6). `id` becomes the hash of everything the
    // device sent, so `INSERT OR IGNORE` makes re-uploading a measurement a no-op.
    //
    // Existing rows are dropped rather than backfilled: version 1 was never deployed, and a
    // backfill would have to re-derive each id from stored JSON, which is exactly the kind of
    // second, subtly-different encoding path this design exists to avoid. If v1 data ever needs
    // preserving, re-ingest it rather than reconstructing ids here.
    //
    // Kept as a rowid table, NOT `WITHOUT ROWID`: measured over 20k realistic rows, WITHOUT ROWID
    // is *larger*, because secondary indexes must then carry the full 16-byte key as the row
    // locator instead of a compact rowid.
    r#"
    DROP TABLE measurement;

    CREATE TABLE measurement (
      id             BLOB    PRIMARY KEY,
      event_time     INTEGER NOT NULL,
      processed_time INTEGER NOT NULL,
      type           TEXT    NOT NULL,
      body           TEXT,
      attributes     TEXT    NOT NULL DEFAULT '{}'
    ) STRICT;

    CREATE INDEX measurement_type_event_time_idx ON measurement (type, event_time DESC, id DESC);
    CREATE INDEX measurement_event_time_idx      ON measurement (event_time DESC, id DESC);
    "#,
    // → version 3: API keys (SPEC §13).
    //
    // `id` is TEXT and holds the public half exactly as it appears in the token, because that is
    // what a request is looked up by: an unknown id costs one index probe and no hashing.
    //
    // `secret_hash` is the *only* record of the secret half — 32 bytes of domain-separated blake3,
    // never the secret itself, so a stolen database yields nothing that can authenticate.
    //
    // No `revoked_at`: revocation is deleting the row. A nullable column nothing reads yet would be
    // a thing to explain later rather than a feature, and the audit trail it would give is one the
    // journal already carries.
    r#"
    CREATE TABLE api_key (
      id          TEXT    PRIMARY KEY,
      secret_hash BLOB    NOT NULL,
      label       TEXT    NOT NULL,
      created_at  INTEGER NOT NULL
    ) STRICT;
    "#,
];

/// No `foreign_keys` pragma: `measurement` and `api_key` are independent — a key is not an owner of
/// the rows ingested with it — so enabling it would imply a constraint that does not exist.
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

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.query_row("SELECT count(*) FROM sqlite_master WHERE name = ?1", [name], |r| {
            r.get::<_, i64>(0)
        })
        .map(|n| n == 1)
        .unwrap_or(false)
    }

    /// A database that stopped at version 2 is what every already-deployed receiver has. The
    /// upgrade must add the key table without touching the measurements beside it.
    #[test]
    fn migrating_from_version_2_adds_keys_and_keeps_the_measurements() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.execute_batch(MIGRATIONS[1]).unwrap();
        conn.pragma_update(None, "user_version", 2i64).unwrap();
        conn.execute(
            "INSERT INTO measurement (id, event_time, processed_time, type, attributes) \
             VALUES (x'01', 1, 2, 'cpu', '{}')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();

        assert!(has_table(&conn, "api_key"));
        let rows: i64 =
            conn.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 1, "an existing measurement must survive the upgrade");
    }

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

    /// The v1 → v2 migration must run on a database that stopped at version 1, not only on an
    /// empty one — the step-by-step path is the one a real upgrade takes.
    #[test]
    fn migrates_stepwise_from_version_1() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();

        migrate(&conn).unwrap();

        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(has_table(&conn, "api_key"), "v3 must have run too");

        // `id` must now be a BLOB primary key, which is what makes INSERT OR IGNORE deduplicate.
        let ty: String = conn
            .query_row(
                "SELECT type FROM pragma_table_info('measurement') WHERE name='id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ty, "BLOB");
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
                "INSERT INTO measurement (id, event_time, processed_time, type, attributes) \
                 VALUES (x'00', 'not-a-number', 1, 't', '{}')",
                [],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot store TEXT value in INTEGER column"),
            "STRICT should have refused the insert; got: {err}"
        );
    }
}
