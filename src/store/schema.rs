//! Connection setup and forward-only migrations (SPEC §6.1, §6.2).

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Bound on both version components. [`Version::encode`] packs the minor into the low three decimal
/// digits, so a major of 1000 would be indistinguishable from 1.0. Three majors in this project's
/// life means the ceiling is not a real constraint; a silent collision would be.
const COMPONENT_LIMIT: i64 = 1000;

/// The schema version, as `major.minor` (SPEC §6.2).
///
/// The split is the whole point: it lets an *older* binary keep working against a database a newer
/// one has migrated. A minor bump may only add tables, indexes and defaulted columns — see the
/// comment on [`MIGRATIONS`] for the exact rule — so a binary that has never heard of one can still
/// read and write everything it does know about. Only a change that would break such a binary bumps
/// the major, and that is the one case [`migrate`] still refuses.
///
/// That matters because reverting to an older binary is routine here, not exceptional: the host runs
/// `system.autoUpgrade` nightly, so a locally-switched generation is replaced by whatever the
/// pipeline last delivered. Under a single version number every schema bump turned that revert into
/// a permanent startup failure retrying every 60 s (SPEC §9.2, §9.4).
///
/// Ordering is lexicographic on `(major, minor)`, which is what the derived `Ord` gives for fields
/// declared in this order — so 3.0 < 3.1 < 4.0, and 3.9 < 3.10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: i64,
    pub minor: i64,
}

impl Version {
    /// Range-checked at compile time wherever it is called in a const context, which is everywhere
    /// a version is *declared* — [`SCHEMA_VERSION`] and every [`MIGRATIONS`] entry.
    pub const fn new(major: i64, minor: i64) -> Self {
        assert!(major >= 0 && major < COMPONENT_LIMIT, "major version must be 0..1000");
        assert!(minor >= 0 && minor < COMPONENT_LIMIT, "minor version must be 0..1000");
        Self { major, minor }
    }

    /// What goes in `PRAGMA user_version`.
    ///
    /// A version with no minor component is written as the **bare major**, which is exactly the form
    /// every database written before this scheme is already in. So introducing the scheme rewrites
    /// nothing, and a binary from before it still reads every `N.0` database.
    ///
    /// That is not tidiness. The scheme exists so that a revert to an older binary is survivable, and
    /// one whose own arrival bricked the binary it was replacing would have been self-defeating.
    pub const fn encode(self) -> i64 {
        if self.minor == 0 {
            self.major
        } else {
            self.major * COMPONENT_LIMIT + self.minor
        }
    }

    /// The version a stored `user_version` denotes.
    ///
    /// Total over the whole range, because the value on disk is not under our control. A bare `N` —
    /// every database written before this scheme, and every `N.0` written since — is `N.0`; anything
    /// larger is unpacked. `3000` therefore also reads as 3.0 even though [`encode`](Self::encode)
    /// never produces it.
    ///
    /// Deliberately not [`Version::new`]: that asserts, and a hand-edited `user_version` may hold
    /// anything at all. An out-of-range value reads as some version and is then handled by
    /// [`migrate`]'s ordinary comparisons rather than by a panic.
    pub const fn decode(raw: i64) -> Self {
        if raw < COMPONENT_LIMIT {
            Self { major: raw, minor: 0 }
        } else {
            Self { major: raw / COMPONENT_LIMIT, minor: raw % COMPONENT_LIMIT }
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Schema version this binary understands. Tracked in `PRAGMA user_version`.
pub const SCHEMA_VERSION: Version = Version::new(3, 0);

/// One forward migration and the version it produces.
struct Migration {
    version: Version,
    sql: &'static str,
}

/// The forward-only migration list, in ascending version order.
///
/// **What may be a minor bump.** Nothing here can enforce this — it is a discipline on what a minor
/// migration may contain, and [`migrate`]'s acceptance of a newer minor is only sound while it holds.
/// A minor bump may only:
///
/// - `CREATE TABLE` — a table an older binary neither reads nor writes;
/// - `CREATE INDEX`;
/// - `ALTER TABLE … ADD COLUMN` that is nullable or has a default, on a table an older binary writes.
///   That binary's `INSERT` does not name the column, so the column has to be satisfiable without it.
///   (On a STRICT table `ADD COLUMN` requires a declared type, and a `NOT NULL` addition requires a
///   non-null default — consistent with this rule.)
///
/// Everything else is a major bump: dropping or renaming a table or column, changing a column's type,
/// adding a constraint an older binary's writes could violate, adding `NOT NULL` without a default,
/// or changing the meaning of existing data.
///
/// The test is not "is it additive in SQL" but **"would the previous binary still behave correctly
/// against it"**. Migration 2.0 below is the illustration: dropping and recreating `measurement` is
/// exactly what an older binary cannot survive.
///
/// **The first three versions are grandfathered.** They shipped as the single numbers 1, 2 and 3 and
/// so become 1.0, 2.0 and 3.0. Under the rule above, 3.0 only added `api_key` and *would* have been
/// 2.1 — but it is already deployed, and renumbering a database in the field buys nothing. The scheme
/// applies from here on; this is not an inconsistency to go and fix.
const MIGRATIONS: &[Migration] = &[
    // → version 1.0: the original table, keyed by rowid.
    Migration {
        version: Version::new(1, 0),
        sql: r#"
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
    },
    // → version 2.0: content-addressed ids (SPEC §6.6). `id` becomes the hash of everything the
    // device sent, so `INSERT OR IGNORE` makes re-uploading a measurement a no-op.
    //
    // A major bump, and the canonical example of why the majors exist: it drops and recreates
    // `measurement`, so a binary expecting the version-1 table cannot read what this leaves behind.
    //
    // Existing rows are dropped rather than backfilled: version 1 was never deployed, and a
    // backfill would have to re-derive each id from stored JSON, which is exactly the kind of
    // second, subtly-different encoding path this design exists to avoid. If v1 data ever needs
    // preserving, re-ingest it rather than reconstructing ids here.
    //
    // Kept as a rowid table, NOT `WITHOUT ROWID`: measured over 20k realistic rows, WITHOUT ROWID
    // is *larger*, because secondary indexes must then carry the full 16-byte key as the row
    // locator instead of a compact rowid.
    Migration {
        version: Version::new(2, 0),
        sql: r#"
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
    },
    // → version 3.0: API keys (SPEC §13). Grandfathered — see the note on MIGRATIONS: this is purely
    // additive and would be 2.1 under the rule that now applies, but it shipped as 3.
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
    Migration {
        version: Version::new(3, 0),
        sql: r#"
    CREATE TABLE api_key (
      id          TEXT    PRIMARY KEY,
      secret_hash BLOB    NOT NULL,
      label       TEXT    NOT NULL,
      created_at  INTEGER NOT NULL
    ) STRICT;
    "#,
    },
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
/// Three outcomes, and which one applies turns on the *major* (SPEC §6.2):
///
/// - **A newer major is fatal**, as it always was: continuing would risk writing rows that the newer
///   schema cannot represent.
/// - **A newer minor is fine.** A minor bump only adds tables, indexes and defaulted columns (see
///   [`MIGRATIONS`]), so everything this binary knows about is still exactly where it expects. It runs,
///   ignoring what it has never heard of. This is the case the major/minor split exists for.
/// - Anything older is migrated forward.
pub fn migrate(conn: &Connection) -> Result<()> {
    let raw: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let current = Version::decode(raw);

    if current.major > SCHEMA_VERSION.major {
        bail!(
            "database schema major version {} is newer than this binary supports ({}); refusing to \
             downgrade",
            current.major,
            SCHEMA_VERSION.major
        );
    }
    // Same major and a higher minor — the major case above is what makes that the only way to get
    // here with `current` ahead of us.
    if current > SCHEMA_VERSION {
        tracing::warn!(
            database = %current,
            binary = %SCHEMA_VERSION,
            "database schema is a newer minor version than this binary knows; continuing, since a \
             minor version only adds tables, indexes and defaulted columns. This binary is older \
             than the one that last migrated this database"
        );
        return Ok(());
    }
    if current == SCHEMA_VERSION {
        // Nothing to do, and nothing written either: a 3.0 database keeps `user_version = 3`
        // literally, so it stays readable by a binary from before this scheme existed.
        return Ok(());
    }

    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<()> {
        // Relies on MIGRATIONS being sorted, which `migrations_are_sorted_and_end_at_the_declared_version`
        // pins. Filtering on the version rather than skipping by index also removes the old
        // `current as usize` cast, which silently tied a version number to an array position.
        for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
            tracing::info!(to_version = %migration.version, "applying migration");
            conn.execute_batch(migration.sql)
                .with_context(|| format!("applying migration to version {}", migration.version))?;
        }
        // pragma_update cannot be parameterised, and SCHEMA_VERSION is a compile-time constant.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION.encode())?;
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

    /// The raw `user_version`, not the decoded one: several assertions below are about the exact
    /// integer on disk, which is what an older binary reads.
    fn stored_version(conn: &Connection) -> i64 {
        conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap()
    }

    // ------------------------------------------------------------------------------- the encoding

    #[test]
    fn a_version_round_trips_through_its_stored_form() {
        for version in [
            Version::new(0, 0),
            Version::new(1, 0),
            Version::new(3, 0),
            Version::new(3, 1),
            Version::new(3, 999),
            Version::new(999, 0),
            Version::new(999, 999),
        ] {
            assert_eq!(Version::decode(version.encode()), version, "on {version}");
        }
    }

    /// The property every already-deployed database depends on, and the reason this scheme could be
    /// introduced without rewriting anything: a bare integer is that major at minor zero.
    #[test]
    fn a_bare_integer_is_that_major_at_minor_zero() {
        assert_eq!(Version::decode(3), Version::new(3, 0), "what is deployed today");
        assert_eq!(Version::decode(1), Version::new(1, 0));
        assert_eq!(Version::decode(0), Version::new(0, 0), "an untouched database");
    }

    /// A minor of zero is stored as the bare major, so a binary from before this scheme still reads
    /// every `N.0` database. Asserted on the integer, because that integer is the compatibility
    /// promise.
    #[test]
    fn a_zero_minor_is_stored_as_the_bare_major() {
        assert_eq!(Version::new(3, 0).encode(), 3);
        assert_eq!(Version::new(4, 0).encode(), 4);
        assert_eq!(SCHEMA_VERSION.encode(), 3, "the version in the field must not move");
    }

    /// `decode` has to be total: `user_version` can be hand-edited to anything. The packed form of a
    /// zero minor is never written, but reading it must still give the same version.
    #[test]
    fn the_packed_form_of_a_zero_minor_still_decodes() {
        assert_eq!(Version::decode(3000), Version::new(3, 0));
        assert_eq!(Version::decode(3001), Version::new(3, 1));
    }

    /// Numeric, not lexical. A string or float comparison would put 3.10 before 3.9.
    #[test]
    fn versions_order_by_major_then_minor() {
        assert!(Version::new(3, 0) < Version::new(3, 1));
        assert!(Version::new(3, 1) < Version::new(4, 0));
        assert!(Version::new(3, 999) < Version::new(4, 0));
        assert!(Version::new(3, 9) < Version::new(3, 10));
    }

    /// Catches both halves of the likeliest mistake: adding a migration without bumping
    /// `SCHEMA_VERSION`, and bumping it without adding one. The sort order is what `migrate`'s
    /// filter relies on to apply migrations in sequence.
    #[test]
    fn migrations_are_sorted_and_end_at_the_declared_version() {
        for pair in MIGRATIONS.windows(2) {
            assert!(
                pair[0].version < pair[1].version,
                "MIGRATIONS must ascend: {} is not before {}",
                pair[0].version,
                pair[1].version
            );
        }
        assert_eq!(
            MIGRATIONS.last().expect("at least one migration").version,
            SCHEMA_VERSION,
            "the last migration must produce exactly SCHEMA_VERSION"
        );
    }

    // ------------------------------------------------------------------------------- migrating

    /// A database that stopped at version 2 is what every already-deployed receiver has. The
    /// upgrade must add the key table without touching the measurements beside it.
    #[test]
    fn migrating_from_version_2_adds_keys_and_keeps_the_measurements() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.execute_batch(MIGRATIONS[1].sql).unwrap();
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
        assert_eq!(stored_version(&conn), SCHEMA_VERSION.encode());

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
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();

        migrate(&conn).unwrap();

        assert_eq!(stored_version(&conn), SCHEMA_VERSION.encode());
        assert!(has_table(&conn, "api_key"), "3.0 must have run too");

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

    /// A newer MAJOR is still fatal: it can have rewritten data this binary cannot read.
    #[test]
    fn refuses_a_database_from_a_newer_major_version() {
        let conn = Connection::open_in_memory().unwrap();
        let newer = Version::new(SCHEMA_VERSION.major + 1, 0);
        conn.pragma_update(None, "user_version", newer.encode()).unwrap();

        let err = migrate(&conn).unwrap_err().to_string();
        assert!(err.contains("newer than this binary"), "unexpected error: {err}");

        // A newer major with a minor on it is the same refusal — the minor is irrelevant once the
        // major is ahead.
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", Version::new(SCHEMA_VERSION.major + 1, 7).encode())
            .unwrap();
        assert!(migrate(&conn).is_err());
    }

    /// **The behaviour this whole scheme exists for.** A database migrated by a newer binary that only
    /// added tables is one this binary can still serve, so it must start rather than refuse — that is
    /// what makes reverting to the previously deployed generation survivable (SPEC §6.2).
    #[test]
    fn accepts_a_newer_minor_version_without_migrating_it() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        // Stand in for a future minor: the table a newer binary would have added, and its version.
        conn.execute_batch("CREATE TABLE from_the_future (x INTEGER) STRICT;").unwrap();
        let future = Version::new(SCHEMA_VERSION.major, SCHEMA_VERSION.minor + 1);
        conn.pragma_update(None, "user_version", future.encode()).unwrap();

        migrate(&conn).expect("a newer minor version must be accepted, not refused");

        assert_eq!(
            stored_version(&conn),
            future.encode(),
            "the version must be left alone — writing ours back would be a silent downgrade"
        );
        assert!(has_table(&conn, "from_the_future"), "and the newer binary's table must survive");
        // What this binary does know about is still there and still usable.
        assert!(has_table(&conn, "measurement"));
        assert!(has_table(&conn, "api_key"));
    }

    /// A database already at our exact version must not be written to at all. That is what keeps a
    /// deployed 3.0 database readable by a binary from before major.minor existed, and therefore what
    /// makes introducing the scheme a no-op on disk.
    #[test]
    fn a_current_database_is_not_rewritten() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.execute_batch(MIGRATIONS[1].sql).unwrap();
        conn.execute_batch(MIGRATIONS[2].sql).unwrap();
        // The legacy form, exactly as every deployed database has it.
        conn.pragma_update(None, "user_version", 3i64).unwrap();

        migrate(&conn).unwrap();

        assert_eq!(stored_version(&conn), 3, "a bare 3 must stay a bare 3");
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
