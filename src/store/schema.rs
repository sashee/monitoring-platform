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
pub const SCHEMA_VERSION: Version = Version::new(4, 0);

/// A compile-time guard, not a test, because it is an invariant about a constant and a build is the right
/// place to lose an argument with one.
///
/// **Bumping the major is what breaks a reverted deployment**, reintroducing the permanent-startup-failure
/// class the major/minor split was introduced to remove. So it needs a deliberate plan and not merely an
/// edit: get the new major deployed through the pipeline before anything writes a database at it. Changing
/// this line is that decision, and this assertion is what makes it a visible one.
///
/// **It has been changed once, from 3 to 4**, and the plan it required is worth recording because the next
/// major will need the same one:
///
/// 1. 3.2 added `series` and dual-wrote it, so nothing read it yet.
/// 2. 3.3 moved every *read* onto the join, leaving `measurement.type` and `measurement.attributes` written
///    but unread. Both minors, so both were revertible and both were exercised on the deployed host.
/// 3. 3.3 was merged and delivered **through the pipeline**, which is what made every binary in
///    circulation one that writes a `series_id`. Only then could 4.0 assume a fully-assigned table and
///    drop the backfill machinery entirely rather than carrying a fill it could not express in SQL.
///
/// The ordering was the whole point: it left 4.0 as a table rebuild with no read-path changes, which is the
/// only shape worth having in a migration that cannot be rehearsed on the host or reverted once applied.
const _: () = assert!(
    SCHEMA_VERSION.major == 4 && SCHEMA_VERSION.minor == 0,
    "a major bump strands every receiver still running the previous one; see SPEC.md §6.2"
);

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
    // → version 3.1: the web interface's users and sessions (SPEC §14).
    //
    // **A minor bump, and it has to stay one.** Two new tables and one new index, and nothing touched
    // that a 3.0 binary reads or writes — so a receiver reverted to 3.0 starts against this database,
    // ignores both tables, and serves measurements exactly as before. That is the property the
    // major/minor split was introduced for, and this is its first use; adding a column to
    // `measurement` here instead would have made it a 4.0 and reintroduced the outage.
    //
    // `web_` prefixed rather than `user`/`session`, because §6.5 keeps a Postgres migration open and
    // `user` is reserved there. Prefixing both keeps them named as a pair.
    //
    // `web_user` holds no email, no roles and no display name: there is one operator, and a column
    // nothing reads is a thing to explain later rather than a feature (the same argument as
    // `api_key`'s absent `revoked_at`). `password_hash` is 32 bytes of domain-separated blake3 — see
    // crate::auth for why a fast hash is the right choice for a high-entropy secret.
    //
    // `web_session` mirrors `api_key` deliberately: `id` is the public half of the token verbatim, so
    // an unissued id costs one index probe and no hashing, and `secret_hash` is the only record of
    // the secret half. A stolen database therefore yields nothing that can log in.
    //
    // No `last_seen_at`. Touching it would make every page load a write, for information nothing
    // acts on; `expires_at` is absolute, so the read path never writes at all.
    //
    // No `revoked_at` either: logging out deletes the row, exactly as revoking a key does.
    //
    // No foreign key from `web_session.username` to `web_user.username` — this schema sets no
    // `foreign_keys` pragma (see `apply_pragmas`), so the constraint would be declared and not
    // enforced, which is worse than not declaring it. Deleting a user deletes their sessions in
    // `store::users::delete` instead, and says so.
    //
    // The index is on `expires_at` alone: the only query that scans rather than probing by id is the
    // opportunistic sweep of expired sessions.
    Migration {
        version: Version::new(3, 1),
        sql: r#"
    CREATE TABLE web_user (
      username      TEXT    PRIMARY KEY,
      password_hash BLOB    NOT NULL,
      created_at    INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE web_session (
      id          TEXT    PRIMARY KEY,
      secret_hash BLOB    NOT NULL,
      username    TEXT    NOT NULL,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL
    ) STRICT;

    CREATE INDEX web_session_expires_at_idx ON web_session (expires_at);
    "#,
    },
    // → version 3.2: the series dimension table (SPEC §6.7), phase one of two.
    //
    // `measurement` carries `type` and `attributes` on every row, and those two columns identify the
    // time series rather than describing what was measured. On the deployed database that is 1,458
    // distinct pairs written out across 117,952 rows — 81× replication, and 50% of the file.
    //
    // **A minor bump, and every line here is chosen to keep it one.** `series` is a new table, which a
    // 3.1 binary neither reads nor writes. `series_id` is a *nullable* added column, because a 3.1
    // binary's INSERT does not name it and so the column has to be satisfiable without it — declaring
    // it NOT NULL is the single edit that would turn this into a 4.0 and strand every receiver the
    // nightly auto-upgrade reverts.
    //
    // Phase two (4.0) makes `series_id` NOT NULL and drops `type` and `attributes`, which is what
    // actually reclaims the space. It cannot happen here: dropping a column a running 3.1 binary
    // selects is precisely the case the majors exist for.
    //
    // The partial index **is the backfill work queue** — see `store::series`. It costs O(unfilled)
    // rather than O(table), collapses to nothing once the fill completes, and a row written by a
    // reverted 3.1 binary enters it automatically, which is what makes the fill self-healing rather
    // than a one-shot with a hole in it. Deliberately temporary: 4.0 drops it.
    //
    // `series_type_attributes_idx` was added for the backfill's set-wise `UPDATE`, correlated on
    // `(type, attributes)`. **That is no longer why it exists, and it must not be dropped**: since 3.3
    // the read path's type filter is `series.type`, and the query plan uses this index to drive the
    // whole join from the 1,629-row `series` table — `SEARCH sr USING INDEX series_type_attributes_idx
    // (type=?)`. Removing it as dead weight would turn every type-filtered query into a scan. 4.0
    // deliberately keeps it while dropping the two indexes that really did become dead.
    //
    // No index on `measurement (series_id, …)`. Nothing reads `series` in phase one, and an index over
    // 118k rows costs space and write throughput now for a query that does not exist yet. Additive, so
    // it stays available as a later minor.
    //
    // The `added_*` columns are bookkeeping over the **insert stream**: monotonic, never revised
    // downward, and deliberately not a description of what the table currently holds. Once expiration
    // exists and rows are deleted, `count(*)` and `min(event_time)` over `measurement` stop answering
    // "what did this series ever carry" — and only these columns still know. That is the whole reason
    // for the prefix: a column called `num_measurements` or `min_event_time` would quietly become a
    // lie, and a stale timestamp reads as data in a way a stale count does not. They are NOT part of
    // `series_id`; the key is type + attributes alone.
    Migration {
        version: Version::new(3, 2),
        sql: r#"
    CREATE TABLE series (
      id                       BLOB    PRIMARY KEY,
      type                     TEXT    NOT NULL,
      attributes               TEXT    NOT NULL,
      added_measurements       INTEGER NOT NULL,
      added_event_time_min     INTEGER NOT NULL,
      added_event_time_max     INTEGER NOT NULL,
      added_processed_time_min INTEGER NOT NULL,
      added_processed_time_max INTEGER NOT NULL
    ) STRICT;

    ALTER TABLE measurement ADD COLUMN series_id BLOB;

    CREATE INDEX measurement_backfill_idx ON measurement (id) WHERE series_id IS NULL;
    CREATE INDEX series_type_attributes_idx ON series (type, attributes);
    "#,
    },
    // → version 3.3: the index the *read* path needs now that it joins `series` (SPEC §6.7, §7.1).
    //
    // 3.2 wrote `series` and read nothing from it. This is the other half: every read of a
    // measurement's `type` or `attributes` now comes from the join, which is what lets 4.0 be nothing
    // but `DROP COLUMN` — no read-path rewrite in the one migration that cannot be rehearsed on the
    // deployed host, because it has to arrive through the pipeline and cannot be reverted.
    //
    // Why a separate minor rather than an edit to 3.2: 3.2 is already applied on the deployed database
    // (`user_version = 3002`), so editing its SQL would silently skip this index there. That is the
    // migration list working as designed, not an inconvenience.
    //
    // The index replaces what `measurement_type_event_time_idx` used to do. That one leads with `type`,
    // which the read path no longer filters on — the predicate is `series.type` now — so a type filter
    // would otherwise have no index to stand on. `measurement_type_event_time_idx` is deliberately
    // *kept*: a 3.2 binary the nightly reverts to still filters on `measurement.type` and would be slow
    // without it. 4.0 drops both it and the column it covers, in that order, since SQLite refuses to
    // drop an indexed column.
    Migration {
        version: Version::new(3, 3),
        sql: r#"
    CREATE INDEX measurement_series_event_time_idx
      ON measurement (series_id, event_time DESC, id DESC);
    "#,
    },
    // → version 4.0: `measurement` loses `type` and `attributes` (SPEC §6.7). The payoff for 3.2 and 3.3.
    //
    // **A major bump, and the second one in this project's life.** Everything that made it safe happened
    // earlier: 3.2 wrote `series`, 3.3 moved every read onto the join, and 3.3 reached the host through
    // the pipeline — so by the time this runs, no binary in circulation writes an unassigned measurement
    // and the table is fully assigned. See the compile-time guard above for why that ordering was
    // required rather than merely tidy.
    //
    // **A rebuild, not `DROP COLUMN`, for three reasons.** SQLite cannot `ALTER TABLE … ADD NOT NULL`; it
    // cannot add a foreign key to an existing table at all; and `DROP COLUMN` rewrites every row without
    // producing a compact table. A rebuild gets all three in the one pass the data has to make anyway,
    // and migration 2.0 is the precedent.
    //
    // **`NOT NULL` is the precondition check.** A database that never passed through 3.3 has unassigned
    // rows, and this `INSERT … SELECT` fails on them — rolling the whole migration back, leaving
    // `user_version` at 3.3 and the previous generation bootable. Nothing here could fill them anyway:
    // minting a series row needs blake3, and SQL cannot hash. So "upgrade through 3.3" is a real
    // constraint on any restored backup, enforced rather than documented.
    //
    // **The foreign key is what makes the read path's inner join total.** `NOT NULL` forbids a NULL
    // `series_id`; only this forbids a *dangling* one, which a write-path bug could otherwise produce and
    // which would make those measurements silently invisible. `DEFERRABLE INITIALLY DEFERRED` is
    // load-bearing: `store::write::insert_batch` inserts each measurement *before* upserting its series
    // row, because `added_measurements` may only count rows the `INSERT OR IGNORE` actually stored.
    // Reversing that order to satisfy an immediate constraint would let a retried batch inflate the count.
    // Deferred checks at `COMMIT`, so the order stays free and the guarantee is the same. It also makes
    // this migration self-verifying: all 120k rows are checked against `series` before it commits.
    //
    // `ON DELETE RESTRICT` by omission, which is wanted: a series with measurements cannot be deleted.
    // That becomes load-bearing when retention arrives.
    //
    // `web_session.username` gains its own key, immediate rather than deferred — a session is only ever
    // created for a user that was just authenticated. Orphans are filtered rather than allowed to fail the
    // migration: a session whose user no longer exists is a credential that should already be invalid, so
    // dropping it is the same repair `store::users::delete` performs by hand.
    //
    // `measurement_type_event_time_idx` and `measurement_backfill_idx` die with the old table and are not
    // recreated. `series_type_attributes_idx` is left alone — the read path's type filter uses it.
    //
    // No `VACUUM`: it cannot run inside a transaction. The ~62 MB of duplicated text is freed *within* the
    // file and reused by later rows; returning it to the filesystem is a one-off manual step.
    Migration {
        version: Version::new(4, 0),
        sql: r#"
    CREATE TABLE measurement_new (
      id             BLOB    PRIMARY KEY,
      event_time     INTEGER NOT NULL,
      processed_time INTEGER NOT NULL,
      body           TEXT,
      series_id      BLOB    NOT NULL REFERENCES series(id) DEFERRABLE INITIALLY DEFERRED
    ) STRICT;

    INSERT INTO measurement_new (id, event_time, processed_time, body, series_id)
      SELECT id, event_time, processed_time, body, series_id FROM measurement;

    DROP TABLE measurement;
    ALTER TABLE measurement_new RENAME TO measurement;

    CREATE INDEX measurement_event_time_idx        ON measurement (event_time DESC, id DESC);
    CREATE INDEX measurement_series_event_time_idx ON measurement (series_id, event_time DESC, id DESC);

    CREATE TABLE web_session_new (
      id          TEXT    PRIMARY KEY,
      secret_hash BLOB    NOT NULL,
      username    TEXT    NOT NULL REFERENCES web_user(username) ON DELETE CASCADE,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL
    ) STRICT;

    INSERT INTO web_session_new (id, secret_hash, username, created_at, expires_at)
      SELECT id, secret_hash, username, created_at, expires_at FROM web_session
      WHERE username IN (SELECT username FROM web_user);

    DROP TABLE web_session;
    ALTER TABLE web_session_new RENAME TO web_session;

    CREATE INDEX web_session_expires_at_idx ON web_session (expires_at);
    "#,
    },
];

/// Enables foreign keys, which this schema did **not** do before 4.0.
///
/// The earlier reasoning was that no genuine referential relationship existed — `api_key` does not own the
/// measurements ingested with it — so declaring one would imply a constraint that was not real, and a
/// pragma left off means SQLite parses a constraint and never enforces it. That reasoning expired when
/// `measurement.series_id` arrived: it is a real reference, and since 3.3 the read path's inner join
/// *depends* on it resolving, so a dangling value makes measurements silently invisible.
///
/// **The pragma is per-connection and not stored in the file**, which is the hazard the old comment
/// feared and it does not go away — a write path that forgets it is silently unenforced. So it lives here,
/// [`open_write_existing`] calls the same thing, and `tests` asserts a dangling insert is refused on each.
/// [`open_read`] deliberately does not: a read-only connection cannot violate a constraint.
fn apply_foreign_keys(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // Asserted rather than assumed: `PRAGMA foreign_keys` is a silent no-op inside a transaction, so a
    // caller that had one open would otherwise get an unenforced connection and no indication of it.
    let on: i64 = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
    if on != 1 {
        bail!("could not enable foreign keys (is a transaction open on this connection?)");
    }
    Ok(())
}

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
    apply_foreign_keys(conn)?;
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

/// Opens a short-lived read-write connection to an **already-migrated** database.
///
/// For the handful of writes that do not go through the storage writer: creating a session at login,
/// deleting one at logout (SPEC §14). Those are single statements on their own tables, not measurement
/// batches, so routing them through the writer's channel would mean teaching it a second kind of work
/// for no gain.
///
/// A second writer against a live receiver is already established as safe — `create-api-key` does
/// exactly this against a running server (see `main.rs`): WAL admits one, and `busy_timeout` covers the
/// overlap.
///
/// **Deliberately does not migrate**, which is the whole reason this exists rather than reusing
/// [`open_write`]. A login is not a plausible moment to discover the schema needs upgrading, and on a
/// receiver whose database is a newer minor than the binary (§6.2) re-running [`migrate`] per request
/// would re-log its warning on every page load.
pub fn open_write_existing(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening database {} for writing", path.display()))?;
    // No journal_mode: WAL is a property of the file and was set when it was created. busy_timeout and
    // foreign_keys are per-connection, and the latter is why this cannot simply skip pragmas: this
    // connection writes `web_session`, whose key to `web_user` would otherwise be parsed and ignored.
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    apply_foreign_keys(&conn)?;
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
    // Enforcement is per-connection, so a declared foreign key is only real on a connection that asked
    // for it — and the connection that just built or upgraded the schema is precisely the one that must.
    // Doing it here rather than only in [`apply_pragmas`] means every path that reaches a current schema
    // has the constraints live, including callers that open a connection directly. Must precede the
    // `BEGIN` below: the pragma is a silent no-op inside a transaction.
    apply_foreign_keys(conn)?;

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
        // A failing COMMIT has to roll back explicitly. Since 4.0 the schema has a *deferred* foreign
        // key, and a deferred violation is reported by `COMMIT` itself — at which point SQLite leaves the
        // transaction open rather than unwinding it. Returning here without the rollback would leave the
        // connection inside a live transaction holding the write lock.
        Ok(()) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(anyhow::Error::from(e).context("committing the migration"))
            }
        },
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
        // 3 is what was deployed before major.minor existed, and what a 3.0 database still holds.
        assert_eq!(Version::new(3, 0).encode(), 3);
        assert_eq!(Version::new(4, 0).encode(), 4);
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

    /// **A database with measurements cannot skip 3.3, and this is what that looks like.**
    ///
    /// 3.2 adds `series_id` as all-NULL; 4.0 requires it `NOT NULL`. Nothing in 4.0 can fill the gap —
    /// minting a series row needs blake3 and SQL cannot hash — so the migration refuses, rolls back
    /// whole, and leaves the database exactly as it was. That is a real constraint on restoring an old
    /// backup, enforced rather than merely documented: the upgrade path runs a 3.3 binary first, which
    /// assigns every row, and only then a 4.0 one.
    #[test]
    fn a_pre_3_2_database_with_rows_refuses_to_reach_4_0() {
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

        let err = format!("{:#}", migrate(&conn).unwrap_err());
        assert!(err.contains("NOT NULL"), "the refusal must name the constraint: {err}");

        // Rolled back whole: the version is untouched, so the previous generation still runs against it.
        assert_eq!(stored_version(&conn), 2, "a partial migration would be unrecoverable");
        let rows: i64 =
            conn.query_row("SELECT count(*) FROM measurement", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 1, "and the measurement is still there");
    }

    /// The same database *without* rows migrates all the way, which is what a fresh deployment does.
    #[test]
    fn a_pre_3_2_database_with_no_rows_migrates_all_the_way() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0].sql).unwrap();
        conn.execute_batch(MIGRATIONS[1].sql).unwrap();
        conn.pragma_update(None, "user_version", 2i64).unwrap();

        migrate(&conn).unwrap();

        assert_eq!(stored_version(&conn), SCHEMA_VERSION.encode());
        assert!(has_table(&conn, "series"));
        assert!(has_table(&conn, "api_key"));
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

    /// A database already at our exact version must not be written to at all.
    #[test]
    fn a_current_database_is_not_rewritten() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let after_first = stored_version(&conn);

        migrate(&conn).unwrap();

        assert_eq!(stored_version(&conn), after_first);
        assert_eq!(after_first, SCHEMA_VERSION.encode());
    }

    /// A 3.0 database's *other* tables survive the whole way to 4.0. Measurements are covered by
    /// `a_pre_3_2_database_with_rows_refuses_to_reach_4_0`; what matters here is that everything beside
    /// them is carried through untouched, including across 4.0's two table rebuilds.
    #[test]
    fn migrating_from_version_3_0_keeps_the_tables_beside_the_measurements() {
        let conn = Connection::open_in_memory().unwrap();
        for migration in MIGRATIONS.iter().filter(|m| m.version <= Version::new(3, 0)) {
            conn.execute_batch(migration.sql).unwrap();
        }
        // The legacy form, exactly as every deployed database had it.
        conn.pragma_update(None, "user_version", 3i64).unwrap();
        conn.execute(
            "INSERT INTO api_key (id, secret_hash, label, created_at) \
             VALUES ('0000000000000001', x'00', 'pi-7', 1)",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();

        assert!(has_table(&conn, "web_user"));
        assert!(has_table(&conn, "web_session"));
        assert!(has_table(&conn, "series"));
        assert_eq!(stored_version(&conn), SCHEMA_VERSION.encode());
        let keys: i64 = conn.query_row("SELECT count(*) FROM api_key", [], |r| r.get(0)).unwrap();
        assert_eq!(keys, 1, "an issued key must survive the upgrade");
    }

    /// **4.0 is where an older binary's writes stop working, and that is the definition of a major.**
    ///
    /// The inverse of the test this replaces. Through 3.3 the property asserted was that the verbatim
    /// pre-3.2 `INSERT` still succeeded — which is what made every one of those bumps a minor, and what
    /// kept the nightly auto-upgrade's revert survivable. 4.0 deliberately ends it: `type` and
    /// `attributes` are gone, so that `INSERT` names columns that do not exist. Asserting the refusal
    /// keeps the boundary explicit rather than implied by a deleted test.
    #[test]
    fn an_older_binarys_writes_are_refused_by_the_4_0_schema() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let err = conn
            .execute(
                "INSERT OR IGNORE INTO measurement \
                 (id, event_time, processed_time, type, body, attributes) \
                 VALUES (x'0102030405060708090a0b0c0d0e0f10', 1, 2, 'cpu', '{}', '{}')",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no column named type") || err.contains("has no column named"),
            "a pre-4.0 insert must be refused for naming dropped columns; got: {err}"
        );

        // The tables 4.0 did not touch still take the same writes they always did.
        conn.execute(
            "INSERT INTO api_key (id, secret_hash, label, created_at) \
             VALUES ('0000000000000001', x'00', 'pi-7', 1)",
            [],
        )
        .expect("api_key is unchanged");
        conn.execute(
            "INSERT INTO web_user (username, password_hash, created_at) VALUES ('op', x'00', 1)",
            [],
        )
        .expect("web_user is unchanged");
    }

    /// STRICT is what makes the column types enforced rather than advisory. Survives the 4.0 rebuild,
    /// which is worth checking: a rebuilt table that forgot `STRICT` would silently start accepting
    /// anything.
    #[test]
    fn schema_is_strict() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let err = conn
            .execute(
                "INSERT INTO measurement (id, event_time, processed_time, body, series_id) \
                 VALUES (x'00', 'not-a-number', 1, '{}', x'00')",
                [],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot store TEXT value in INTEGER column"),
            "STRICT should have refused the insert; got: {err}"
        );
    }
}
