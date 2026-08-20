//! The `web_session` table (SPEC §14). All SQL for sessions lives here; the cookie's token format is
//! [`crate::auth`], which knows nothing about storage.

use anyhow::{Context, Result};
use blake3::Hash;
use rusqlite::{Connection, OptionalExtension, params};

use crate::auth::SECRET_BYTES;

/// A session as stored — everything except the secret half, which no row contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub id: String,
    pub username: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// What a session lookup needs in order to decide: the hash to compare against, who it belongs to, and
/// when it stops counting.
///
/// Returned together from one query rather than as three lookups, because deciding whether a request is
/// authenticated must not depend on reading the table more than once — between two reads the row could
/// be deleted by a logout and the answers would disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub secret_hash: Hash,
    pub username: String,
    pub expires_at: i64,
}

pub fn insert(
    conn: &Connection,
    id: &str,
    secret_hash: &Hash,
    username: &str,
    created_at: i64,
    expires_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO web_session (id, secret_hash, username, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, secret_hash.as_bytes().as_slice(), username, created_at, expires_at],
    )
    .with_context(|| format!("storing session {id}"))?;
    Ok(())
}

/// The record for one session id, or `None` when there is no such session.
///
/// By id rather than by scanning every row and comparing hashes, which is the point of the cookie
/// carrying a public half: a cookie naming a session nobody issued is refused after one index probe and
/// no hashing at all.
///
/// A row whose `secret_hash` is not 32 bytes reads as `None`, the same rule
/// [`crate::store::keys::secret_hash`] applies: an unusable hash can only have been written by
/// something other than [`insert`], and "no such session" is the only safe reading of it.
///
/// Does **not** check expiry. Whether a session has expired is a question about the current time, and
/// this module takes no clock — the caller passes one in to [`SessionRecord::is_live`], so the decision
/// stays testable against a fixed instant.
pub fn lookup(conn: &Connection, id: &str) -> Result<Option<SessionRecord>> {
    let row: Option<(Vec<u8>, String, i64)> = conn
        .query_row(
            "SELECT secret_hash, username, expires_at FROM web_session WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .with_context(|| format!("looking up session {id}"))?;

    Ok(row.and_then(|(hash, username, expires_at)| {
        let secret_hash = <[u8; SECRET_BYTES]>::try_from(hash.as_slice()).ok()?;
        Some(SessionRecord { secret_hash: Hash::from(secret_hash), username, expires_at })
    }))
}

impl SessionRecord {
    /// Whether this session is still valid at `now` (nanoseconds since the Unix epoch).
    ///
    /// Expiry is absolute, not sliding: `expires_at` is fixed when the session is created and never
    /// moves. A sliding window would mean writing to the database on every page load to record activity
    /// nothing else reads — and it would make the read path a writer, which for a receiver whose single
    /// storage writer is the thing holding measurement throughput up is a poor trade for a
    /// one-operator UI.
    pub fn is_live(&self, now: i64) -> bool {
        now < self.expires_at
    }
}

/// Deletes one session, returning whether it existed. This is what logging out does.
///
/// Deleting rather than marking revoked, exactly as revoking an API key is deleting its row: a
/// `revoked_at` column nothing reads would be a thing to explain later, and the journal already carries
/// whatever audit trail a logout deserves.
pub fn delete(conn: &Connection, id: &str) -> Result<bool> {
    let removed = conn
        .execute("DELETE FROM web_session WHERE id = ?1", [id])
        .with_context(|| format!("deleting session {id}"))?;
    Ok(removed > 0)
}

/// Deletes every session that expired at or before `now`, returning how many went.
///
/// Called opportunistically at login rather than from a timer: logins are the only moment sessions are
/// created, so it is the only moment the table can grow, and a background timer for a table that gains
/// one row per login would be machinery in exchange for nothing. An expired row left lying around is
/// inert anyway — [`SessionRecord::is_live`] is what decides, not the row's presence.
pub fn delete_expired(conn: &Connection, now: i64) -> Result<usize> {
    conn.execute("DELETE FROM web_session WHERE expires_at <= ?1", [now])
        .context("deleting expired sessions")
}

/// Every session, newest first. Carries no hashes.
pub fn list(conn: &Connection) -> Result<Vec<StoredSession>> {
    let mut statement = conn
        .prepare(
            "SELECT id, username, created_at, expires_at FROM web_session \
             ORDER BY created_at DESC, id",
        )
        .context("preparing the session listing")?;

    let sessions = statement
        .query_map([], |row| {
            Ok(StoredSession {
                id: row.get(0)?,
                username: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })
        .context("listing sessions")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the session listing")?;

    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{SessionToken, TOKEN_BYTES};

    /// The users these sessions belong to have to exist: since 4.0 `web_session.username` is a foreign
    /// key into `web_user`, so a session for nobody is refused rather than stored. That is the point of
    /// the constraint, and it means a fixture cannot conjure a session out of nothing any more.
    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        for username in ["sashee", "irrelevant"] {
            crate::store::users::insert(&conn, username, &crate::auth::hash_password("pw"), 1)
                .expect("seeding the owner of the test sessions");
        }
        conn
    }

    /// The constraint itself: a session can only exist for a user that does. Before 4.0 nothing stopped
    /// this, and an orphan session stayed valid until it expired.
    #[test]
    fn a_session_cannot_be_created_for_a_user_who_does_not_exist() {
        let conn = db();
        let session = token(9);
        // `{:#}` rather than `to_string()`: the store wraps errors in context, so the constraint that
        // actually fired is in the source chain, not the outermost message.
        let err = format!(
            "{:#}",
            insert(&conn, session.id(), &session.secret_hash(), "ghost", 10, 100).unwrap_err()
        );
        assert!(err.to_lowercase().contains("foreign key"), "unexpected error: {err}");
    }

    fn token(first: u8) -> SessionToken {
        let mut bytes = [7u8; TOKEN_BYTES];
        bytes[0] = first;
        SessionToken::from_random(&bytes)
    }

    #[test]
    fn a_stored_session_is_found_by_its_id() {
        let conn = db();
        let session = token(1);
        insert(&conn, session.id(), &session.secret_hash(), "sashee", 10, 100).unwrap();

        let found = lookup(&conn, session.id()).unwrap().expect("the session must be found");
        assert_eq!(found.secret_hash, session.secret_hash());
        assert_eq!(found.username, "sashee");
        assert_eq!(found.expires_at, 100);
    }

    #[test]
    fn an_unissued_id_is_none_rather_than_an_error() {
        assert_eq!(lookup(&db(), "0000000000000000").unwrap(), None);
    }

    /// The secret is not in the table in any form.
    #[test]
    fn no_column_holds_the_secret() {
        let conn = db();
        let session = token(2);
        let cookie = session.to_secret_string();
        insert(&conn, session.id(), &session.secret_hash(), "sashee", 1, 100).unwrap();

        let secret = cookie.split_once('.').unwrap().1;
        let dumped: String = conn
            .query_row("SELECT quote(id) || quote(secret_hash) FROM web_session", [], |r| r.get(0))
            .unwrap();
        assert!(!dumped.contains(secret), "the secret reached the database: {dumped}");
    }

    /// Expiry is a comparison against a clock the caller supplies, so the boundary is testable exactly.
    #[test]
    fn a_session_is_live_strictly_before_its_expiry() {
        let record = SessionRecord {
            secret_hash: crate::auth::hash_password("irrelevant"),
            username: "sashee".into(),
            expires_at: 100,
        };
        assert!(record.is_live(99));
        assert!(!record.is_live(100), "expiry is exclusive");
        assert!(!record.is_live(101));
    }

    #[test]
    fn deleting_a_session_is_what_logging_out_does() {
        let conn = db();
        let session = token(3);
        insert(&conn, session.id(), &session.secret_hash(), "sashee", 1, 100).unwrap();

        assert!(delete(&conn, session.id()).unwrap());
        assert_eq!(lookup(&conn, session.id()).unwrap(), None);
        assert!(!delete(&conn, session.id()).unwrap(), "deleting twice is false, not an error");
    }

    #[test]
    fn expired_sessions_are_swept_and_live_ones_are_not() {
        let conn = db();
        let (old, live) = (token(4), token(5));
        insert(&conn, old.id(), &old.secret_hash(), "sashee", 1, 50).unwrap();
        insert(&conn, live.id(), &live.secret_hash(), "sashee", 1, 500).unwrap();

        assert_eq!(delete_expired(&conn, 100).unwrap(), 1);
        assert_eq!(lookup(&conn, old.id()).unwrap(), None);
        assert!(lookup(&conn, live.id()).unwrap().is_some());
    }

    /// The sweep is inclusive at the boundary, matching `is_live`'s exclusive one: a session that is no
    /// longer live is one the sweep is entitled to remove.
    #[test]
    fn the_sweep_removes_a_session_expiring_exactly_now() {
        let conn = db();
        let session = token(6);
        insert(&conn, session.id(), &session.secret_hash(), "sashee", 1, 100).unwrap();

        assert_eq!(delete_expired(&conn, 100).unwrap(), 1);
    }

    #[test]
    fn sessions_list_newest_first() {
        let conn = db();
        let (old, new) = (token(7), token(8));
        insert(&conn, old.id(), &old.secret_hash(), "sashee", 1_000, 9_000).unwrap();
        insert(&conn, new.id(), &new.secret_hash(), "sashee", 2_000, 9_000).unwrap();

        let listed = list(&conn).unwrap();
        assert_eq!(
            listed,
            vec![
                StoredSession {
                    id: new.id().to_owned(),
                    username: "sashee".into(),
                    created_at: 2_000,
                    expires_at: 9_000,
                },
                StoredSession {
                    id: old.id().to_owned(),
                    username: "sashee".into(),
                    created_at: 1_000,
                    expires_at: 9_000,
                },
            ]
        );
    }

    #[test]
    fn an_empty_table_lists_as_nothing() {
        assert!(list(&db()).unwrap().is_empty());
    }

    /// A `secret_hash` of the wrong width can only come from something other than `insert`. It must read
    /// as "no such session" rather than panicking or matching anything.
    #[test]
    fn a_hash_of_the_wrong_length_is_not_a_usable_session() {
        let conn = db();
        conn.execute(
            "INSERT INTO web_session (id, secret_hash, username, created_at, expires_at) \
             VALUES ('0000000000000001', x'00', 'sashee', 1, 100)",
            [],
        )
        .unwrap();

        assert_eq!(lookup(&conn, "0000000000000001").unwrap(), None);
    }
}
