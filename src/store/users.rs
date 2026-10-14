//! The `web_user` table (SPEC §14). All SQL for web users lives here.
//!
//! A user is a name and nothing to sign in with: how they sign in is their passkeys (`store::passkeys`) and,
//! for a few minutes at a time, a sign-in token (`store::login_tokens`).

use anyhow::{Context, Result};
use rusqlite::Connection;

/// A user as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUser {
    pub username: String,
    pub created_at: i64,
}

pub fn insert(conn: &Connection, username: &str, created_at: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO web_user (username, created_at) VALUES (?1, ?2)",
        rusqlite::params![username, created_at],
    )
    .with_context(|| format!("storing web user {username:?}"))?;
    Ok(())
}

/// How many users exist.
///
/// For the users page, which refuses to delete the last one.
pub fn count(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT count(*) FROM web_user", [], |row| row.get(0))
        .context("counting web users")
}

/// Every user, oldest first.
///
/// Oldest first rather than newest: with one operator the order is cosmetic, and creation order reads
/// more naturally than its reverse on a page that is normally one row long.
pub fn list(conn: &Connection) -> Result<Vec<StoredUser>> {
    let mut statement = conn
        .prepare("SELECT username, created_at FROM web_user ORDER BY created_at, username")
        .context("preparing the web user listing")?;

    let users = statement
        .query_map([], |row| {
            Ok(StoredUser { username: row.get(0)?, created_at: row.get(1)? })
        })
        .context("listing web users")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the web user listing")?;

    Ok(users)
}

/// Deletes a user **and every session they hold**, returning whether the user existed.
///
/// The session sweep is done here rather than left to a foreign key because this schema sets no
/// `foreign_keys` pragma (see [`crate::store::schema`]), so `ON DELETE CASCADE` would be parsed and
/// never enforced. Without it, deleting a user would leave live sessions that still authenticate
/// against a username that no longer exists — the session guard looks a session up by id, and nothing
/// downstream re-checks that its user is still there.
///
/// One transaction, so a failure between the two statements cannot leave the sessions orphaned.
pub fn delete(conn: &Connection, username: &str) -> Result<bool> {
    let tx = conn.unchecked_transaction().context("beginning the user deletion")?;
    tx.execute("DELETE FROM web_session WHERE username = ?1", [username])
        .with_context(|| format!("deleting sessions for web user {username:?}"))?;
    let removed = tx
        .execute("DELETE FROM web_user WHERE username = ?1", [username])
        .with_context(|| format!("deleting web user {username:?}"))?;
    tx.commit().context("committing the user deletion")?;
    Ok(removed > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        conn
    }

    #[test]
    fn a_stored_user_is_listed() {
        let conn = db();
        insert(&conn, "sashee", 1_000).unwrap();
        assert_eq!(list(&conn).unwrap(), vec![StoredUser { username: "sashee".into(), created_at: 1_000 }]);
    }

    #[test]
    fn the_same_username_cannot_be_stored_twice() {
        let conn = db();
        insert(&conn, "sashee", 1).unwrap();
        assert!(insert(&conn, "sashee", 2).is_err(), "the primary key must refuse a duplicate username");
    }

    /// Usernames are compared as stored, so two spellings are two users. SQLite's default `BINARY` collation
    /// is what gives this; asserted because a later `COLLATE NOCASE` would silently merge them.
    #[test]
    fn usernames_are_case_sensitive() {
        let conn = db();
        insert(&conn, "sashee", 1).unwrap();
        insert(&conn, "Sashee", 2).expect("a different username");
        assert_eq!(count(&conn).unwrap(), 2);
    }

    #[test]
    fn users_list_oldest_first() {
        let conn = db();
        insert(&conn, "second", 2_000).unwrap();
        insert(&conn, "first", 1_000).unwrap();

        assert_eq!(
            list(&conn).unwrap(),
            vec![
                StoredUser { username: "first".into(), created_at: 1_000 },
                StoredUser { username: "second".into(), created_at: 2_000 },
            ]
        );
    }

    #[test]
    fn an_empty_table_lists_as_nothing() {
        assert!(list(&db()).unwrap().is_empty());
        assert_eq!(count(&db()).unwrap(), 0);
    }

    /// Deleting a user must take their sessions with them, or a live cookie keeps working against a
    /// username that no longer exists.
    #[test]
    fn deleting_a_user_deletes_their_sessions() {
        let conn = db();
        insert(&conn, "sashee", 1).unwrap();
        insert(&conn, "other", 1).unwrap();
        crate::store::sessions::insert(&conn, "aa", &blake3::hash(b"s1"), "sashee", 1, 100).unwrap();
        crate::store::sessions::insert(&conn, "bb", &blake3::hash(b"s2"), "other", 1, 100).unwrap();

        assert!(delete(&conn, "sashee").unwrap());

        assert_eq!(count(&conn).unwrap(), 1);
        assert!(
            crate::store::sessions::lookup(&conn, "aa").unwrap().is_none(),
            "the deleted user's session must be gone"
        );
        assert!(
            crate::store::sessions::lookup(&conn, "bb").unwrap().is_some(),
            "and nobody else's may be touched"
        );
    }

    #[test]
    fn deleting_a_user_who_does_not_exist_is_false_rather_than_an_error() {
        assert!(!delete(&db(), "nobody").unwrap());
    }
}
