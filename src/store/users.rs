//! The `web_user` table (SPEC §14). All SQL for web users lives here; how a password is hashed is
//! [`crate::auth`], which knows nothing about storage.

use anyhow::{Context, Result};
use blake3::Hash;
use rusqlite::{Connection, OptionalExtension, params};

use crate::auth::SECRET_BYTES;

/// A user as stored — that is, everything about them *except* the password, which no query can return
/// because no row contains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUser {
    pub username: String,
    pub created_at: i64,
}

pub fn insert(
    conn: &Connection,
    username: &str,
    password_hash: &Hash,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO web_user (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        params![username, password_hash.as_bytes().as_slice(), created_at],
    )
    .with_context(|| format!("storing web user {username:?}"))?;
    Ok(())
}

/// The stored hash for one username, or `None` when there is no such user.
///
/// A row whose `password_hash` is not 32 bytes reads as `None`. It cannot be produced by [`insert`], so
/// it means the column was written by something else — and treating an unusable hash as "no such user"
/// is the only safe reading. Exactly the rule [`crate::store::keys::secret_hash`] applies, and for the
/// same reason.
pub fn password_hash(conn: &Connection, username: &str) -> Result<Option<Hash>> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT password_hash FROM web_user WHERE username = ?1", [username], |row| {
            row.get(0)
        })
        .optional()
        .with_context(|| format!("looking up web user {username:?}"))?;

    Ok(stored
        .and_then(|bytes| <[u8; SECRET_BYTES]>::try_from(bytes.as_slice()).ok())
        .map(Hash::from))
}

/// How many users exist.
///
/// For the login page: a receiver with no users cannot be logged into at all, and saying so once at
/// startup is better than leaving it to be discovered as a form that never accepts anything.
pub fn count(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT count(*) FROM web_user", [], |row| row.get(0))
        .context("counting web users")
}

/// Every user, oldest first. Carries no hashes, for the same reason the key listing does not.
///
/// Oldest first rather than newest: with one operator the order is cosmetic, and creation order reads
/// more naturally than its reverse on a page that is normally one row long.
pub fn list(conn: &Connection) -> Result<Vec<StoredUser>> {
    let mut statement = conn
        .prepare("SELECT username, created_at FROM web_user ORDER BY created_at, username")
        .context("preparing the web user listing")?;

    let users = statement
        .query_map([], |row| Ok(StoredUser { username: row.get(0)?, created_at: row.get(1)? }))
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
    use crate::auth::hash_password;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        conn
    }

    #[test]
    fn a_stored_user_is_found_by_username() {
        let conn = db();
        insert(&conn, "sashee", &hash_password("correct horse"), 1_000).unwrap();

        assert_eq!(
            password_hash(&conn, "sashee").unwrap(),
            Some(hash_password("correct horse"))
        );
    }

    #[test]
    fn an_unknown_username_is_none_rather_than_an_error() {
        assert_eq!(password_hash(&db(), "nobody").unwrap(), None);
    }

    /// The password is not in the table in any form, which is the property the whole scheme rests on.
    #[test]
    fn no_column_holds_the_password() {
        let conn = db();
        insert(&conn, "sashee", &hash_password("hunter2-but-longer"), 1).unwrap();

        let dumped: String = conn
            .query_row(
                "SELECT quote(username) || quote(password_hash) || quote(created_at) FROM web_user",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!dumped.contains("hunter2"), "the password reached the database: {dumped}");
    }

    #[test]
    fn the_same_username_cannot_be_stored_twice() {
        let conn = db();
        insert(&conn, "sashee", &hash_password("a"), 1).unwrap();
        assert!(
            insert(&conn, "sashee", &hash_password("b"), 2).is_err(),
            "the primary key must refuse a duplicate username"
        );
    }

    /// Usernames are compared as stored, so two spellings are two users rather than one with two
    /// passwords. SQLite's default `BINARY` collation is what gives this; asserted because a later
        /// `COLLATE NOCASE` would silently change who can log in.
    #[test]
    fn usernames_are_case_sensitive() {
        let conn = db();
        insert(&conn, "sashee", &hash_password("a"), 1).unwrap();
        insert(&conn, "Sashee", &hash_password("b"), 2).expect("a different username");

        assert_eq!(password_hash(&conn, "sashee").unwrap(), Some(hash_password("a")));
        assert_eq!(password_hash(&conn, "Sashee").unwrap(), Some(hash_password("b")));
    }

    #[test]
    fn users_list_oldest_first_without_hashes() {
        let conn = db();
        insert(&conn, "second", &hash_password("b"), 2_000).unwrap();
        insert(&conn, "first", &hash_password("a"), 1_000).unwrap();

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
        insert(&conn, "sashee", &hash_password("a"), 1).unwrap();
        insert(&conn, "other", &hash_password("b"), 1).unwrap();
        crate::store::sessions::insert(&conn, "aa", &hash_password("s1"), "sashee", 1, 100).unwrap();
        crate::store::sessions::insert(&conn, "bb", &hash_password("s2"), "other", 1, 100).unwrap();

        assert!(delete(&conn, "sashee").unwrap());

        assert_eq!(password_hash(&conn, "sashee").unwrap(), None);
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
