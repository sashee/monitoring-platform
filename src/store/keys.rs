//! The `api_key` table (SPEC §13). All SQL for API keys lives here; the token format itself is
//! [`crate::auth`], which knows nothing about storage.

use anyhow::{Context, Result};
use blake3::Hash;
use rusqlite::{Connection, OptionalExtension, params};

use crate::auth::SECRET_BYTES;

/// A key as stored — that is, everything about it *except* the secret, which no query can return
/// because no row contains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    pub id: String,
    pub label: String,
    pub created_at: i64,
}

pub fn insert(
    conn: &Connection,
    id: &str,
    secret_hash: &Hash,
    label: &str,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO api_key (id, secret_hash, label, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, secret_hash.as_bytes().as_slice(), label, created_at],
    )
    .with_context(|| format!("storing api key {id}"))?;
    Ok(())
}

/// The stored hash for one id, or `None` when there is no such key.
///
/// By id rather than by scanning, which is the point of the token having a public half: a request
/// carrying an id nobody issued is refused after one index probe, without hashing anything.
///
/// A row whose `secret_hash` is not 32 bytes reads as `None`. It cannot be produced by [`insert`],
/// so it means the column was written by something else — and treating an unusable hash as "no such
/// key" is the only safe reading.
pub fn secret_hash(conn: &Connection, id: &str) -> Result<Option<Hash>> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT secret_hash FROM api_key WHERE id = ?1", [id], |row| row.get(0))
        .optional()
        .with_context(|| format!("looking up api key {id}"))?;

    Ok(stored
        .and_then(|bytes| <[u8; SECRET_BYTES]>::try_from(bytes.as_slice()).ok())
        .map(Hash::from))
}

/// Every key, newest first. For the operator-facing listing, so it carries no hashes either.
pub fn list(conn: &Connection) -> Result<Vec<StoredKey>> {
    let mut statement = conn
        .prepare("SELECT id, label, created_at FROM api_key ORDER BY created_at DESC, id")
        .context("preparing the api key listing")?;

    let keys = statement
        .query_map([], |row| {
            Ok(StoredKey { id: row.get(0)?, label: row.get(1)?, created_at: row.get(2)? })
        })
        .context("listing api keys")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the api key listing")?;

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Token, hash_secret};

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        conn
    }

    fn token(first: u8) -> Token {
        let mut bytes = [7u8; crate::auth::TOKEN_BYTES];
        bytes[0] = first;
        Token::from_random(&bytes)
    }

    #[test]
    fn a_stored_key_is_found_by_its_id() {
        let conn = db();
        let token = token(1);
        insert(&conn, token.id(), &token.secret_hash(), "pi-7", 1_000).unwrap();

        assert_eq!(secret_hash(&conn, token.id()).unwrap(), Some(token.secret_hash()));
    }

    #[test]
    fn an_unissued_id_is_none_rather_than_an_error() {
        let conn = db();
        assert_eq!(secret_hash(&conn, "0000000000000000").unwrap(), None);
    }

    /// The secret is not in the table in any form, which is the property the whole scheme rests on.
    #[test]
    fn no_column_holds_the_secret() {
        let conn = db();
        let token = token(2);
        let printed = token.to_secret_string();
        insert(&conn, token.id(), &token.secret_hash(), "pi-7", 1_000).unwrap();

        let secret = printed.split_once('.').unwrap().1;
        let dumped: String = conn
            .query_row("SELECT quote(id) || quote(secret_hash) || quote(label) FROM api_key", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!dumped.contains(secret), "the secret reached the database: {dumped}");
    }

    #[test]
    fn the_same_id_cannot_be_stored_twice() {
        let conn = db();
        let token = token(3);
        insert(&conn, token.id(), &token.secret_hash(), "first", 1).unwrap();
        assert!(
            insert(&conn, token.id(), &token.secret_hash(), "second", 2).is_err(),
            "the primary key must refuse a duplicate id"
        );
    }

    #[test]
    fn keys_list_newest_first_without_hashes() {
        let conn = db();
        let (old, new) = (token(4), token(5));
        insert(&conn, old.id(), &old.secret_hash(), "old", 1_000).unwrap();
        insert(&conn, new.id(), &new.secret_hash(), "new", 2_000).unwrap();

        let listed = list(&conn).unwrap();
        assert_eq!(
            listed,
            vec![
                StoredKey { id: new.id().to_owned(), label: "new".into(), created_at: 2_000 },
                StoredKey { id: old.id().to_owned(), label: "old".into(), created_at: 1_000 },
            ]
        );
    }

    #[test]
    fn an_empty_table_lists_as_nothing() {
        assert!(list(&db()).unwrap().is_empty());
    }

    /// A `secret_hash` of the wrong width can only come from something other than `insert`. It must
    /// read as "no such key" rather than panicking or matching anything.
    #[test]
    fn a_hash_of_the_wrong_length_is_not_a_usable_key() {
        let conn = db();
        conn.execute(
            "INSERT INTO api_key (id, secret_hash, label, created_at) \
             VALUES ('0000000000000001', x'00', 'hand-written', 1)",
            [],
        )
        .unwrap();

        assert_eq!(secret_hash(&conn, "0000000000000001").unwrap(), None);
    }

    /// The hash stored is the domain-separated one, not a bare blake3 of the secret.
    #[test]
    fn the_stored_hash_is_the_domain_separated_one() {
        let conn = db();
        let token = token(6);
        insert(&conn, token.id(), &token.secret_hash(), "pi-7", 1).unwrap();

        let stored = secret_hash(&conn, token.id()).unwrap().unwrap();
        let secret_hex = token.to_secret_string().split_once('.').unwrap().1.to_owned();
        assert_ne!(stored, blake3::hash(secret_hex.as_bytes()));
        assert_eq!(stored, hash_secret(&hex_to_bytes(&secret_hex)));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
