//! The `web_login_token` table (SPEC §14.7). All SQL for sign-in tokens lives here; the token's format is
//! [`crate::auth`], which knows nothing about storage.
//!
//! A sign-in token lets its user in **once**, and only for a few minutes after it was issued: it is how a user
//! with no passkey on this device gets a session in which to add one.

use anyhow::{Context, Result};
use blake3::Hash;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::auth::SECRET_BYTES;

/// A token as stored — everything except the secret half, which no row contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLoginToken {
    pub id: String,
    pub username: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl StoredLoginToken {
    /// Whether it still signs in at `now`. Exclusive, like `sessions::SessionRecord::is_live`.
    pub fn is_live(&self, now: i64) -> bool {
        now < self.expires_at
    }
}

/// Stores a new token for `username`, **replacing any they had**, and returns whether the user exists.
///
/// One token per user, so issuing a new one is also how a token that went astray is voided, and the table
/// never holds more rows than there are users. Expired tokens are swept in the same transaction: issuing is
/// the only moment the table grows, so it is the moment to keep it small, as logging in is for sessions.
///
/// The insert names its user through `EXISTS` rather than leaving an unknown one to the foreign key, so "no
/// such user" is an answer and not an error a caller would have to pick out of a constraint failure.
pub fn issue(
    conn: &Connection,
    id: &str,
    secret_hash: &Hash,
    username: &str,
    created_at: i64,
    expires_at: i64,
) -> Result<bool> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .context("beginning the sign-in token issue")?;
    tx.execute(
        "DELETE FROM web_login_token WHERE username = ?1 OR expires_at <= ?2",
        params![username, created_at],
    )
    .with_context(|| format!("removing the earlier sign-in tokens of web user {username:?}"))?;
    let inserted = tx
        .execute(
            "INSERT INTO web_login_token (id, secret_hash, username, created_at, expires_at) \
             SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM web_user WHERE username = ?3)",
            params![id, secret_hash.as_bytes().as_slice(), username, created_at, expires_at],
        )
        .with_context(|| format!("storing a sign-in token for web user {username:?}"))?;
    tx.commit().context("committing the sign-in token")?;
    Ok(inserted > 0)
}

/// The session a redeemed token turns into: what [`crate::store::sessions::insert`] needs besides the user,
/// which the token decides, and the creation time, which is the redemption's.
#[derive(Debug, Clone, Copy)]
pub struct NewSession<'a> {
    pub id: &'a str,
    pub secret_hash: Hash,
    pub expires_at: i64,
}

/// What presenting a token came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redemption {
    /// The token was good: it is gone, and the session is stored.
    SignedIn { username: String },
    /// The token was good but too late. It is gone too, since nothing could use it now.
    Expired,
    /// No token has this id and secret — never issued, already used, replaced, or deleted.
    Unknown,
}

/// Uses up a token and starts `session` for its user, **both or neither**.
///
/// One `IMMEDIATE` transaction, which is what makes a token single-use: two requests presenting it at once
/// are serialized, and the second finds no row. And it is why the session is stored here rather than by the
/// caller afterwards — a failure between the two would otherwise spend the token and sign nobody in.
///
/// A wrong secret leaves the row alone. The id is the token's public half, so deleting on it alone would let
/// anyone who saw an id void the token behind it.
///
/// Expiry is checked against the `now` passed in, which is also the session's creation time: this module
/// takes no clock, as [`crate::store::sessions`] takes none.
pub fn redeem(
    conn: &Connection,
    id: &str,
    presented: &Hash,
    now: i64,
    session: NewSession<'_>,
) -> Result<Redemption> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .context("beginning the sign-in token redemption")?;
    let row: Option<(Vec<u8>, String, i64)> = tx
        .query_row(
            "SELECT secret_hash, username, expires_at FROM web_login_token WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .with_context(|| format!("looking up sign-in token {id}"))?;

    // A stored hash of the wrong width can only have been written by something other than `issue`, and
    // matches nothing — the rule every credential table here applies.
    // `blake3::Hash`'s constant-time `PartialEq`, as everywhere else a secret is compared.
    let Some((username, expires_at)) = row.and_then(|(hash, username, expires_at)| {
        let stored = Hash::from(<[u8; SECRET_BYTES]>::try_from(hash.as_slice()).ok()?);
        (stored == *presented).then_some((username, expires_at))
    }) else {
        return Ok(Redemption::Unknown);
    };

    tx.execute("DELETE FROM web_login_token WHERE id = ?1", [id])
        .with_context(|| format!("using up sign-in token {id}"))?;
    let outcome = if now < expires_at {
        let NewSession { id: session_id, secret_hash, expires_at: session_expires_at } = session;
        crate::store::sessions::insert(&tx, session_id, &secret_hash, &username, now, session_expires_at)?;
        Redemption::SignedIn { username }
    } else {
        Redemption::Expired
    };
    tx.commit().context("committing the sign-in token redemption")?;
    Ok(outcome)
}

/// Deletes `username`'s token, returning whether there was one.
pub fn delete(conn: &Connection, username: &str) -> Result<bool> {
    let removed = conn
        .execute("DELETE FROM web_login_token WHERE username = ?1", [username])
        .with_context(|| format!("deleting the sign-in token of web user {username:?}"))?;
    Ok(removed > 0)
}

/// Every token, expired ones included, oldest user first. Carries no hashes.
///
/// One listing for every reader — the account page wants one user's, the users page and `list-users` every
/// user's — because the table holds at most one row per user, and a query per question would be more code
/// than the rows it saves reading.
pub fn list(conn: &Connection) -> Result<Vec<StoredLoginToken>> {
    let mut statement = conn
        .prepare(
            "SELECT id, username, created_at, expires_at FROM web_login_token ORDER BY created_at, id",
        )
        .context("preparing the sign-in token listing")?;

    let tokens = statement
        .query_map([], |row| {
            Ok(StoredLoginToken {
                id: row.get(0)?,
                username: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })
        .context("listing sign-in tokens")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the sign-in token listing")?;

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{LoginToken, SessionToken, TOKEN_BYTES};

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        for user in ["sashee", "other"] {
            crate::store::users::insert(&conn, user, 1).unwrap();
        }
        conn
    }

    fn token(first: u8) -> LoginToken {
        let mut bytes = [7u8; TOKEN_BYTES];
        bytes[0] = first;
        LoginToken::from_random(&bytes)
    }

    fn issue_for(conn: &Connection, username: &str, token: &LoginToken, created_at: i64) -> bool {
        issue(conn, token.id(), &token.secret_hash(), username, created_at, created_at + 100).unwrap()
    }

    fn session(first: u8) -> SessionToken {
        SessionToken::from_random(&[first; TOKEN_BYTES])
    }

    fn redeem_at(conn: &Connection, token: &LoginToken, now: i64, session: &SessionToken) -> Redemption {
        let new = NewSession { id: session.id(), secret_hash: session.secret_hash(), expires_at: now + 1_000 };
        redeem(conn, token.id(), &token.secret_hash(), now, new).unwrap()
    }

    /// **Single use.** The token signs in once, starting the session, and then it is gone.
    #[test]
    fn a_token_signs_in_once() {
        let conn = db();
        let login = token(1);
        assert!(issue_for(&conn, "sashee", &login, 10));

        assert_eq!(
            redeem_at(&conn, &login, 20, &session(1)),
            Redemption::SignedIn { username: "sashee".into() }
        );
        let started = crate::store::sessions::lookup(&conn, session(1).id()).unwrap().expect("a session");
        assert_eq!(started.username, "sashee");
        assert_eq!(started.expires_at, 1_020);

        assert_eq!(redeem_at(&conn, &login, 21, &session(2)), Redemption::Unknown, "not twice");
        assert_eq!(crate::store::sessions::lookup(&conn, session(2).id()).unwrap(), None);
    }

    /// A wrong secret signs nobody in **and leaves the token usable**: the id alone must not be enough to
    /// void it.
    #[test]
    fn a_wrong_secret_neither_signs_in_nor_spends_the_token() {
        let conn = db();
        let login = token(1);
        issue_for(&conn, "sashee", &login, 10);

        let started = session(1);
        let wrong = NewSession { id: started.id(), secret_hash: started.secret_hash(), expires_at: 1_000 };
        // Another secret: `token(n)` varies only the id half.
        let presented = LoginToken::from_random(&[2; TOKEN_BYTES]).secret_hash();
        assert_eq!(redeem(&conn, login.id(), &presented, 20, wrong).unwrap(), Redemption::Unknown);

        assert_eq!(list(&conn).unwrap().len(), 1, "still there");
        assert!(matches!(redeem_at(&conn, &login, 20, &session(1)), Redemption::SignedIn { .. }));
    }

    /// Expiry is exclusive, and an expired token is used up rather than left to be tried again.
    #[test]
    fn an_expired_token_signs_nobody_in() {
        let conn = db();
        let login = token(1);
        issue_for(&conn, "sashee", &login, 10);

        assert_eq!(redeem_at(&conn, &login, 110, &session(1)), Redemption::Expired);
        assert_eq!(crate::store::sessions::lookup(&conn, session(1).id()).unwrap(), None);
        assert!(list(&conn).unwrap().is_empty(), "nothing could use it now");
    }

    /// One token per user: a new one voids the old, and leaves other users' alone.
    #[test]
    fn issuing_replaces_the_users_earlier_token() {
        let conn = db();
        let (first, second, theirs) = (token(1), token(2), token(3));
        issue_for(&conn, "sashee", &first, 10);
        issue_for(&conn, "other", &theirs, 10);
        issue_for(&conn, "sashee", &second, 20);

        assert_eq!(redeem_at(&conn, &first, 30, &session(1)), Redemption::Unknown, "replaced");
        assert!(matches!(redeem_at(&conn, &second, 30, &session(2)), Redemption::SignedIn { .. }));
        assert!(matches!(redeem_at(&conn, &theirs, 30, &session(3)), Redemption::SignedIn { .. }));
    }

    #[test]
    fn issuing_sweeps_expired_tokens() {
        let conn = db();
        issue_for(&conn, "other", &token(1), 10);
        issue_for(&conn, "sashee", &token(2), 500);

        let left: Vec<String> = list(&conn).unwrap().into_iter().map(|t| t.username).collect();
        assert_eq!(left, vec!["sashee".to_owned()]);
    }

    #[test]
    fn a_token_for_nobody_is_not_stored() {
        let conn = db();
        assert!(!issue_for(&conn, "ghost", &token(1), 10));
        assert!(list(&conn).unwrap().is_empty());
    }

    #[test]
    fn deleting_removes_only_that_users_token() {
        let conn = db();
        issue_for(&conn, "sashee", &token(1), 10);
        issue_for(&conn, "other", &token(2), 10);

        assert!(delete(&conn, "sashee").unwrap());
        assert!(!delete(&conn, "sashee").unwrap(), "deleting twice is false, not an error");
        let left: Vec<String> = list(&conn).unwrap().into_iter().map(|t| t.username).collect();
        assert_eq!(left, vec!["other".to_owned()]);
    }

    /// Deleting the user takes their token with them, so it cannot sign in as a user who is gone.
    #[test]
    fn deleting_a_user_deletes_their_token() {
        let conn = db();
        let login = token(1);
        issue_for(&conn, "sashee", &login, 10);

        crate::store::users::delete(&conn, "sashee").unwrap();
        assert_eq!(redeem_at(&conn, &login, 20, &session(1)), Redemption::Unknown);
    }

    /// The secret is not in the table in any form.
    #[test]
    fn no_column_holds_the_secret() {
        let conn = db();
        let login = token(1);
        issue_for(&conn, "sashee", &login, 10);

        let printed = login.to_secret_string();
        let secret = printed.split_once('.').unwrap().1;
        let dumped: String = conn
            .query_row("SELECT quote(id) || quote(secret_hash) FROM web_login_token", [], |r| r.get(0))
            .unwrap();
        assert!(!dumped.contains(secret), "the secret reached the database: {dumped}");
    }

    #[test]
    fn a_token_is_live_strictly_before_its_expiry() {
        let stored =
            StoredLoginToken { id: "x".into(), username: "sashee".into(), created_at: 0, expires_at: 100 };
        assert!(stored.is_live(99));
        assert!(!stored.is_live(100));
    }
}
