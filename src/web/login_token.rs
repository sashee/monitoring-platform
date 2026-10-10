//! Issuing sign-in tokens (SPEC §14.7) — shared by the pages that issue them and by `create-user` and
//! `create-login-token`, so a token is one thing however it was issued.
//!
//! Redeeming one is the login form's (`web::login`), and the storage is `store::login_tokens`.

use rusqlite::Connection;

use crate::auth::LoginToken;

/// How long a sign-in token works: fifteen minutes.
///
/// Long enough to carry it from a terminal or another device to the one being set up, short enough that one
/// left in a scrollback or a clipboard is dead by the time anyone finds it. Like the session lifetime, a
/// constant rather than a module option.
pub const TTL_NANOS: i64 = 15 * 60 * 1_000_000_000;

/// A token just issued: the secret, which exists only here and in what is shown, and when it stops working.
pub struct Issued {
    pub token: LoginToken,
    pub expires_at: i64,
}

/// Issues a token for `username`, replacing any they had, or `None` when there is no such user.
pub fn issue(conn: &Connection, username: &str, now: i64) -> anyhow::Result<Option<Issued>> {
    let token = LoginToken::from_random(&crate::random_bytes()?);
    let expires_at = now.saturating_add(TTL_NANOS);
    let stored =
        crate::store::login_tokens::issue(conn, token.id(), &token.secret_hash(), username, now, expires_at)?;
    Ok(stored.then_some(Issued { token, expires_at }))
}
