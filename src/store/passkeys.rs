//! The `web_passkey` table (SPEC §14.10). All SQL for passkeys lives here; what the stored state means is
//! `web::passkey`'s business, which is the only place that knows about WebAuthn.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::HashMap;

/// A newly registered passkey, as `web::passkey` hands it over: opaque bytes plus the site it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    /// The host it was registered from, without a port: what a later sign-in is checked against.
    pub rp_id: String,
    pub static_state: Vec<u8>,
    pub dynamic_state: Vec<u8>,
}

/// A passkey as listed to its owner: everything but the key material, which no page needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedPasskey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// A passkey as a sign-in needs it: its owner and site, and the state to verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub username: String,
    pub rp_id: String,
    pub static_state: Vec<u8>,
    pub dynamic_state: Vec<u8>,
}

pub fn insert(
    conn: &Connection,
    username: &str,
    passkey: &NewPasskey,
    label: &str,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO web_passkey \
         (credential_id, username, rp_id, static_state, dynamic_state, label, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            passkey.credential_id,
            username,
            passkey.rp_id,
            passkey.static_state,
            passkey.dynamic_state,
            label,
            created_at
        ],
    )
    .with_context(|| format!("storing a passkey for web user {username:?}"))?;
    Ok(())
}

/// One user's passkeys, newest first.
pub fn list(conn: &Connection, username: &str) -> Result<Vec<ListedPasskey>> {
    let mut statement = conn
        .prepare(
            "SELECT credential_id, rp_id, label, created_at, last_used_at FROM web_passkey \
             WHERE username = ?1 ORDER BY created_at DESC, credential_id",
        )
        .context("preparing the passkey listing")?;
    let listed = statement
        .query_map([username], |row| {
            Ok(ListedPasskey {
                credential_id: row.get(0)?,
                rp_id: row.get(1)?,
                label: row.get(2)?,
                created_at: row.get(3)?,
                last_used_at: row.get(4)?,
            })
        })
        .with_context(|| format!("listing passkeys for web user {username:?}"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the passkey listing")?;
    Ok(listed)
}

/// The credential ids a user already has on one site.
///
/// Sent as `excludeCredentials` when registering, so an authenticator that already holds a passkey for
/// this account says so instead of quietly replacing it. Only the one site, because a passkey registered
/// on another host is bound to that host and could never be on the authenticator being asked.
pub fn ids_on(conn: &Connection, username: &str, rp_id: &str) -> Result<Vec<Vec<u8>>> {
    let mut statement = conn
        .prepare("SELECT credential_id FROM web_passkey WHERE username = ?1 AND rp_id = ?2")
        .context("preparing the passkey id lookup")?;
    let ids = statement
        .query_map(params![username, rp_id], |row| row.get(0))
        .with_context(|| format!("looking up passkey ids for web user {username:?}"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading the passkey ids")?;
    Ok(ids)
}

/// Whether a passkey was removed, or why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyRemoval {
    Removed,
    /// No such passkey of this user's — already removed, or someone else's.
    NotFound,
    /// It is the user's last passkey and they have no password, so nothing would sign them in afterwards.
    LastWayIn,
}

/// Removes one of `username`'s passkeys — unless it is their last way in.
///
/// Scoped to the owner in the statement itself, so a form naming someone else's credential id removes
/// nothing, rather than relying on the handler to have checked first. The last-way-in check runs in the same
/// `IMMEDIATE` transaction as the delete, for the reason `users::remove_password` gives: checked separately,
/// removing the password and removing the last passkey could each pass on their own and together lock the user
/// out.
pub fn delete(conn: &Connection, username: &str, credential_id: &[u8]) -> Result<PasskeyRemoval> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .context("beginning the passkey removal")?;
    let others: i64 = tx
        .query_row(
            "SELECT count(*) FROM web_passkey WHERE username = ?1 AND credential_id != ?2",
            params![username, credential_id],
            |r| r.get(0),
        )
        .with_context(|| format!("counting the passkeys of web user {username:?}"))?;
    if others == 0 && !crate::store::users::has_password(&tx, username)? {
        let exists: bool = tx
            .query_row(
                "SELECT count(*) > 0 FROM web_passkey WHERE username = ?1 AND credential_id = ?2",
                params![username, credential_id],
                |r| r.get(0),
            )
            .context("looking up the passkey to remove")?;
        return Ok(if exists { PasskeyRemoval::LastWayIn } else { PasskeyRemoval::NotFound });
    }
    let removed = tx
        .execute(
            "DELETE FROM web_passkey WHERE username = ?1 AND credential_id = ?2",
            params![username, credential_id],
        )
        .with_context(|| format!("deleting a passkey of web user {username:?}"))?;
    tx.commit().context("committing the passkey removal")?;
    Ok(if removed > 0 { PasskeyRemoval::Removed } else { PasskeyRemoval::NotFound })
}

/// The passkey with this credential id, whoever owns it — a sign-in names no user until it has verified.
pub fn find(conn: &Connection, credential_id: &[u8]) -> Result<Option<StoredCredential>> {
    conn.query_row(
        "SELECT username, rp_id, static_state, dynamic_state FROM web_passkey WHERE credential_id = ?1",
        [credential_id],
        |row| {
            Ok(StoredCredential {
                credential_id: credential_id.to_vec(),
                username: row.get(0)?,
                rp_id: row.get(1)?,
                static_state: row.get(2)?,
                dynamic_state: row.get(3)?,
            })
        },
    )
    .optional()
    .context("looking up a passkey")
}

/// Records a sign-in with a passkey: when, and its new dynamic state when the verification changed it.
///
/// `dynamic_state` is `None` when nothing changed — the phone app's counter stays at zero, so for it this is
/// only ever the timestamp.
pub fn record_use(
    conn: &Connection,
    credential_id: &[u8],
    dynamic_state: Option<&[u8]>,
    at: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE web_passkey SET last_used_at = ?2, dynamic_state = coalesce(?3, dynamic_state) \
         WHERE credential_id = ?1",
        params![credential_id, at, dynamic_state],
    )
    .context("recording a passkey sign-in")?;
    Ok(())
}

/// How many passkeys each user has, for the users page. Users with none are absent.
pub fn counts(conn: &Connection) -> Result<HashMap<String, i64>> {
    let mut statement = conn
        .prepare("SELECT username, count(*) FROM web_passkey GROUP BY username")
        .context("preparing the passkey counts")?;
    let counts = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .context("counting passkeys")?
        .collect::<rusqlite::Result<HashMap<_, _>>>()
        .context("reading the passkey counts")?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hash_password;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::store::schema::migrate(&conn).unwrap();
        for user in ["sashee", "other"] {
            crate::store::users::insert(&conn, user, &hash_password("pw"), 1).unwrap();
        }
        conn
    }

    fn passkey(id: u8, rp_id: &str) -> NewPasskey {
        NewPasskey {
            credential_id: vec![id; 16],
            rp_id: rp_id.to_owned(),
            static_state: vec![1, 2, 3],
            dynamic_state: vec![4, 5],
        }
    }

    #[test]
    fn a_stored_passkey_is_listed_to_its_owner_newest_first() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        insert(&conn, "sashee", &passkey(2, "abc.localhost"), "phone", 200).unwrap();

        let listed = list(&conn, "sashee").unwrap();
        assert_eq!(listed.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(), ["phone", "laptop"]);
        assert_eq!(listed[0].rp_id, "abc.localhost");
        assert_eq!(listed[0].last_used_at, None);
        assert!(list(&conn, "other").unwrap().is_empty());
    }

    #[test]
    fn excluded_ids_are_only_those_on_the_same_site() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        insert(&conn, "sashee", &passkey(2, "abc.localhost"), "phone", 200).unwrap();
        assert_eq!(ids_on(&conn, "sashee", "abc.localhost").unwrap(), vec![vec![2; 16]]);
    }

    /// Another user's credential id removes nothing: the owner is part of the statement.
    #[test]
    fn a_passkey_can_only_be_deleted_by_its_owner() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        assert_eq!(delete(&conn, "other", &[1; 16]).unwrap(), PasskeyRemoval::NotFound);
        assert_eq!(list(&conn, "sashee").unwrap().len(), 1);
        assert_eq!(delete(&conn, "sashee", &[1; 16]).unwrap(), PasskeyRemoval::Removed);
        assert!(list(&conn, "sashee").unwrap().is_empty());
    }

    /// Deleting a user deletes their passkeys — by the foreign key, not by a statement someone has to
    /// remember to add to `users::delete`.
    #[test]
    fn deleting_a_user_deletes_their_passkeys() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        crate::store::users::delete(&conn, "sashee").unwrap();
        let left: i64 = conn.query_row("SELECT count(*) FROM web_passkey", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn a_passkey_cannot_belong_to_a_user_that_does_not_exist() {
        assert!(insert(&db(), "nobody", &passkey(1, "localhost"), "laptop", 100).is_err());
    }

    #[test]
    fn a_passkey_is_found_by_its_credential_id_with_its_owner() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "abc.localhost"), "phone", 100).unwrap();
        let found = find(&conn, &[1; 16]).unwrap().unwrap();
        assert_eq!((found.username.as_str(), found.rp_id.as_str()), ("sashee", "abc.localhost"));
        assert_eq!((found.static_state, found.dynamic_state), (vec![1, 2, 3], vec![4, 5]));
        assert_eq!(find(&conn, &[9; 16]).unwrap(), None);
    }

    /// A sign-in always records when, and replaces the dynamic state only when verification changed it.
    #[test]
    fn a_use_records_the_time_and_any_new_state() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "abc.localhost"), "phone", 100).unwrap();

        record_use(&conn, &[1; 16], None, 500).unwrap();
        assert_eq!(list(&conn, "sashee").unwrap()[0].last_used_at, Some(500));
        assert_eq!(find(&conn, &[1; 16]).unwrap().unwrap().dynamic_state, vec![4, 5]);

        record_use(&conn, &[1; 16], Some(&[6, 7]), 600).unwrap();
        assert_eq!(list(&conn, "sashee").unwrap()[0].last_used_at, Some(600));
        assert_eq!(find(&conn, &[1; 16]).unwrap().unwrap().dynamic_state, vec![6, 7]);
    }

    /// **The other lockout guard.** Without a password, a user's last passkey is their only way in: it is
    /// kept. With another passkey, or with a password, it goes.
    #[test]
    fn the_last_way_in_is_not_removed() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        insert(&conn, "sashee", &passkey(2, "abc.localhost"), "phone", 200).unwrap();
        crate::store::users::remove_password(&conn, "sashee").unwrap();

        assert_eq!(delete(&conn, "sashee", &[1; 16]).unwrap(), PasskeyRemoval::Removed, "another remains");
        assert_eq!(delete(&conn, "sashee", &[2; 16]).unwrap(), PasskeyRemoval::LastWayIn);
        assert_eq!(list(&conn, "sashee").unwrap().len(), 1, "the last one is kept");
        assert_eq!(delete(&conn, "sashee", &[9; 16]).unwrap(), PasskeyRemoval::NotFound);

        let hash = crate::auth::hash_password("back");
        crate::store::users::set_password(&conn, "sashee", &hash).unwrap();
        assert_eq!(delete(&conn, "sashee", &[2; 16]).unwrap(), PasskeyRemoval::Removed, "a password remains");
    }

    #[test]
    fn passkeys_are_counted_per_user() {
        let conn = db();
        insert(&conn, "sashee", &passkey(1, "localhost"), "laptop", 100).unwrap();
        insert(&conn, "sashee", &passkey(2, "abc.localhost"), "phone", 200).unwrap();
        let counts = counts(&conn).unwrap();
        assert_eq!(counts.get("sashee"), Some(&2));
        assert_eq!(counts.get("other"), None);
    }
}
