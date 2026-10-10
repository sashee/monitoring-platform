//! The account page (SPEC §14.10): the signed-in user's own passkeys — listing, adding and removing them — and
//! their sign-in token (§14.7), which gets them in once on a device that has no passkey yet.
//!
//! **One of the two pages with a script on it** (the other is the login page; both scripts are in
//! `web::passkey_page`). WebAuthn has no HTML-form API, so adding a passkey takes a script — and only that
//! does: without it the page still lists and removes passkeys.

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::Extension;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::passkey::{self, PasskeyError, Site};
use super::passkey_page;
use super::login_token::{self, Issued};
use super::session::Identity;
use super::{failed, html, see_other};
use crate::AppState;
use crate::api::query::format_nanos;
use crate::store::login_tokens::StoredLoginToken;
use crate::store::passkeys::{ListedPasskey, PasskeyRemoval};

/// The longest name a passkey may be given. A label in a table, not a description.
const MAX_LABEL_CHARS: usize = 64;

pub async fn account(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Response {
    render(&state, &identity, &headers, None, None).await
}

#[derive(Deserialize)]
pub struct NewPasskeyForm {
    label: String,
    /// The credential as WebAuthn JSON, filled in by the page's script.
    response: String,
}

pub async fn add_passkey(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
    Form(form): Form<NewPasskeyForm>,
) -> Response {
    let label = form.label.trim().to_owned();
    // The input says `required` and `maxlength`, and the browser checks both before the script runs — so
    // this only refuses a request that did not come from the form. By then the authenticator has made the
    // passkey, which is why the browser's check, not this one, is the one a person meets.
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return render(&state, &identity, &headers, Some("A passkey needs a name, up to 64 characters."), None)
            .await;
    }
    // A `POST` reaches here only if the origin guard matched `Origin` to `Host`, so this is the request's
    // own origin — the one the browser signed into the client data.
    let Some(site) = header_value(&headers, header::ORIGIN).and_then(Site::from_origin) else {
        return render(&state, &identity, &headers, Some(PasskeyError::NotLocalhost.message()), None).await;
    };

    let db_path = state.config.database_path.clone();
    let ceremonies = state.ceremonies.clone();
    let (username, stored_label) = (identity.username.clone(), label.clone());
    let added = tokio::task::spawn_blocking(move || -> anyhow::Result<Result<String, PasskeyError>> {
        let passkey =
            match passkey::finish_registration(&ceremonies, &site, &username, &form.response) {
                Ok(passkey) => passkey,
                Err(e) => return Ok(Err(e)),
            };
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::passkeys::insert(&conn, &username, &passkey, &stored_label, crate::now_unix_nanos())?;
        Ok(Ok(passkey.rp_id))
    })
    .await;

    match added {
        Ok(Ok(Ok(rp_id))) => {
            tracing::info!(user = %identity.username, %rp_id, %label, "passkey added");
            see_other("/account")
        }
        Ok(Ok(Err(e))) => {
            // `warn` with the library's reason: the realistic causes are an expired prompt or a browser
            // sending something unexpected, and the journal is where that can be told apart.
            tracing::warn!(user = %identity.username, error = %e, "passkey not added");
            render(&state, &identity, &headers, Some(e.message()), None).await
        }
        Ok(Err(e)) => failed("storing the new passkey", &e),
        Err(e) => failed("the passkey task", &e),
    }
}

#[derive(Deserialize)]
pub struct TargetPasskey {
    /// The credential id, base64url without padding — as rendered in the table.
    credential: String,
}

pub async fn remove_passkey(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
    Form(form): Form<TargetPasskey>,
) -> Response {
    // An id that does not decode names no passkey, which is the same outcome as one already removed.
    let Ok(id) = URL_SAFE_NO_PAD.decode(form.credential.as_bytes()) else {
        return see_other("/account");
    };
    let db_path = state.config.database_path.clone();
    let username = identity.username.clone();
    let removed = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::passkeys::delete(&conn, &username, &id)
    })
    .await;

    match removed {
        Ok(Ok(PasskeyRemoval::Removed)) => {
            tracing::info!(user = %identity.username, "passkey removed");
            see_other("/account")
        }
        Ok(Ok(PasskeyRemoval::NotFound)) => see_other("/account"),
        // The page hides this passkey's button, so this is a page older than another passkey's removal, or a
        // request that did not come from it — checked here regardless, where the delete happens.
        Ok(Ok(PasskeyRemoval::LastWayIn)) => {
            render(&state, &identity, &headers, Some(LAST_WAY_IN), None).await
        }
        Ok(Err(e)) => failed("removing the passkey", &e),
        Err(e) => failed("the passkey task", &e),
    }
}

/// Why the last passkey stays.
const LAST_WAY_IN: &str = "That is your only passkey, so it is your only way to sign in. Add another passkey \
                           first. (Lost them all? create-login-token on the host gets you back in.)";

/// Issues a sign-in token for the signed-in user, replacing any they had, and shows it the one time it exists.
///
/// For a device with no passkey yet: the token gets it in once, and the passkey is added there. Only for
/// yourself — a token for someone else is `create-login-token` on the host, or the one shown on creating them.
pub async fn issue_token(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Response {
    let db_path = state.config.database_path.clone();
    let username = identity.username.clone();
    let issued = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        login_token::issue(&conn, &username, crate::now_unix_nanos())
    })
    .await;

    match issued {
        Ok(Ok(Some(issued))) => {
            // The id is public and worth logging; the token is not.
            tracing::info!(user = %identity.username, token = %issued.token.id(), "sign-in token issued");
            render(&state, &identity, &headers, None, Some(&issued)).await
        }
        // The session guard found this user a moment ago, and deleting a user deletes their sessions.
        Ok(Ok(None)) => failed("issuing a sign-in token", &"the signed-in user no longer exists"),
        Ok(Err(e)) => failed("issuing a sign-in token", &e),
        Err(e) => failed("the sign-in token task", &e),
    }
}

/// Deletes the signed-in user's sign-in token, if they have one.
pub async fn delete_token(State(state): State<AppState>, Extension(identity): Extension<Identity>) -> Response {
    let db_path = state.config.database_path.clone();
    let username = identity.username.clone();
    let deleted = tokio::task::spawn_blocking(move || {
        let conn = crate::store::open_write_existing(&db_path)?;
        crate::store::login_tokens::delete(&conn, &username)
    })
    .await;

    match deleted {
        Ok(Ok(existed)) => {
            if existed {
                tracing::info!(user = %identity.username, "sign-in token deleted");
            }
            see_other("/account")
        }
        Ok(Err(e)) => failed("deleting the sign-in token", &e),
        Err(e) => failed("the sign-in token task", &e),
    }
}

/// What the "add a passkey" section can offer, decided by the host the page was reached at.
enum Adding {
    /// A ceremony has started; these are its options for the browser.
    Ready(String),
    /// Not a loopback name, so no passkey can be bound here. Carries the `Host` it was reached at, so the
    /// page can link to the same address under `localhost`.
    NotLocalhost(Option<String>),
    /// The ceremony could not start.
    Refused(PasskeyError),
}

/// The account page, optionally with an error from a failed action, or with a sign-in token just issued — the
/// one time it is shown.
async fn render(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    error: Option<&str>,
    issued: Option<&Issued>,
) -> Response {
    let db_path = state.config.database_path.clone();
    let ceremonies = state.ceremonies.clone();
    let username = identity.username.clone();
    let host = header_value(headers, header::HOST).map(str::to_owned);
    let gathered = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Vec<ListedPasskey>, Option<StoredLoginToken>, Adding)> {
            let conn = crate::store::open_read(&db_path)?;
            let listed = crate::store::passkeys::list(&conn, &username)?;
            let now = crate::now_unix_nanos();
            let token = crate::store::login_tokens::list(&conn)?
                .into_iter()
                .find(|t| t.username == username && t.is_live(now));
            let adding = match host.as_deref().and_then(passkey::rp_id_for) {
                Some(rp_id) => {
                    let existing = crate::store::passkeys::ids_on(&conn, &username, &rp_id)?;
                    match passkey::start_registration(&ceremonies, &rp_id, &username, existing) {
                        Ok(options) => Adding::Ready(options),
                        Err(e) => Adding::Refused(e),
                    }
                }
                None => Adding::NotLocalhost(host),
            };
            Ok((listed, token, adding))
        },
    )
    .await;

    let (listed, token, adding) = match gathered {
        Ok(Ok(gathered)) => gathered,
        Ok(Err(e)) => return failed("reading your passkeys", &e),
        Err(e) => return failed("the passkey query task", &e),
    };

    let mut body = String::new();
    if let Some(message) = error {
        body.push_str(&format!("<p class=\"error\">{}</p>\n", html::escape(message)));
    }
    body.push_str("<h2>passkeys</h2>\n");
    body.push_str(&passkey_table(&listed));
    body.push_str("<h2>add a passkey</h2>\n");
    body.push_str(&match adding {
        Adding::Ready(options) => passkey_page::add_form(&options, MAX_LABEL_CHARS),
        Adding::NotLocalhost(host) => passkey_page::not_localhost(host.as_deref(), "/account", "added"),
        Adding::Refused(e) => {
            tracing::warn!(user = %identity.username, error = %e, "passkey registration could not start");
            html::note(e.message())
        }
    });

    body.push_str("<h2>sign-in token</h2>\n");
    body.push_str(&token_section(issued, token.as_ref()));

    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    super::html(status, html::page("account", "/account", &body))
}

/// The sign-in token: the one just issued, shown once; or the one waiting, with a button to delete it; and the
/// button that issues one — a new one replaces the old.
fn token_section(issued: Option<&Issued>, waiting: Option<&StoredLoginToken>) -> String {
    let state = match (issued, waiting) {
        (Some(issued), _) => html::issued(
            &issued.token.to_secret_string(),
            &format!(
                "Copy this now — it is not stored and cannot be shown again. Paste it into the sign-in form \
                 on the device to add a passkey on. It works once, until {}:",
                format_nanos(issued.expires_at)
            ),
        ),
        // Separate elements: a `<form>` inside a `<p>` closes the paragraph where it starts.
        (None, Some(waiting)) => format!(
            "{}<form method=\"post\" action=\"/account/tokens/delete\" class=\"inline\">\
             <button type=\"submit\">delete it</button></form>\n",
            html::note(&format!("A sign-in token you issued works until {}.", format_nanos(waiting.expires_at)))
        ),
        (None, None) => html::note(
            "A sign-in token lets you in once, within 15 minutes, on a device with no passkey yet — so that \
             you can add one there.",
        ),
    };
    let label = if issued.is_some() || waiting.is_some() { "issue a new one" } else { "issue a sign-in token" };
    format!(
        "{state}<form method=\"post\" action=\"/account/tokens/create\" class=\"inline\">\
         <button type=\"submit\">{label}</button></form>\n"
    )
}

fn passkey_table(listed: &[ListedPasskey]) -> String {
    // The last passkey is the only way in from this page: its button is not rendered, as the last user's
    // delete button is not on the users page. The handler refuses it regardless.
    let last_way_in = listed.len() == 1;
    let rows: Vec<Vec<String>> = listed
        .iter()
        .map(|p| {
            vec![
                html::escape(&p.label),
                html::escape(&p.rp_id),
                html::escape(&format_nanos(p.created_at)),
                html::escape(&p.last_used_at.map(format_nanos).unwrap_or_else(|| "never".to_owned())),
                if last_way_in {
                    String::new()
                } else {
                    html::post_button(
                        "/account/passkeys/delete",
                        "credential",
                        &URL_SAFE_NO_PAD.encode(&p.credential_id),
                        "remove",
                        "link",
                    )
                },
            ]
        })
        .collect();
    let mut out =
        html::table(&["name", "site", "added", "last used", ""], &rows, "no passkeys yet");
    if !listed.is_empty() {
        out.push_str(&html::note(
            "A passkey belongs to the address it was added at: one added on this laptop at localhost is \
             not offered on the phone, which reaches this page at its own address.",
        ));
    }
    out
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}
