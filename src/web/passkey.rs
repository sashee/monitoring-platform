//! Passkeys (SPEC §14.10): the WebAuthn half — which sites may hold one, registering one, and signing in
//! with one. The table is `store::passkeys`; the pages are `web::account` and the login page.
//!
//! **A passkey is bound to the host it was registered from, not to a site name chosen here.** Each device
//! reaches this page at its own loopback name: a laptop at `localhost`, the phone app at
//! `<label>.localhost`, its label derived from the tunnel's endpoint id. There is no one host they share,
//! and the phone app refuses an RP ID other than its own host anyway. So the RP ID is taken from the
//! request, each passkey records it, and a sign-in is checked against the passkey's own.
//!
//! **Taking the RP ID from the request is safe because only loopback names are accepted.** `localhost` and
//! `*.localhost` always resolve to the device the browser runs on, so no remote site can serve a page there
//! to phish a registration. Anything else — `127.0.0.1` included, which browsers refuse for WebAuthn
//! regardless — gets no passkey. The port is never part of it: an RP ID has none, and the tunnel's local
//! port is whatever was free.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use webauthn_rp::bin::{Decode as _, Encode as _};
use webauthn_rp::request::auth::AuthenticationVerificationOptions;
use webauthn_rp::request::register::{
    CredProtect, Nickname, PublicKeyCredentialUserEntity, RegistrationVerificationOptions,
    USER_HANDLE_MAX_LEN, UserHandle64, Username,
};
use webauthn_rp::request::{
    AsciiDomain, DomainOrigin, FixedCapHashSet, InsertResult, Port, PublicKeyCredentialDescriptor, RpId,
    Scheme,
};
use webauthn_rp::response::auth::ser_relaxed::DiscoverableAuthenticationRelaxed64;
use webauthn_rp::response::register::ser_relaxed::RegistrationRelaxed;
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, CredentialId};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication64, DiscoverableAuthenticationServerState,
    DiscoverableCredentialRequestOptions, PublicKeyCredentialCreationOptions, RegistrationServerState,
};

use crate::store::passkeys::{NewPasskey, StoredCredential};

/// How many registrations may be in progress at once. Each is a page someone has open with an "add a
/// passkey" button on it; a full set replaces whatever has expired, and refuses only if nothing has.
const CEREMONY_CAPACITY: usize = 32;

/// The same for sign-ins, with more room: every visit to the login page starts one, including every
/// redirect there from an expired session. Reaching the page at all takes the tunnel's own authentication
/// (SPEC §14.5), so this bounds memory rather than defending against strangers — and a full set refuses only
/// the passkey button; the password form does not use it.
const SIGN_IN_CAPACITY: usize = 64;

/// Domain for deriving a user handle. Frozen: changing it changes every user's handle, after which no
/// existing passkey signs anyone in.
const DOMAIN_USER_HANDLE: &[u8] = b"monitoring-platform/passkey-user-handle/v1";

/// Ceremonies in progress, between the page that starts one and the form that finishes it.
///
/// **In memory, not in the database.** A ceremony lives for minutes and means nothing after a restart, so
/// a table would only add a write per page view and a sweep to forget it again. The cost is that a passkey
/// prompt open across a restart fails, and is tapped again.
pub struct Ceremonies {
    registrations: Mutex<FixedCapHashSet<RegistrationServerState<USER_HANDLE_MAX_LEN>>>,
    sign_ins: Mutex<FixedCapHashSet<DiscoverableAuthenticationServerState>>,
}

impl Default for Ceremonies {
    fn default() -> Self {
        Self {
            registrations: Mutex::new(FixedCapHashSet::new(CEREMONY_CAPACITY)),
            sign_ins: Mutex::new(FixedCapHashSet::new(SIGN_IN_CAPACITY)),
        }
    }
}

/// Where a ceremony is finished: the scheme, host and port of the request's `Origin`.
///
/// Built from `Origin` only on a `POST`, which the origin guard has already matched against `Host` — so it
/// is this request's own origin, the one the browser put in the signed client data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl Site {
    /// Parses an `Origin` header value, if its host is one passkeys may be bound to.
    pub fn from_origin(origin: &str) -> Option<Site> {
        let (scheme, authority) = origin.split_once("://")?;
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let (host, port) = split_port(authority)?;
        Some(Site { scheme: scheme.to_owned(), host: rp_id_for(host)?, port })
    }
}

/// The RP ID for a page reached at `host` (a `Host` header value, port and all), if passkeys may be bound
/// there: `localhost` or a `*.localhost` name, lowercased, without its port.
pub fn rp_id_for(host: &str) -> Option<String> {
    let (name, _port) = split_port(host)?;
    let name = name.to_ascii_lowercase();
    let loopback =
        name == "localhost" || name.strip_suffix(".localhost").is_some_and(|label| !label.is_empty());
    (loopback && AsciiDomain::try_from(name.clone()).is_ok()).then_some(name)
}

/// `host[:port]` into its parts. `None` when there is a colon but no valid port after it.
fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((authority, None)),
    }
}

/// The user handle an authenticator stores with each of a user's passkeys.
///
/// **Derived from the username rather than stored.** It has to be the same for every passkey of a user —
/// an authenticator holds one credential per site and handle, so a second registration from the same device
/// is recognised rather than added — and deriving it means there is no column to keep in step and nothing
/// to generate before the first passkey exists. It is not a secret and not meant to be; with one operator
/// whose username is not secret either (SPEC §14.3), it identifies no one who was not already identified.
pub fn user_handle(username: &str) -> UserHandle64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_USER_HANDLE);
    hasher.update(username.as_bytes());
    let mut bytes = [0u8; USER_HANDLE_MAX_LEN];
    hasher.finalize_xof().fill(&mut bytes);
    let Ok(handle) = UserHandle64::decode(bytes);
    handle
}

/// Why a registration or a sign-in did not happen. [`Self::message`] is for the page; `Display` is for the
/// journal and carries the library's own reason.
#[derive(Debug)]
pub enum PasskeyError {
    /// The page is not on a host passkeys can be bound to.
    NotLocalhost,
    /// An authenticator would not accept this username as an account name.
    UnusableUsername,
    /// More ceremonies in progress than [`CEREMONY_CAPACITY`], none of them expired.
    Busy,
    /// The browser's response did not parse.
    Malformed(String),
    /// No ceremony with this challenge: it expired, the server restarted, or it was already used.
    Expired,
    /// The response parsed but did not verify.
    Refused(String),
    /// The ceremony was started for someone else.
    WrongUser,
    /// A sign-in with a credential id no stored passkey has — most likely one removed on the account page
    /// that the device still holds.
    UnknownPasskey,
    /// A sign-in with a passkey registered at another of this site's addresses.
    WrongSite,
}

impl PasskeyError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotLocalhost => "Passkeys need this page opened at a localhost address.",
            Self::UnusableUsername => "This username cannot be used as a passkey's account name.",
            Self::Busy => "Too many passkey prompts are open at once. Try again in a few minutes.",
            Self::Malformed(_) | Self::Refused(_) | Self::WrongUser => "The passkey could not be verified.",
            Self::Expired => "That passkey prompt expired or was already used. Try again.",
            Self::UnknownPasskey => "That passkey is not registered here. It may have been removed.",
            Self::WrongSite => "That passkey belongs to another address of this site.",
        }
    }
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed response: {detail}"),
            Self::Refused(detail) => write!(f, "verification failed: {detail}"),
            Self::WrongUser => f.write_str("the ceremony was started for another user"),
            other => f.write_str(other.message()),
        }
    }
}

/// Starts registering a passkey for `username` on the site at `rp_id`, returning the options for
/// `navigator.credentials.create` as JSON.
///
/// `existing` are the user's credential ids on this site, sent as `excludeCredentials` so an authenticator
/// that already holds one says so instead of replacing it.
pub fn start_registration(
    ceremonies: &Ceremonies,
    rp_id: &str,
    username: &str,
    existing: Vec<Vec<u8>>,
) -> Result<String, PasskeyError> {
    let rp_id = rp_id_domain(rp_id)?;
    let handle = user_handle(username);
    let entity = PublicKeyCredentialUserEntity {
        name: Username::try_from(username).map_err(|_| PasskeyError::UnusableUsername)?,
        id: &handle,
        display_name: Nickname::try_from(username).ok(),
    };
    // No transports: hints for how to reach an authenticator, and empty means "any".
    let no_transports =
        AuthTransports::decode(0).unwrap_or_else(|_| unreachable!("0 is the empty set of transports"));
    let exclude = existing
        .into_iter()
        .filter_map(|id| CredentialId::<Vec<u8>>::decode(id).ok())
        .map(|id| PublicKeyCredentialDescriptor { id, transports: no_transports })
        .collect();

    let mut options = PublicKeyCredentialCreationOptions::passkey(&rp_id, entity, exclude);
    // The library asks for the `credProtect` extension and requires it, which the phone app's authenticator
    // does not implement — so registration there would fail outright. User verification is required
    // regardless (the options say so, and verification checks the flag), which is what credProtect's
    // strictest level would have added.
    options.extensions.cred_protect = CredProtect::None;
    let (server, client) =
        options.start_ceremony().map_err(|e| PasskeyError::Refused(format!("{e:?}")))?;
    let json = serde_json::to_string(&client).map_err(|e| PasskeyError::Malformed(e.to_string()))?;

    match registrations(ceremonies).insert_or_replace_all_expired(server) {
        InsertResult::Success => Ok(json),
        _ => Err(PasskeyError::Busy),
    }
}

/// Finishes a registration: verifies the browser's `response` (the credential as WebAuthn JSON) against
/// the ceremony it answers, on the `site` it was submitted from, for `username`.
pub fn finish_registration(
    ceremonies: &Ceremonies,
    site: &Site,
    username: &str,
    response: &str,
) -> Result<NewPasskey, PasskeyError> {
    let registration = serde_json::from_str::<RegistrationRelaxed>(response)
        .map_err(|e| PasskeyError::Malformed(e.to_string()))?
        .0;
    let challenge =
        registration.challenge_relaxed().map_err(|e| PasskeyError::Malformed(e.to_string()))?;
    // Taken out before verifying, so a challenge is used once whatever the outcome.
    let ceremony = registrations(ceremonies).take(&challenge).ok_or(PasskeyError::Expired)?;

    let rp_id = rp_id_domain(&site.host)?;
    let origin = [domain_origin(site)];
    let registered = ceremony
        .verify(
            &rp_id,
            &registration,
            &RegistrationVerificationOptions::<DomainOrigin<'_, '_>, &str> {
                allowed_origins: &origin,
                ..Default::default()
            },
        )
        .map_err(|e| PasskeyError::Refused(format!("{e:?}")))?;
    if *registered.user_id() != user_handle(username) {
        return Err(PasskeyError::WrongUser);
    }

    let Ok(static_state) = registered.static_state().encode();
    let Ok(dynamic_state) = registered.dynamic_state().encode();
    Ok(NewPasskey {
        credential_id: registered.id().as_ref().to_vec(),
        rp_id: site.host.clone(),
        static_state,
        dynamic_state: dynamic_state.to_vec(),
    })
}

/// Starts a sign-in on the site at `rp_id`, returning the options for `navigator.credentials.get` as JSON.
///
/// **Discoverable**: no `allowCredentials`, so no username is asked for — the authenticator offers whichever
/// passkeys it holds for this site, and the one chosen names its user by its handle.
pub fn start_sign_in(ceremonies: &Ceremonies, rp_id: &str) -> Result<String, PasskeyError> {
    let rp_id = rp_id_domain(rp_id)?;
    let (server, client) = DiscoverableCredentialRequestOptions::passkey(&rp_id)
        .start_ceremony()
        .map_err(|e| PasskeyError::Refused(format!("{e:?}")))?;
    let json = serde_json::to_string(&client).map_err(|e| PasskeyError::Malformed(e.to_string()))?;
    match sign_ins(ceremonies).insert_or_replace_all_expired(server) {
        InsertResult::Success => Ok(json),
        _ => Err(PasskeyError::Busy),
    }
}

/// A browser's answer to a sign-in, parsed, so its credential id can be looked up before it is verified.
pub struct Assertion(DiscoverableAuthentication64);

impl Assertion {
    pub fn parse(response: &str) -> Result<Self, PasskeyError> {
        serde_json::from_str::<DiscoverableAuthenticationRelaxed64>(response)
            .map(|relaxed| Self(relaxed.0))
            .map_err(|e| PasskeyError::Malformed(e.to_string()))
    }

    pub fn credential_id(&self) -> Vec<u8> {
        self.0.raw_id().as_ref().to_vec()
    }
}

/// Finishes a sign-in: verifies `assertion` against the ceremony it answers, on the `site` it was submitted
/// from, with the stored passkey its credential id named (`None` when there is none).
///
/// Returns the passkey's new dynamic state when verification changed it, for `store::passkeys::record_use`.
///
/// **The ceremony is taken before anything is checked**, the unknown-passkey case included, so a challenge
/// answers exactly one response whatever becomes of it.
pub fn finish_sign_in(
    ceremonies: &Ceremonies,
    site: &Site,
    assertion: &Assertion,
    passkey: Option<&StoredCredential>,
) -> Result<Option<Vec<u8>>, PasskeyError> {
    let challenge =
        assertion.0.challenge_relaxed().map_err(|e| PasskeyError::Malformed(e.to_string()))?;
    let ceremony = sign_ins(ceremonies).take(&challenge).ok_or(PasskeyError::Expired)?;
    let passkey = passkey.ok_or(PasskeyError::UnknownPasskey)?;
    // Verification would refuse this too — the authenticator data carries the hash of the RP ID it signed
    // for — but saying which passkey went where is more use to someone reading the journal.
    if passkey.rp_id != site.host {
        return Err(PasskeyError::WrongSite);
    }

    let rp_id = rp_id_domain(&site.host)?;
    let unreadable = |what: &str| PasskeyError::Refused(format!("the stored {what} does not decode"));
    let handle = user_handle(&passkey.username);
    let static_state = StaticState::<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>::decode(
        passkey.static_state.as_slice(),
    )
    .map_err(|_| unreadable("public key"))?;
    let dynamic_state = <[u8; 7]>::try_from(passkey.dynamic_state.as_slice())
        .ok()
        .and_then(|bytes| DynamicState::decode(bytes).ok())
        .ok_or_else(|| unreadable("dynamic state"))?;
    let id = CredentialId::<&[u8]>::decode(passkey.credential_id.as_slice())
        .map_err(|_| unreadable("credential id"))?;
    // Checks the response's user handle against the one derived for the passkey's owner, so a passkey cannot
    // be presented under someone else's handle.
    let mut credential = AuthenticatedCredential::new(id, &handle, static_state, dynamic_state)
        .map_err(|e| PasskeyError::Refused(format!("{e:?}")))?;

    let origin = [domain_origin(site)];
    let changed = ceremony
        .verify(
            &rp_id,
            &assertion.0,
            &mut credential,
            &AuthenticationVerificationOptions::<DomainOrigin<'_, '_>, &str> {
                allowed_origins: &origin,
                ..Default::default()
            },
        )
        .map_err(|e| PasskeyError::Refused(format!("{e:?}")))?;
    let Ok(dynamic_state) = credential.dynamic_state().encode();
    Ok(changed.then(|| dynamic_state.to_vec()))
}

/// The request's own origin, as the verification options spell one.
fn domain_origin(site: &Site) -> DomainOrigin<'_, '_> {
    DomainOrigin {
        scheme: if site.scheme == "https" { Scheme::Https } else { Scheme::Other(&site.scheme) },
        host: &site.host,
        port: site.port.map_or(Port::None, Port::Val),
    }
}

fn rp_id_domain(rp_id: &str) -> Result<RpId, PasskeyError> {
    AsciiDomain::try_from(rp_id.to_owned()).map(RpId::Domain).map_err(|_| PasskeyError::NotLocalhost)
}

/// The registration set, poisoned or not: a panic mid-insert leaves it consistent, at worst a slot short.
fn registrations(
    ceremonies: &Ceremonies,
) -> std::sync::MutexGuard<'_, FixedCapHashSet<RegistrationServerState<USER_HANDLE_MAX_LEN>>> {
    ceremonies.registrations.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The sign-in set, likewise.
fn sign_ins(
    ceremonies: &Ceremonies,
) -> std::sync::MutexGuard<'_, FixedCapHashSet<DiscoverableAuthenticationServerState>> {
    ceremonies.sign_ins.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback names only, lowercased, without the port — the rule the whole design rests on.
    #[test]
    fn only_loopback_names_can_hold_a_passkey() {
        assert_eq!(rp_id_for("localhost:8080").as_deref(), Some("localhost"));
        assert_eq!(rp_id_for("localhost").as_deref(), Some("localhost"));
        assert_eq!(rp_id_for("6c4b9e.localhost:24038").as_deref(), Some("6c4b9e.localhost"));
        assert_eq!(rp_id_for("ABC.LocalHost:1").as_deref(), Some("abc.localhost"));

        // Browsers refuse WebAuthn on an IP address, and anything not loopback could be phished.
        for refused in ["127.0.0.1:8080", "[::1]:8080", "example.com", "localhost.example.com",
                        "notlocalhost", ".localhost", "localhost:http", ""] {
            assert_eq!(rp_id_for(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn an_origin_is_parsed_into_its_parts() {
        assert_eq!(
            Site::from_origin("http://abc.localhost:24038"),
            Some(Site { scheme: "http".into(), host: "abc.localhost".into(), port: Some(24038) })
        );
        assert_eq!(
            Site::from_origin("http://localhost"),
            Some(Site { scheme: "http".into(), host: "localhost".into(), port: None })
        );
        assert_eq!(Site::from_origin("http://127.0.0.1:8080"), None);
        assert_eq!(Site::from_origin("file://localhost"), None);
        assert_eq!(Site::from_origin("null"), None);
    }

    /// The same username always gets the same handle, and different ones different handles.
    #[test]
    fn a_user_handle_is_stable_and_distinct_per_user() {
        assert_eq!(user_handle("sashee"), user_handle("sashee"));
        assert_ne!(user_handle("sashee"), user_handle("other"));
    }

    /// The options a browser gets: ES256 offered (the phone app supports nothing else), no `credProtect`
    /// (it does not implement it), the RP ID the page's own host, and user verification required.
    #[test]
    fn registration_options_suit_the_phone_app() {
        let ceremonies = Ceremonies::default();
        let json = start_registration(&ceremonies, "abc.localhost", "sashee", vec![vec![7; 16]]).unwrap();
        let options: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(options["rp"]["id"], "abc.localhost");
        assert!(options["pubKeyCredParams"].as_array().unwrap().iter().any(|p| p["alg"] == -7));
        assert_eq!(options["extensions"], serde_json::json!({}));
        assert_eq!(options["authenticatorSelection"]["userVerification"], "required");
        assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(options["attestation"], "none");
        assert_eq!(options["excludeCredentials"].as_array().unwrap().len(), 1);
    }

    /// Sign-in options name the page's own host and ask for user verification, and list no credentials: the
    /// authenticator offers whichever passkey it holds for the site, and no username is typed.
    #[test]
    fn sign_in_options_are_discoverable_and_require_verification() {
        let json = start_sign_in(&Ceremonies::default(), "abc.localhost").unwrap();
        let options: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(options["rpId"], "abc.localhost");
        assert_eq!(options["userVerification"], "required");
        assert_eq!(options["allowCredentials"], serde_json::json!([]));
    }

    #[test]
    fn a_response_with_no_ceremony_behind_it_is_refused() {
        let site = Site { scheme: "http".into(), host: "localhost".into(), port: None };
        let err = finish_registration(&Ceremonies::default(), &site, "sashee", "{}").unwrap_err();
        assert!(matches!(err, PasskeyError::Malformed(_)), "{err}");
    }
}
