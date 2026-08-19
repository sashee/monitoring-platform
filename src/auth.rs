//! Credential identity: the tokens handed out, the passwords accepted, and the hashes the database
//! keeps (SPEC §13, §14).
//!
//! Pure — no I/O, and no randomness either: [`Token::from_random`] and [`SessionToken::from_random`]
//! take the bytes rather than sourcing them, so every property here is testable against a fixed value.
//! The randomness itself is [`crate::random_bytes`].
//!
//! Three credentials live here, because they are three answers to one question — *what proves who you
//! are* — and keeping them together is what keeps their domains provably distinct:
//!
//! | | presented as | looked up by | stored |
//! |---|---|---|---|
//! | API key (§13) | `Authorization: Bearer mpk_…` | its public id | `blake3(api-key domain ‖ secret)` |
//! | session (§14) | the `mp_session` cookie | its public id | `blake3(session domain ‖ secret)` |
//! | password (§14) | a login form field | the username | `blake3(password domain ‖ password)` |
//!
//! A token has two halves with different jobs:
//!
//! - **id** — public. It is what a request is looked up by, so an unknown id costs one index probe
//!   and no hashing at all. Stored verbatim.
//! - **secret** — never stored. Only `blake3(domain || secret)` is, so a stolen database yields
//!   nothing a client could authenticate with.
//!
//! **Why a plain hash rather than argon2, scrypt or bcrypt.** Those exist to make guessing
//! *low-entropy human* passwords expensive. A secret here is 32 bytes straight from the kernel's
//! CSPRNG — 2^256 of them — so an attacker holding the hash cannot search the space at any hash
//! speed, and a deliberately slow verification would only tax the receiver, which runs on the same
//! class of hardware as the devices it collects from. What a fast hash does still need is domain
//! separation, and that is here.
//!
//! **That argument covers the password too, but only because of how the password is chosen.** It is
//! one operator's own high-entropy secret, not a human-memorable string, so there is no small space to
//! search and nothing for a slow KDF to buy (SPEC §14). The moment a second user picks a password they
//! can remember, that stops being true and [`hash_password`] is where argon2 belongs — which is why
//! this is written down rather than left as an inherited assumption.

use blake3::Hash;

/// Marks a token as one of ours wherever it turns up — a log, a config file, a paste. Secret
/// scanners key off exactly this kind of fixed prefix.
pub const PREFIX: &str = "mpk_";

/// The session cookie's counterpart to [`PREFIX`].
///
/// A *different* prefix, not a reuse of `mpk_`, for two reasons that both matter: a secret scanner
/// should be able to tell which kind of credential leaked, and a session value that looked like an API
/// key would invite exactly the confusion §14's separate auth layers exist to prevent.
pub const SESSION_PREFIX: &str = "mps_";

pub const ID_BYTES: usize = 8;
/// 256 bits, which is what makes hashing it with a fast hash sound (see the module docs).
pub const SECRET_BYTES: usize = 32;
/// Randomness one token needs.
pub const TOKEN_BYTES: usize = ID_BYTES + SECRET_BYTES;

/// Prefixed to the secret before hashing, so these hashes can never be confused with the
/// measurement content ids in [`crate::content_id`], which use the same function.
///
/// **The value is frozen.** Changing this string invalidates every API key ever issued, since only the
/// hash is stored and it cannot be recomputed from anything. The Rust name was changed when the
/// session and password domains arrived; the bytes were not.
const DOMAIN_API_KEY: &[u8] = b"monitoring-platform/api-key/v1";

/// The session equivalent of [`DOMAIN_API_KEY`], and frozen for the same reason — though the cost of
/// changing it is only that everyone is logged out, not that a device stops delivering.
///
/// Distinct from the API key domain so that the same 32 bytes presented as a cookie and as a bearer
/// token hash differently. Without that, one stored hash would authenticate on either surface, and
/// §14's separation of the two auth layers would hold in the router while leaking through the database.
const DOMAIN_SESSION: &[u8] = b"monitoring-platform/session/v1";

/// The password domain (SPEC §14). Changing it invalidates every stored password, which then have to
/// be re-set with `create-user`.
const DOMAIN_PASSWORD: &[u8] = b"monitoring-platform/password/v1";

/// A token as a client presents it.
#[derive(Clone)]
pub struct Token {
    id: String,
    secret: [u8; SECRET_BYTES],
}

impl std::fmt::Debug for Token {
    /// Redacted, deliberately. A `Token` reaching a log line through a `{:?}` on some struct that
    /// happens to contain it is precisely how a credential leaks, so it must not be printable by
    /// accident. [`Token::to_secret_string`] is the one way out, and it has to be called by name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token {{ id: {:?}, secret: <redacted> }}", self.id)
    }
}

impl Token {
    /// Splits `TOKEN_BYTES` of randomness into the two halves.
    pub fn from_random(bytes: &[u8; TOKEN_BYTES]) -> Self {
        let (id, secret) = bytes.split_at(ID_BYTES);
        Self {
            id: hex(id),
            secret: secret.try_into().expect("TOKEN_BYTES - ID_BYTES == SECRET_BYTES"),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// What the database stores.
    pub fn secret_hash(&self) -> Hash {
        hash_secret(&self.secret)
    }

    /// The single string a client is configured with.
    ///
    /// Printed once, when the key is created, and not recoverable afterwards — which is the point of
    /// storing only the hash, and the reason this is a named method rather than `Display`.
    pub fn to_secret_string(&self) -> String {
        format!("{PREFIX}{}.{}", self.id, hex(&self.secret))
    }
}

/// A browser session, as the `mp_session` cookie carries it (SPEC §14).
///
/// The same two-half shape as [`Token`] and for the same reasons, so the session table can mirror
/// `api_key` exactly: a cookie naming an id nobody issued is refused after one index probe, and only
/// the hash of the secret half is stored.
///
/// A separate type rather than a reused [`Token`] because the two must not be interchangeable. They
/// carry different prefixes, hash into different domains, and are checked by different middleware; a
/// single type would make passing one where the other belongs a compile-time possibility, and the
/// separation in §14 is worth more than the forty lines saved.
#[derive(Clone)]
pub struct SessionToken {
    id: String,
    secret: [u8; SECRET_BYTES],
}

impl std::fmt::Debug for SessionToken {
    /// Redacted, for the reason spelled out on [`Token`]'s impl: a credential must not be printable by
    /// accident. Here the accident is more likely, not less — a session is handled per request, so it
    /// passes through more code than a key ever does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken {{ id: {:?}, secret: <redacted> }}", self.id)
    }
}

impl SessionToken {
    pub fn from_random(bytes: &[u8; TOKEN_BYTES]) -> Self {
        let (id, secret) = bytes.split_at(ID_BYTES);
        Self {
            id: hex(id),
            secret: secret.try_into().expect("TOKEN_BYTES - ID_BYTES == SECRET_BYTES"),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// What `web_session.secret_hash` stores.
    pub fn secret_hash(&self) -> Hash {
        hash_session_secret(&self.secret)
    }

    /// The cookie value. Named for what it is, like [`Token::to_secret_string`], so it cannot be
    /// reached by a stray `{}` or `{:?}`.
    pub fn to_secret_string(&self) -> String {
        format!("{SESSION_PREFIX}{}.{}", self.id, hex(&self.secret))
    }
}

/// A session token out of a cookie value.
///
/// Rejects an API key outright, rather than parsing it and failing to find the id in `web_session`: the
/// prefixes are what distinguish the two credentials, so a mismatch is a malformed session and should
/// say so.
pub fn parse_session(raw: &str) -> Result<SessionToken, Malformed> {
    let body = raw.strip_prefix(SESSION_PREFIX).ok_or(Malformed::MissingPrefix)?;
    let (id, secret) = body.split_once('.').ok_or(Malformed::NotTwoParts)?;

    unhex::<ID_BYTES>(id).ok_or(Malformed::BadId)?;
    let secret = unhex::<SECRET_BYTES>(secret).ok_or(Malformed::BadSecret)?;

    Ok(SessionToken { id: id.to_owned(), secret })
}

/// Why a token string was not usable.
///
/// Carries no part of the input. An error that echoes a credential back into a log would defeat the
/// point of never storing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The header is there but its bytes are not text, so nothing can be parsed out of it. Distinct
    /// from an absent header: a client that sent something unreadable has a different problem from
    /// one that sent nothing, and the log has to be able to say which.
    NotText,
    /// Not an `Authorization: Bearer …` header.
    NotBearer,
    MissingPrefix,
    /// No `.` separating the two halves.
    NotTwoParts,
    BadId,
    BadSecret,
}

impl Malformed {
    /// Safe to log and safe to return to the client: it describes the shape, never the value.
    ///
    /// Shared by API keys and sessions, so the two shape messages name no particular credential —
    /// `MissingPrefix` is what a session cookie carrying `mpk_` produces, and saying "an API key starts
    /// with `mpk_`" about it would be actively misleading in the log. Which surface it was is the
    /// caller's to say, and both do.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotText => "the Authorization header is not valid text",
            Self::NotBearer => "expected an `Authorization: Bearer <token>` header",
            Self::MissingPrefix => "the token does not start with the prefix for its kind",
            Self::NotTwoParts => "a token is an id and a secret separated by `.`",
            Self::BadId => "the id half is not 16 lowercase hex digits",
            Self::BadSecret => "the secret half is not 64 lowercase hex digits",
        }
    }
}

/// The token out of an `Authorization` header value.
pub fn from_authorization(value: &str) -> Result<Token, Malformed> {
    let (scheme, rest) = value.split_once(' ').ok_or(Malformed::NotBearer)?;
    // RFC 7235 makes the scheme case-insensitive, and clients do vary.
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Malformed::NotBearer);
    }
    parse(rest.trim())
}

/// A bare token, without the header scheme.
pub fn parse(raw: &str) -> Result<Token, Malformed> {
    let body = raw.strip_prefix(PREFIX).ok_or(Malformed::MissingPrefix)?;
    let (id, secret) = body.split_once('.').ok_or(Malformed::NotTwoParts)?;

    // The id is validated as hex but kept as the string, since that is what the table is keyed by.
    unhex::<ID_BYTES>(id).ok_or(Malformed::BadId)?;
    let secret = unhex::<SECRET_BYTES>(secret).ok_or(Malformed::BadSecret)?;

    Ok(Token { id: id.to_owned(), secret })
}

pub fn hash_secret(secret: &[u8]) -> Hash {
    hash_in_domain(DOMAIN_API_KEY, secret)
}

/// What `web_session.secret_hash` stores (SPEC §14).
pub fn hash_session_secret(secret: &[u8]) -> Hash {
    hash_in_domain(DOMAIN_SESSION, secret)
}

/// What `web_user.password_hash` stores (SPEC §14).
///
/// Takes the password as `&str` rather than `&[u8]`: it arrives as text from a form field or a
/// terminal, and hashing the UTF-8 bytes of exactly what was typed is the only rule that makes a
/// password reproducible. No normalization, no trimming — a trailing space is part of the secret, and a
/// hash that silently disagreed with what the operator entered would be unrecoverable.
pub fn hash_password(password: &str) -> Hash {
    hash_in_domain(DOMAIN_PASSWORD, password.as_bytes())
}

/// The one place a domain is prefixed, so no caller can hash into the wrong one by writing the
/// two-line `Hasher` dance out again slightly differently.
fn hash_in_domain(domain: &[u8], secret: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(secret);
    hasher.finalize()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (nibble(bytes[i * 2])? << 4) | nibble(bytes[i * 2 + 1])?;
    }
    Some(out)
}

/// Lowercase only, and no sign or whitespace either — which is why this is here rather than
/// `u8::from_str_radix`, which accepts `+f` and `F` alike. One secret with two spellings would be
/// one secret with two hashes, only one of which is stored.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed bytes, so every expectation below is a literal rather than a re-derivation of the code
    /// under test. The id half counts up from `00`; the secret half counts up from `80`, so the two
    /// cannot be mistaken for each other in a failure message.
    fn bytes() -> [u8; TOKEN_BYTES] {
        let mut bytes = [0u8; TOKEN_BYTES];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = if i < ID_BYTES { i as u8 } else { 0x80 + (i - ID_BYTES) as u8 };
        }
        bytes
    }

    fn token() -> Token {
        Token::from_random(&bytes())
    }

    #[test]
    fn a_token_round_trips_through_its_string_form() {
        let printed = token().to_secret_string();
        let parsed = parse(&printed).expect("the printed form must parse");

        assert_eq!(parsed.id(), token().id());
        assert_eq!(parsed.secret_hash(), token().secret_hash());
    }

    #[test]
    fn the_id_is_the_first_eight_bytes_in_lowercase_hex() {
        assert_eq!(token().id(), "0001020304050607");
        assert!(token().to_secret_string().starts_with("mpk_0001020304050607."));
    }

    #[test]
    fn the_printed_form_has_the_documented_shape() {
        let printed = token().to_secret_string();
        let body = printed.strip_prefix(PREFIX).expect("prefix");
        let (id, secret) = body.split_once('.').expect("two parts");
        assert_eq!(id.len(), ID_BYTES * 2);
        assert_eq!(secret.len(), SECRET_BYTES * 2);
    }

    /// The whole reason only a hash is stored: nothing that gets logged may contain the secret.
    #[test]
    fn debug_redacts_the_secret() {
        let rendered = format!("{:?}", token());
        assert!(rendered.contains("0001020304050607"), "the id is not secret: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("808182"),
            "the secret must never be printable by accident: {rendered}"
        );
    }

    #[test]
    fn a_bearer_header_is_accepted_whatever_the_scheme_case() {
        let printed = token().to_secret_string();
        for header in [
            format!("Bearer {printed}"),
            format!("bearer {printed}"),
            format!("BEARER {printed}"),
        ] {
            assert_eq!(
                from_authorization(&header).expect(&header).id(),
                token().id(),
                "failed on {header:?}"
            );
        }
    }

    #[test]
    fn a_non_bearer_header_is_refused() {
        let printed = token().to_secret_string();
        assert_eq!(from_authorization(&printed).unwrap_err(), Malformed::NotBearer, "no scheme");
        assert_eq!(
            from_authorization(&format!("Basic {printed}")).unwrap_err(),
            Malformed::NotBearer
        );
    }

    #[test]
    fn each_way_a_token_can_be_malformed_is_named() {
        let cases = [
            ("0001020304050607.88", Malformed::MissingPrefix),
            ("mpk_0001020304050607", Malformed::NotTwoParts),
            ("mpk_00010203.0102", Malformed::BadId),
            ("mpk_00010203040506070809.0102", Malformed::BadId),
            ("mpk_0001020304050607.0102", Malformed::BadSecret),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse(raw).unwrap_err(), expected, "on {raw:?}");
        }
    }

    /// Uppercase hex is refused rather than accepted and lowercased: one secret with two spellings
    /// would hash two ways, and only one of the two is in the database.
    #[test]
    fn uppercase_hex_is_not_the_same_token() {
        let printed = token().to_secret_string();
        assert!(parse(&printed.to_uppercase()).is_err());
        // Only the secret half uppercased, so the id still resolves and the *secret* is what differs.
        assert_eq!(
            parse(&printed.replace("8b8c8d", "8B8C8D")).unwrap_err(),
            Malformed::BadSecret
        );
    }

    /// `u8::from_str_radix` would accept these; the strict nibble parser is why they are refused.
    #[test]
    fn signs_and_spaces_are_not_hex() {
        assert!(parse("mpk_+0010203040506 7.0102").is_err());
        assert!(parse("mpk_ 001020304050607.0102").is_err());
    }

    #[test]
    fn the_hash_is_domain_separated_from_a_bare_blake3() {
        assert_ne!(hash_secret(b"secret"), blake3::hash(b"secret"));
        assert_eq!(hash_secret(b"secret"), hash_secret(b"secret"), "and it is deterministic");
        assert_ne!(hash_secret(b"secret"), hash_secret(b"secrez"));
    }

    /// The three domains must not collide, and this is the test that says so.
    ///
    /// Without it, one stored hash could authenticate on more than one surface: the same 32 bytes presented
    /// as a bearer token and as a session cookie would match the same row, and §14's separation of the two
    /// auth layers would hold in the router while leaking through the database.
    #[test]
    fn the_three_credential_domains_are_mutually_distinct() {
        let secret = b"the same bytes in every domain";

        let api_key = hash_secret(secret);
        let session = hash_session_secret(secret);
        let password = hash_password(std::str::from_utf8(secret).unwrap());

        assert_ne!(api_key, session, "an api key hash must not match a session hash");
        assert_ne!(api_key, password);
        assert_ne!(session, password);
        for hash in [api_key, session, password] {
            assert_ne!(hash, blake3::hash(secret), "none may be a bare blake3");
        }
    }

    /// A password is hashed as exactly the bytes typed. No trimming, no normalization — a hash that
    /// disagreed with what the operator entered would be unrecoverable, since only the hash is stored.
    #[test]
    fn a_password_is_hashed_verbatim() {
        assert_eq!(hash_password("hunter2"), hash_password("hunter2"), "deterministic");
        assert_ne!(hash_password("hunter2"), hash_password("hunter2 "), "a trailing space counts");
        assert_ne!(hash_password("hunter2"), hash_password(" hunter2"));
        assert_ne!(hash_password("hunter2"), hash_password("Hunter2"), "and case counts");
    }

    // ------------------------------------------------------------------------------- session tokens

    fn session() -> SessionToken {
        SessionToken::from_random(&bytes())
    }

    #[test]
    fn a_session_token_round_trips_through_its_cookie_form() {
        let printed = session().to_secret_string();
        let parsed = parse_session(&printed).expect("the printed form must parse");

        assert_eq!(parsed.id(), session().id());
        assert_eq!(parsed.secret_hash(), session().secret_hash());
    }

    #[test]
    fn a_session_token_is_prefixed_as_a_session() {
        assert!(session().to_secret_string().starts_with("mps_"));
        assert_eq!(session().id(), "0001020304050607", "the id half is derived the same way");
    }

    /// The prefixes are what tell the two credentials apart, so each parser must refuse the other's token
    /// outright rather than accept it and fail to find the id in its own table.
    #[test]
    fn an_api_key_and_a_session_are_not_interchangeable() {
        let key = token().to_secret_string();
        let cookie = session().to_secret_string();

        assert_eq!(parse_session(&key).unwrap_err(), Malformed::MissingPrefix);
        assert_eq!(parse(&cookie).unwrap_err(), Malformed::MissingPrefix);
    }

    /// Even though both halves come from the same bytes here, the stored hashes differ — which is the
    /// database-level half of keeping the two credentials separate.
    #[test]
    fn the_same_bytes_hash_differently_as_a_key_and_as_a_session() {
        assert_eq!(token().id(), session().id(), "precondition: the same source bytes");
        assert_ne!(token().secret_hash(), session().secret_hash());
    }

    #[test]
    fn session_debug_redacts_the_secret() {
        let rendered = format!("{:?}", session());
        assert!(rendered.contains("0001020304050607"), "the id is not secret: {rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("808182"), "{rendered}");
    }

    #[test]
    fn each_way_a_session_cookie_can_be_malformed_is_named() {
        let cases = [
            ("0001020304050607.88", Malformed::MissingPrefix),
            ("", Malformed::MissingPrefix),
            ("mps_0001020304050607", Malformed::NotTwoParts),
            ("mps_00010203.0102", Malformed::BadId),
            ("mps_0001020304050607.0102", Malformed::BadSecret),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse_session(raw).unwrap_err(), expected, "on {raw:?}");
        }
    }

    /// The two halves come from disjoint randomness, which is worth pinning in both directions: a
    /// public id that moved with the secret would leak information about it, and a secret that moved
    /// with the id would make the public half load-bearing.
    #[test]
    fn the_two_halves_come_from_disjoint_randomness() {
        let mut differing_id = bytes();
        differing_id[0] ^= 0xff;
        let differing_id = Token::from_random(&differing_id);

        let mut differing_secret = bytes();
        differing_secret[ID_BYTES] ^= 0xff;
        let differing_secret = Token::from_random(&differing_secret);

        assert_ne!(differing_id.id(), token().id(), "a new id must not collide");
        assert_eq!(
            differing_id.secret_hash(),
            token().secret_hash(),
            "the id must not feed the secret's hash"
        );

        assert_eq!(differing_secret.id(), token().id());
        assert_ne!(differing_secret.secret_hash(), token().secret_hash());
    }
}
