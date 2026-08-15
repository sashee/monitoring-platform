//! Scaffolding shared by the integration tests.

use monitoring_platform::auth::{TOKEN_BYTES, Token};
use monitoring_platform::store;
use std::path::Path;

/// Opens (and migrates) the database at `db`, issues one API key, and returns the `Authorization`
/// header value for it.
///
/// Every integration test that drives the API needs this: authentication is unconditional, so a
/// harness presenting no key would be testing the 401 path and nothing else. The refusal paths are
/// covered deliberately in `tests/auth.rs` instead.
///
/// The token comes from fixed bytes rather than randomness — each test gets its own temporary
/// database, so there is nothing to collide with, and a failure prints the same id every run.
pub fn issue_key(db: &Path) -> String {
    let conn = store::open_write(db).expect("opening the database to issue a test key");
    let token = Token::from_random(&[0x5a; TOKEN_BYTES]);

    store::keys::insert(&conn, token.id(), &token.secret_hash(), "integration-test", 0)
        .expect("storing the test key");

    format!("Bearer {}", token.to_secret_string())
}
