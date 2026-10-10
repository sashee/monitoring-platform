//! Wiring, signals and shutdown ordering.

use anyhow::{Context, Result};
use clap::Parser;
use monitoring_platform::config::{
    ApiKeyArgs, Cli, Command, CreateApiKeyArgs, CreateUserArgs, DeleteUserArgs, ServeArgs,
};
use monitoring_platform::{
    AppState, Config, api, auth, clock, now_unix_nanos, store, transport, web,
};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => {
            init_tracing(&args.log_level);
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building tokio runtime")?
                .block_on(serve(args))
        }
        // No tokio runtime: the gate is a synchronous poll loop with nothing to overlap, and it
        // runs as ExecStartPre in a separate process from the server.
        Command::WaitForClock(args) => {
            init_tracing(&args.log_level);
            clock::wait_until_synchronized(&args.settings())
        }
        // Nor here: both key commands are one SQLite transaction and some printing.
        Command::CreateApiKey(args) => {
            init_tracing_on_stderr(&args.common.log_level);
            create_api_key(&args)
        }
        // The §14 commands, all one SQLite transaction and some printing, so no runtime here either.
        Command::CreateUser(args) => {
            init_tracing_on_stderr(&args.common.log_level);
            create_user(&args)
        }
        Command::CreateLoginToken(args) => {
            init_tracing_on_stderr(&args.common.log_level);
            create_login_token(&args)
        }
        Command::ListUsers(args) => {
            init_tracing_on_stderr(&args.log_level);
            list_users(&args)
        }
        Command::ListSessions(args) => {
            init_tracing_on_stderr(&args.log_level);
            list_sessions(&args)
        }
        Command::DeleteUser(args) => {
            init_tracing_on_stderr(&args.common.log_level);
            delete_user(&args)
        }
    }
}

/// Issues a key and prints the token once.
///
/// `open_write` rather than `open_read` because it also migrates: on a receiver upgraded but not yet
/// restarted, this is what creates the table. Running it against a live server is safe — WAL admits a
/// second writer, and `busy_timeout` covers the overlap.
fn create_api_key(args: &CreateApiKeyArgs) -> Result<()> {
    let path = args.common.database_path();

    // A mistyped `--db` would otherwise create a second database, store the key in it, and report
    // success — leaving a key the receiver has never heard of. Creating one is legitimate (the first
    // key may predate the first start), so this warns rather than refuses, and the resolved path is
    // printed either way.
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "no database there yet; creating one. If the receiver already has a database, \
             check --db or STATE_DIRECTORY — a key stored here would be invisible to it"
        );
    }

    let conn = store::open_write(&path)?;

    let token = auth::Token::from_random(&monitoring_platform::random_bytes()?);
    store::keys::insert(
        &conn,
        token.id(),
        &token.secret_hash(),
        &args.label,
        now_unix_nanos(),
    )?;

    // stdout, and nothing else on it: this is the command's output, and it is the only time the
    // token exists anywhere. A `tracing` line would put a credential wherever the journal goes.
    println!("{}", token.to_secret_string());

    // stderr, so redirecting stdout to a file captures the token alone.
    eprintln!(
        "stored key {} for {:?} in {}; the token above cannot be recovered",
        token.id(),
        args.label,
        path.display()
    );
    Ok(())
}


/// Creates a web interface user (SPEC §14), and prints a sign-in token for them.
///
/// `open_write` rather than `open_read` for the same reason `create_api_key` uses it: on a receiver upgraded
/// but not yet restarted, this is what applies the migrations that create the tables.
fn create_user(args: &CreateUserArgs) -> Result<()> {
    let path = args.common.database_path();

    // Same warning, and same reasoning, as create-api-key: a mistyped `--db` would otherwise create a
    // second database, store the user in it, and report success — leaving a login the receiver has never
    // heard of.
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "no database there yet; creating one. If the receiver already has a database, \
             check --db or STATE_DIRECTORY — a user stored here would be invisible to it"
        );
    }

    let conn = store::open_write(&path)?;
    let now = now_unix_nanos();
    store::users::insert(&conn, &args.username, now)?;
    eprintln!("stored user {:?} in {}", args.username, path.display());

    print_login_token(&conn, &args.username, now, &path)
}

/// Issues a sign-in token for an existing user (SPEC §14.7): the way in on a device with no passkey.
///
/// Refuses a `--db` with no file behind it rather than create an empty database and report that the user is
/// not in it. `open_write` once it exists, not `open_write_existing`: on a receiver upgraded but not yet
/// restarted, the table the token goes in is created by the migration this applies.
fn create_login_token(args: &CreateUserArgs) -> Result<()> {
    let path = args.common.database_path();
    if !path.exists() {
        anyhow::bail!("no database at {}; check --db or STATE_DIRECTORY", path.display());
    }
    let conn = store::open_write(&path)?;
    print_login_token(&conn, &args.username, now_unix_nanos(), &path)
}

/// Issues a token for `username` and prints it — to stdout, and nothing else there, as `create-api-key`
/// prints a key: this is the only time it exists anywhere, and a `tracing` line would put it wherever the
/// journal goes.
fn print_login_token(
    conn: &rusqlite::Connection,
    username: &str,
    now: i64,
    path: &std::path::Path,
) -> Result<()> {
    let Some(issued) = web::login_token::issue(conn, username, now)? else {
        anyhow::bail!("no user {username:?} in {}", path.display());
    };
    println!("{}", issued.token.to_secret_string());
    // stderr, so redirecting stdout to a file captures the token alone.
    eprintln!(
        "the sign-in token above signs {username:?} in once, until {}; paste it into the login page",
        api::query::format_nanos(issued.expires_at)
    );
    Ok(())
}

fn list_users(args: &ApiKeyArgs) -> Result<()> {
    let conn = store::open_read(&args.database_path())?;
    let passkeys = store::passkeys::counts(&conn)?;
    let tokens = store::login_tokens::list(&conn)?;
    let now = now_unix_nanos();
    for user in store::users::list(&conn)? {
        // How each user signs in, so a recovery starts by seeing who has no passkey.
        let passkeys = passkeys.get(&user.username).copied().unwrap_or(0);
        let token = tokens
            .iter()
            .find(|t| t.username == user.username && t.is_live(now))
            .map(|t| format!(", a sign-in token until {}", api::query::format_nanos(t.expires_at)))
            .unwrap_or_default();
        println!(
            "{}  {}  {passkeys} passkey{}{token}",
            api::query::format_nanos(user.created_at),
            user.username,
            if passkeys == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

fn list_sessions(args: &ApiKeyArgs) -> Result<()> {
    let conn = store::open_read(&args.database_path())?;
    let now = now_unix_nanos();
    for session in store::sessions::list(&conn)? {
        // Marked rather than filtered out: an expired session is inert but still on disk until the next
        // login sweeps it, and a listing that hid them would make the table look empty when it is not.
        let state = if session.expires_at <= now { "expired" } else { "live" };
        println!(
            "{}  {}  {}  expires {}  {}",
            session.id,
            api::query::format_nanos(session.created_at),
            session.username,
            api::query::format_nanos(session.expires_at),
            state
        );
    }
    Ok(())
}

fn delete_user(args: &DeleteUserArgs) -> Result<()> {
    let path = args.common.database_path();
    let conn = store::open_write(&path)?;

    // Reported rather than an error: `delete-user` on a name that is already gone has achieved what was
    // asked, and failing would make the command awkward to re-run.
    if store::users::delete(&conn, &args.username)? {
        eprintln!("deleted user {:?} and their sessions from {}", args.username, path.display());
    } else {
        eprintln!("no user {:?} in {}", args.username, path.display());
    }
    Ok(())
}

fn env_filter(filter: &str) -> EnvFilter {
    EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"))
}

fn init_tracing(filter: &str) {
    tracing_subscriber::fmt().with_env_filter(env_filter(filter)).with_target(false).init();
}

/// Logs on stderr, for the commands whose stdout is *data*.
///
/// Without this, `TOKEN=$(monitoring-platform create-api-key …)` captures the migration lines along
/// with the token. `serve` keeps the default: under systemd both streams land in the journal, so
/// moving it there would change nothing and is not worth the divergence.
fn init_tracing_on_stderr(filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(env_filter(filter))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

async fn serve(args: ServeArgs) -> Result<()> {
    let config = Config::from_env(&args);
    tracing::info!(
        socket = %config.socket_path.display(),
        database = %config.database_path.display(),
        "starting"
    );

    // Migrations run before the socket is bound, so a schema failure is a clean startup failure
    // rather than a service that accepts requests it cannot store. A migration may take longer than
    // the unit's start timeout, so it extends that timeout for itself first (SPEC §9.2).
    let conn = store::schema::open_write_with(&config.database_path, extend_start_timeout)?;

    // Nothing between the migration and the writer: the invariant the read path's inner join needs is
    // enforced by the schema (`series_id NOT NULL` with a foreign key, SPEC §6.7), not repaired at
    // startup. 3.2 and 3.3 ran a convergence sweep here instead, which cost ~42 s on the first start.

    // Loud, but not fatal. Refusing to start would take `/healthz` down with it — the one endpoint
    // that needs no key and that a readiness probe depends on — and turn a recoverable state into a
    // restart loop with nothing to read. An error line names the fix instead.
    match store::keys::count(&conn) {
        Ok(0) => tracing::error!(
            "no API keys exist, and every endpoint except /healthz requires one: this receiver will \
             refuse everything. Issue one with `monitoring-platform create-api-key --db {} --label \
             <name>`",
            config.database_path.display()
        ),
        Ok(keys) => tracing::info!(keys, "API keys loaded"),
        Err(e) => tracing::warn!(error = %e, "could not count the API keys"),
    }

    // Sessions issued under a longer lifetime than this binary's — the thirty days before passkeys — are cut
    // to it, so a shorter lifetime holds from this start on (SPEC §14.2). Not fatal, like the key count: if it
    // fails, those sessions simply last until their own expiry.
    match store::sessions::cap_lifetimes(&conn, monitoring_platform::web::session::TTL_NANOS) {
        Ok(0) => {}
        Ok(capped) => tracing::info!(capped, "shortened sessions to the current lifetime"),
        Err(e) => tracing::warn!(error = %e, "could not shorten older sessions"),
    }

    let (writer, writer_done) = store::write::spawn(conn);

    let listener = transport::uds::bind(&config.socket_path)?;
    let socket_path = config.socket_path.clone();

    let app = api::app(AppState::new(config, writer.clone()));

    // Only now is the service genuinely ready: schema current, socket accepting. Telling systemd
    // any earlier would let a dependent unit race our bind() (SPEC §9.2).
    // `notify` returns Ok(()) when NOTIFY_SOCKET is unset, so this is inert outside systemd —
    // no branch needed for development runs or tests. The empty STATUS= clears a migration's status
    // line, which `systemctl status` would otherwise go on showing after the migration had finished.
    if let Err(e) = sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status(""),
    ]) {
        tracing::warn!(error = %e, "failed to send readiness notification to systemd");
    }
    tracing::info!("ready");

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving");

    // Ordering matters: dropping every Writer closes the channel, which ends the writer loop and
    // checkpoints WAL. Awaiting it before unlinking means a committed batch is never lost to exit.
    tracing::info!("draining storage writer");
    drop(writer);
    if let Err(e) = writer_done.await {
        tracing::warn!(error = %e, "writer task did not shut down cleanly");
    }
    transport::uds::cleanup(&socket_path);
    tracing::info!("stopped");

    result
}

/// How long a schema migration may hold up startup (SPEC §9.2). Generous on purpose: what this bounds is
/// a migration that has stalled, and the alternative to waiting is a kill that rolls the work back and
/// starts it over.
const MIGRATION_START_BUDGET: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Gives a pending migration [`MIGRATION_START_BUDGET`] on top of systemd's start timeout, and says why
/// in `systemctl status`. Sent once: an extension moves the deadline to now plus the budget, so nothing
/// has to keep it alive.
fn extend_start_timeout(from: store::schema::Version, to: store::schema::Version) {
    let status = format!("applying schema migration from {from} to {to}");
    let extend = extend_timeout_usec(MIGRATION_START_BUDGET);
    if let Err(e) = sd_notify::notify(&[
        sd_notify::NotifyState::Status(&status),
        sd_notify::NotifyState::Custom(&extend),
    ]) {
        tracing::warn!(error = %e, "failed to extend the systemd start timeout for the migration");
    }
}

/// Written by hand rather than with `NotifyState::ExtendTimeoutUsec`, which takes a `u32` and so tops out
/// at about 71 minutes. systemd parses the value as 64-bit.
fn extend_timeout_usec(budget: std::time::Duration) -> String {
    format!("EXTEND_TIMEOUT_USEC={}", budget.as_micros())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen for SIGTERM");
            return;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received; shutting down"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received; shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget does not fit the `u32` sd-notify's own variant would have taken, which is the reason the
    /// message is written by hand.
    #[test]
    fn the_migration_budget_is_sent_whole() {
        assert_eq!(extend_timeout_usec(MIGRATION_START_BUDGET), "EXTEND_TIMEOUT_USEC=21600000000");
        assert!(MIGRATION_START_BUDGET.as_micros() > u128::from(u32::MAX));
    }
}
