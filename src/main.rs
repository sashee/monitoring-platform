//! Wiring, signals and shutdown ordering.

use anyhow::{Context, Result};
use clap::Parser;
use monitoring_platform::config::{
    ApiKeyArgs, Cli, Command, CreateApiKeyArgs, CreateUserArgs, DeleteUserArgs, ServeArgs,
};
use monitoring_platform::{
    AppState, Config, api, auth, clock, now_unix_nanos, store, transport,
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


/// Creates a web interface user (SPEC §14).
///
/// `open_write` rather than `open_read` for the same reason `create_api_key` uses it: on a receiver upgraded
/// but not yet restarted, this is what applies the 3.1 migration that creates the table.
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

    let password = read_password()?;

    let conn = store::open_write(&path)?;
    store::users::insert(&conn, &args.username, &auth::hash_password(&password), now_unix_nanos())?;

    // stderr, not stdout: unlike a token, there is nothing here worth capturing into a variable, and the
    // command's whole output being diagnostic keeps it consistent with the key commands' split.
    eprintln!("stored user {:?} in {}", args.username, path.display());
    Ok(())
}

/// The password, from stdin.
///
/// **Never from argv**, for the reason on `Command::CreateUser`. Not from an environment variable either:
/// `/proc/<pid>/environ` is readable by the same processes, and an exported variable outlives the command.
///
/// No terminal echo suppression, deliberately: that needs `termios` handling — a raw-mode dance with a
/// restore-on-signal path to avoid leaving the operator's shell echo-less after a Ctrl-C — for a command run
/// once per host. Piping is the documented usage precisely so the password need not be typed where it can be
/// seen:
///
/// ```sh
/// printf %s "$PASSWORD" | monitoring-platform create-user --username sashee
/// ```
///
/// The prompt goes to stderr so it is visible even when stdout is redirected.
fn read_password() -> Result<String> {
    use std::io::{BufRead, IsTerminal};

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("password (will be visible as you type): ");
    }

    let mut password = String::new();
    stdin.lock().read_line(&mut password).context("reading the password from stdin")?;
    if stdin.is_terminal() {
        eprintln!();
    }

    // Only the line ending is stripped, and only from the end. A password may legitimately begin or end with
    // a space, and `trim()` would quietly store something other than what was supplied — unrecoverably, since
    // only the hash is kept.
    let password = password.strip_suffix('\n').unwrap_or(&password);
    let password = password.strip_suffix('\r').unwrap_or(password);

    if password.is_empty() {
        anyhow::bail!(
            "the password was empty. Pipe one in, e.g. \
             `printf %s \"$PASSWORD\" | monitoring-platform create-user --username <name>`"
        );
    }
    Ok(password.to_owned())
}

fn list_users(args: &ApiKeyArgs) -> Result<()> {
    let conn = store::open_read(&args.database_path())?;
    for user in store::users::list(&conn)? {
        println!("{}  {}", api::query::format_nanos(user.created_at), user.username);
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
    // rather than a service that accepts requests it cannot store.
    let mut conn = store::open_write(&config.database_path)?;

    // Every startup, not once (SPEC §6.7). A revert to a 3.1 binary — routine here, since
    // `system.autoUpgrade` runs nightly — writes measurements with no `series_id`, so the fill has to
    // be a convergence sweep rather than a migration step. Idempotent: with nothing to do it is a
    // single probe of a partial index, measured at ~0 ms against the deployed database.
    //
    // Not inside `migrate`, and not inside `open_write`: `create-api-key` and `create-user` open the
    // database the same way and have no business running a backfill.
    //
    // Before readiness rather than behind it, because it must not race the writer for the connection.
    // That is only defensible while the fill is fast, so the duration is logged and the budget is
    // explicit: `TimeoutStartSec` is 420 s, of which the clock gate claims 300, leaving 120 s. The
    // first attempt at this backfill spent 168 s of that and had to be rewritten — see
    // `store::series::backfill`. If the logged duration approaches the slack again, this is the call
    // that moves behind `sd_notify`.
    // **Fatal on failure, unlike the key count below**, and the difference is worth being explicit
    // about. A missing API key degrades a *feature*: the receiver refuses requests, loudly, and nothing
    // it does report is wrong. An unassigned measurement is different — since §6.7 the read path joins
    // `series` for every `type` and `attributes`, so a row without one is **invisible**: `/v1/measurements`
    // and every chart would silently omit it. For a monitoring system, quietly under-reporting is the
    // worst available failure, strictly worse than being down and saying so.
    //
    // `backfill` is one transaction that re-checks the queue before committing, so `Ok` means the queue
    // is empty — the precondition the inner join rests on is exactly "this returned Ok". Nothing can
    // refill it afterwards: only the writer stores measurements, it is spawned below, and it always sets
    // `series_id`.
    //
    // Reachable only from data this receiver did not write, or from I/O failure. Both need a human, and
    // `Restart=on-failure` retries every 60 s meanwhile.
    let started = std::time::Instant::now();
    let filled = store::series::backfill(&mut conn)
        .context("assigning series to measurements; refusing to serve reads that would omit them")?;
    if filled > 0 {
        tracing::info!(
            filled,
            elapsed_ms = started.elapsed().as_millis(),
            "series backfill finished"
        );
    }

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

    let (writer, writer_done) = store::write::spawn(conn);

    let listener = transport::uds::bind(&config.socket_path)?;
    let socket_path = config.socket_path.clone();

    let app = api::app(AppState::new(config, writer.clone()));

    // Only now is the service genuinely ready: schema current, socket accepting. Telling systemd
    // any earlier would let a dependent unit race our bind() (SPEC §9.2).
    // `notify` returns Ok(()) when NOTIFY_SOCKET is unset, so this is inert outside systemd —
    // no branch needed for development runs or tests.
    if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
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
