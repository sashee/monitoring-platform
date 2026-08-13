//! Wiring, signals and shutdown ordering.

use anyhow::{Context, Result};
use clap::Parser;
use monitoring_platform::config::{ApiKeyArgs, Cli, Command, CreateApiKeyArgs, ServeArgs};
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
        Command::ListApiKeys(args) => {
            init_tracing_on_stderr(&args.log_level);
            list_api_keys(&args)
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

    let token = auth::Token::from_random(&random_token_bytes()?);
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

fn list_api_keys(args: &ApiKeyArgs) -> Result<()> {
    let conn = store::open_read(&args.database_path())?;
    for key in store::keys::list(&conn)? {
        println!(
            "{}  {}  {}",
            key.id,
            api::query::format_nanos(key.created_at),
            key.label
        );
    }
    Ok(())
}

/// The secret's entropy, straight from the kernel.
///
/// `/dev/urandom` rather than a `rand`/`getrandom` dependency: it is the same CSPRNG, this service is
/// Linux-only by construction (adjtimex, /proc, systemd credentials), and a credential is a poor
/// reason to widen the dependency graph. `read_exact` because a short read must be an error, never a
/// key with predictable tail bytes.
fn random_token_bytes() -> Result<[u8; auth::TOKEN_BYTES]> {
    use std::io::Read;

    let mut bytes = [0u8; auth::TOKEN_BYTES];
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(&mut bytes)
        .context("reading from /dev/urandom")?;
    Ok(bytes)
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
    let conn = store::open_write(&config.database_path)?;

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
