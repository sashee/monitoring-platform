//! Wiring, signals and shutdown ordering.

use anyhow::{Context, Result};
use clap::Parser;
use monitoring_platform::config::{Cli, Command, ServeArgs};
use monitoring_platform::{AppState, Config, api, store, transport};
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
    }
}

fn init_tracing(filter: &str) {
    let env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).with_target(false).init();
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
