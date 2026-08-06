//! `mp-collector` — wiring, socket activation, signals and shutdown ordering.
//!
//! See `collector-clock-correction-design.md`.

use anyhow::{Context, Result};
use clap::Parser;
use mp_collector::config::{Cli, Config, validate};
use mp_collector::{receive, runtime};
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    // BEFORE the runtime exists, because it removes environment variables and that is only sound
    // while the process is single-threaded. Doing it here rather than inside `serve` is the whole
    // reason `main` is not `#[tokio::main]`.
    //
    // SAFETY: no thread has been spawned yet — `tokio`'s runtime is built below — so nothing can
    // be reading the environment concurrently.
    let inherited: Vec<_> = unsafe { sd_notify::listen_fds_and_unset_env() }
        .context("reading LISTEN_FDS from the service manager")?
        .collect();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?
        .block_on(serve(cli, inherited))
}

fn init_tracing(filter: &str) {
    let env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).with_target(false).init();
}

async fn serve(cli: Cli, inherited: Vec<std::os::fd::RawFd>) -> Result<()> {
    let config = Arc::new(Config::from_env(&cli)?);
    validate(&config)?;

    // Read once, at the top, and threaded through by value: everything keyed by it — the epoch
    // table on disk, the spool — must agree on which boot this is.
    let boot_id = mp_host::clock::boot_id().context("reading the kernel's boot id")?;

    tracing::info!(
        socket = %config.socket_path.display(),
        forward_to = ?config.target,
        state = %config.state_dir.display(),
        boot_id = %boot_id,
        "starting"
    );

    let (listener, owns_socket) = bind(&config, &inherited)?;
    let (handle, tasks) = runtime::build(Arc::clone(&config), boot_id)?;

    let clock = tokio::spawn(tasks.clock.run());
    let flush = tokio::spawn(tasks.flush.run());

    let app = receive::app(receive::AppState { config: Arc::clone(&config), handle })
        .into_make_service_with_connect_info::<receive::Peer>();

    // Only now is the collector genuinely ready: history loaded, clock watch armed, socket
    // accepting. Telling systemd earlier would let an application unit ordered after it race the
    // very thing that ordering exists to guarantee.
    if let Err(e) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        tracing::warn!(error = %e, "failed to send readiness notification to systemd");
    }
    tracing::info!("ready");

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving");

    // Ordering matters. Aborting the clock task first would be harmless; aborting the flush task
    // first would strand whatever is in the buffer, so it is given the chance to drain: its
    // `run` loop ends when the inbox closes, which happens when the HTTP layer above is gone.
    tracing::info!("draining the buffer");
    clock.abort();
    match tokio::time::timeout(std::time::Duration::from_secs(10), flush).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::warn!(error = %e, "the flush task failed"),
        Ok(Err(e)) => tracing::warn!(error = %e, "the flush task panicked"),
        Err(_) => tracing::warn!("the flush task did not drain within ten seconds"),
    }

    // Only a socket this process created is this process's to remove; a socket-activated one
    // belongs to systemd, which recreates it on the next start.
    if owns_socket {
        mp_host::uds::cleanup(&config.socket_path);
    }
    tracing::info!("stopped");

    result
}

/// The inherited socket if the service manager passed one, else a freshly bound one.
///
/// Socket activation is the deployed arrangement and is what removes the startup ordering race
/// entirely: the socket unit creates the endpoint before any client can connect, so a client
/// blocks rather than fails. Binding is the development path.
fn bind(config: &Config, inherited: &[std::os::fd::RawFd]) -> Result<(UnixListener, bool)> {
    match inherited {
        [] => {
            tracing::info!("no socket from the service manager; binding our own");
            Ok((mp_host::uds::bind(&config.socket_path)?, true))
        }
        [fd] => {
            tracing::info!(fd, "adopting the socket-activated listener");
            Ok((mp_host::uds::adopt(*fd)?, false))
        }
        many => anyhow::bail!(
            "the service manager passed {} sockets; this collector serves exactly one",
            many.len()
        ),
    }
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
