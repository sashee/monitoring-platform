//! Configuration resolution. Mirrors `monitoring_platform::config`: CLI flag → environment
//! variable → systemd directory → relative default, resolved by a pure function over an
//! environment map so it is testable without touching the process environment.

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::epoch::{DEFAULT_RESYNC_THRESHOLD_NANOS, DEFAULT_TOLERANCE_NANOS};
use crate::journal::DEFAULT_STEP_THRESHOLD_NANOS;
use crate::sync::{DEFAULT_CONSECUTIVE, DEFAULT_THRESHOLD_MICROS};

/// Where a corrected batch goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A local unix socket — the receiver's own, in the shape SPEC.md §1 describes.
    Unix(PathBuf),
    /// Plain HTTP over TCP.
    Http { authority: String, path: String },
}

/// The receiver's default socket, from `nix/module.nix`.
pub const DEFAULT_FORWARD_TO: &str = "/run/monitoring-platform/monitoring-platform.sock";
/// The OTLP/HTTP logs endpoint, appended when a URL names no path of its own.
pub const LOGS_PATH: &str = "/v1/logs";

/// A leading `http://` means TCP; anything else is a filesystem path.
///
/// `https://` is refused rather than silently downgraded: TLS is out of scope for the receiver
/// (SPEC.md §2), so a URL that looks encrypted and is not would be the worst of the three
/// outcomes. Refusing names the problem at startup instead of at the first flush.
pub fn parse_target(raw: &str) -> Result<Target> {
    if raw.is_empty() {
        bail!("--forward-to is empty; expected a socket path or an http:// URL");
    }
    if let Some(rest) = raw.strip_prefix("https://") {
        bail!(
            "--forward-to {raw:?} requests TLS, which this collector does not implement \
             (SPEC.md §2 puts it out of scope). Use a unix socket, or http://{rest} if the hop \
             is genuinely local."
        );
    }
    let Some(rest) = raw.strip_prefix("http://") else {
        return Ok(Target::Unix(PathBuf::from(raw)));
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        bail!("--forward-to {raw:?} has no host");
    }
    // A bare host means "the OTLP logs endpoint on that host", which is what every OTLP exporter
    // configured with an endpoint rather than a full URL also means.
    let path = if path.is_empty() || path == "/" { LOGS_PATH } else { path };
    Ok(Target::Http { authority: authority.to_owned(), path: path.to_owned() })
}

#[derive(Debug, Parser)]
#[command(
    name = "mp-collector",
    about = "On-host OTLP collector that retroactively corrects timestamps from an unsynchronized clock",
    version
)]
pub struct Cli {
    /// Unix socket to listen on. Defaults to $RUNTIME_DIRECTORY/mp-collector.sock, else ./mp-collector.sock
    ///
    /// Ignored when systemd passes a listening socket through `LISTEN_FDS`, which is the
    /// deployed arrangement: the socket unit creates the endpoint before any client can connect.
    #[arg(long, env = "MPC_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Where to send corrected batches: a unix socket path, or an `http://host:port/path` URL.
    #[arg(long, env = "MPC_FORWARD_TO")]
    pub forward_to: Option<String>,

    /// Directory for the epoch table and the spool. Defaults to $STATE_DIRECTORY, else ./
    #[arg(long, env = "MPC_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Records to hold in memory before spilling the oldest to disk.
    #[arg(long, env = "MPC_BUFFER_MAX_RECORDS")]
    pub buffer_max_records: Option<usize>,

    /// Encoded bytes to hold in memory before spilling the oldest to disk.
    #[arg(long, env = "MPC_BUFFER_MAX_BYTES")]
    pub buffer_max_bytes: Option<usize>,

    /// Seconds to wait for the clock before flushing anyway, marked uncertain.
    #[arg(long, env = "MPC_BUFFER_TIMEOUT_SECS")]
    pub buffer_timeout_secs: Option<u64>,

    /// Milliseconds to accumulate a batch once the clock is good.
    #[arg(long, env = "MPC_GRACE_MILLIS")]
    pub grace_millis: Option<u64>,

    /// Seconds to wait for the receiver to answer before abandoning the attempt and retrying.
    #[arg(long, env = "MPC_FORWARD_TIMEOUT_SECS")]
    pub forward_timeout_secs: Option<u64>,

    /// Seconds to cap the retry backoff at while delivery is failing. 0 retries every cycle.
    #[arg(long, env = "MPC_RETRY_MAX_SECS")]
    pub retry_max_secs: Option<u64>,

    /// Seconds between §9 self-metric events. 0 disables them.
    #[arg(long, env = "MPC_HEALTH_INTERVAL_SECS")]
    pub health_interval_secs: Option<u64>,

    /// Maximum kernel clock error to accept, in microseconds. Default 5000000 (5 s).
    #[arg(long, env = "MPC_CLOCK_THRESHOLD_MICROS")]
    pub clock_threshold_micros: Option<i64>,

    /// Consecutive good clock readings required before the buffer is released.
    #[arg(long, env = "MPC_CLOCK_CONSECUTIVE")]
    pub clock_consecutive: Option<u32>,

    /// Reconstruct pre-collector offset history from journald at startup.
    #[arg(long, env = "MPC_JOURNAL_BACKFILL", default_value_t = true, action = clap::ArgAction::Set)]
    pub journal_backfill: bool,

    /// Maximum wire request body, in bytes.
    #[arg(long, env = "MPC_MAX_BODY_BYTES")]
    pub max_body_bytes: Option<usize>,

    /// Maximum decompressed request body, in bytes.
    #[arg(long, env = "MPC_MAX_DECOMPRESSED_BYTES")]
    pub max_decompressed_bytes: Option<usize>,

    /// Log filter, e.g. `info` or `mp_collector=debug`.
    #[arg(long, env = "MPC_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            socket: None,
            forward_to: None,
            state_dir: None,
            buffer_max_records: None,
            buffer_max_bytes: None,
            buffer_timeout_secs: None,
            grace_millis: None,
            forward_timeout_secs: None,
            retry_max_secs: None,
            health_interval_secs: None,
            clock_threshold_micros: None,
            clock_consecutive: None,
            journal_backfill: true,
            max_body_bytes: None,
            max_decompressed_bytes: None,
            log_level: "info".to_owned(),
        }
    }
}

/// 5 minutes, matching the receiver's own clock-gate budget (`clock::DEFAULT_MAX_POLLS`
/// × `DEFAULT_POLL_INTERVAL_SECS`). A Pi that boots with no network may never synchronize, and
/// holding its telemetry indefinitely is worse than shipping it marked.
pub const DEFAULT_BUFFER_TIMEOUT_SECS: u64 = 300;
/// Long enough to coalesce a burst, short enough that nothing waits on it. Stays active even
/// after sync (§4.6): it costs almost nothing, smooths batching, and guarantees a step never
/// arrives with zero correctable records in hand.
pub const DEFAULT_GRACE_MILLIS: u64 = 500;
/// A minute: frequent enough to catch a device that never synchronizes within the buffer timeout,
/// infrequent enough to be free. Zero turns them off, which is what a test wanting an exact row
/// count needs — these are ordinary measurements and they land in the same table as everything
/// else, which is the point of them and also a thing that can surprise an assertion.
pub const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 60;
/// Generous on purpose. This bounds a *hung* transport, and the retry backoff — not this value — is
/// what keeps an unreachable receiver from starving the receive path, so there is nothing to buy by
/// making it tight. A timeout short enough to fire on a receiver that is merely slow would be the
/// worse failure: the batch lands, the acknowledgement arrives too late to be believed, and the
/// collector re-sends work the receiver has already done, indefinitely.
///
/// It exists at all because "the receiver is down" stops being a connect error the moment anything
/// stands between the collector and the receiver. A local proxy socket accepts whether or not its
/// far end is reachable, so the failure arrives as silence, and silence has no other detector.
pub const DEFAULT_FORWARD_TIMEOUT_SECS: u64 = 30;
/// The backoff ceiling: the longest a batch can wait *after* the receiver comes back. Sized so an
/// ordinary `systemctl restart monitoring-platform` costs a few seconds of delay rather than a
/// minute.
pub const DEFAULT_RETRY_MAX_SECS: u64 = 10;
pub const DEFAULT_BUFFER_MAX_RECORDS: usize = 100_000;
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

/// Immutable resolved configuration, passed down by value. No global state, and the environment is
/// never re-read after startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub socket_path: PathBuf,
    pub target: Target,
    pub state_dir: PathBuf,
    pub buffer_max_records: usize,
    pub buffer_max_bytes: usize,
    pub buffer_timeout: Duration,
    pub grace: Duration,
    /// How long one delivery attempt may take before it is abandoned and retried.
    pub forward_timeout: Duration,
    /// Ceiling for the exponential retry backoff, whose floor is `grace`.
    pub retry_max: Duration,
    /// `None` when self-metrics are switched off.
    pub health_interval: Option<Duration>,
    pub clock_threshold_micros: i64,
    pub clock_consecutive: u32,
    pub journal_backfill: bool,
    pub max_body_bytes: usize,
    pub max_decompressed_bytes: usize,
    /// Slack for fuzzy epoch boundaries in frame resolution.
    pub tolerance_nanos: i64,
    /// How far a sampled offset may sit from the active epoch before it is a missed boundary.
    pub resync_threshold_nanos: i64,
    /// How far the offset must move between journal entries to count as a step.
    pub journal_step_threshold_nanos: i64,
}

impl Config {
    /// `env` supplies `RUNTIME_DIRECTORY` / `STATE_DIRECTORY`; clap has already applied `MPC_*`.
    pub fn resolve(args: &Cli, env: &HashMap<String, String>) -> Result<Self> {
        let dir = |key: &str| {
            // systemd may hand over a colon-separated list; the first entry is ours.
            env.get(key)
                .and_then(|d| d.split(':').next())
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
        };

        Ok(Config {
            socket_path: args.socket.clone().unwrap_or_else(|| {
                dir("RUNTIME_DIRECTORY")
                    .map_or_else(|| PathBuf::from("./mp-collector.sock"), |d| d.join("mp-collector.sock"))
            }),
            target: parse_target(args.forward_to.as_deref().unwrap_or(DEFAULT_FORWARD_TO))?,
            state_dir: args
                .state_dir
                .clone()
                .or_else(|| dir("STATE_DIRECTORY"))
                .unwrap_or_else(|| PathBuf::from(".")),
            buffer_max_records: args.buffer_max_records.unwrap_or(DEFAULT_BUFFER_MAX_RECORDS),
            buffer_max_bytes: args.buffer_max_bytes.unwrap_or(DEFAULT_BUFFER_MAX_BYTES),
            buffer_timeout: Duration::from_secs(
                args.buffer_timeout_secs.unwrap_or(DEFAULT_BUFFER_TIMEOUT_SECS),
            ),
            grace: Duration::from_millis(args.grace_millis.unwrap_or(DEFAULT_GRACE_MILLIS)),
            forward_timeout: Duration::from_secs(
                args.forward_timeout_secs.unwrap_or(DEFAULT_FORWARD_TIMEOUT_SECS),
            ),
            retry_max: Duration::from_secs(
                args.retry_max_secs.unwrap_or(DEFAULT_RETRY_MAX_SECS),
            ),
            health_interval: match args.health_interval_secs.unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS)
            {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
            clock_threshold_micros: args
                .clock_threshold_micros
                .unwrap_or(DEFAULT_THRESHOLD_MICROS),
            clock_consecutive: args.clock_consecutive.unwrap_or(DEFAULT_CONSECUTIVE),
            journal_backfill: args.journal_backfill,
            max_body_bytes: args.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
            max_decompressed_bytes: args
                .max_decompressed_bytes
                .unwrap_or(DEFAULT_MAX_DECOMPRESSED_BYTES),
            tolerance_nanos: DEFAULT_TOLERANCE_NANOS,
            resync_threshold_nanos: DEFAULT_RESYNC_THRESHOLD_NANOS,
            journal_step_threshold_nanos: DEFAULT_STEP_THRESHOLD_NANOS,
        })
    }

    pub fn from_env(args: &Cli) -> Result<Self> {
        Self::resolve(args, &std::env::vars().collect())
    }

    /// Where the epoch table is persisted (§4.1).
    pub fn epochs_path(&self) -> PathBuf {
        self.state_dir.join("epochs.json")
    }

    /// Where overflowing batches are spilled (§4.6).
    pub fn spool_dir(&self) -> PathBuf {
        self.state_dir.join("spool")
    }
}

/// Refuses a configuration that cannot work, rather than discovering it at the first flush.
pub fn validate(config: &Config) -> Result<()> {
    if config.buffer_max_records == 0 || config.buffer_max_bytes == 0 {
        return Err(anyhow!("a zero buffer cap would spill every batch to disk immediately"));
    }
    if config.clock_consecutive == 0 {
        return Err(anyhow!("--clock-consecutive 0 would release the buffer without ever reading the clock"));
    }
    // A zero `retry_max` is deliberately allowed — it means "retry on every cycle", which is the
    // behaviour from before the backoff existed and a legitimate choice for a purely local hop.
    // A zero timeout is not: it abandons every attempt before it can finish.
    if config.forward_timeout.is_zero() {
        return Err(anyhow!(
            "--forward-timeout-secs 0 would abandon every batch before the receiver could answer"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn falls_back_to_relative_paths_for_development() {
        let c = Config::resolve(&Cli::default(), &env(&[])).unwrap();
        assert_eq!(c.socket_path, PathBuf::from("./mp-collector.sock"));
        assert_eq!(c.state_dir, PathBuf::from("."));
        assert_eq!(c.target, Target::Unix(PathBuf::from(DEFAULT_FORWARD_TO)));
    }

    #[test]
    fn uses_systemd_directories_when_present() {
        let c = Config::resolve(
            &Cli::default(),
            &env(&[("RUNTIME_DIRECTORY", "/run/mpc"), ("STATE_DIRECTORY", "/var/lib/mpc")]),
        )
        .unwrap();
        assert_eq!(c.socket_path, PathBuf::from("/run/mpc/mp-collector.sock"));
        assert_eq!(c.epochs_path(), PathBuf::from("/var/lib/mpc/epochs.json"));
        assert_eq!(c.spool_dir(), PathBuf::from("/var/lib/mpc/spool"));
    }

    /// systemd sets a colon-separated list when several directories are configured.
    #[test]
    fn takes_the_first_of_a_systemd_directory_list() {
        let c = Config::resolve(&Cli::default(), &env(&[("RUNTIME_DIRECTORY", "/run/a:/run/b")]))
            .unwrap();
        assert_eq!(c.socket_path, PathBuf::from("/run/a/mp-collector.sock"));
    }

    #[test]
    fn empty_systemd_directory_is_ignored() {
        let c = Config::resolve(&Cli::default(), &env(&[("RUNTIME_DIRECTORY", "")])).unwrap();
        assert_eq!(c.socket_path, PathBuf::from("./mp-collector.sock"));
    }

    #[test]
    fn explicit_flags_beat_systemd_directories() {
        let args = Cli {
            socket: Some("/tmp/c.sock".into()),
            state_dir: Some("/tmp/state".into()),
            buffer_timeout_secs: Some(7),
            grace_millis: Some(11),
            ..Cli::default()
        };
        let c = Config::resolve(&args, &env(&[("RUNTIME_DIRECTORY", "/run/mpc")])).unwrap();
        assert_eq!(c.socket_path, PathBuf::from("/tmp/c.sock"));
        assert_eq!(c.state_dir, PathBuf::from("/tmp/state"));
        assert_eq!(c.buffer_timeout, Duration::from_secs(7));
        assert_eq!(c.grace, Duration::from_millis(11));
    }

    #[test]
    fn a_bare_path_is_a_unix_socket() {
        assert_eq!(
            parse_target("/run/monitoring-platform/monitoring-platform.sock").unwrap(),
            Target::Unix(PathBuf::from("/run/monitoring-platform/monitoring-platform.sock"))
        );
        assert_eq!(parse_target("./relative.sock").unwrap(), Target::Unix("./relative.sock".into()));
    }

    /// A bare host means the OTLP logs endpoint on it, which is what an exporter configured with
    /// an endpoint rather than a full URL also means.
    #[test]
    fn a_url_without_a_path_gets_the_otlp_logs_endpoint() {
        assert_eq!(
            parse_target("http://collector:4318").unwrap(),
            Target::Http { authority: "collector:4318".into(), path: LOGS_PATH.into() }
        );
        assert_eq!(
            parse_target("http://collector:4318/").unwrap(),
            Target::Http { authority: "collector:4318".into(), path: LOGS_PATH.into() }
        );
    }

    #[test]
    fn an_explicit_path_is_kept() {
        assert_eq!(
            parse_target("http://host:1234/otlp/v1/logs").unwrap(),
            Target::Http { authority: "host:1234".into(), path: "/otlp/v1/logs".into() }
        );
    }

    /// The one refusal. A URL that looks encrypted and silently is not would be worse than either
    /// implementing TLS or rejecting it, and the message has to say which.
    #[test]
    fn https_is_refused_with_an_explanation() {
        let err = parse_target("https://host/v1/logs").unwrap_err().to_string();
        assert!(err.contains("TLS"), "the reason must be named: {err}");
        assert!(err.contains("http://host/v1/logs"), "the alternative must be spelled out: {err}");
    }

    #[test]
    fn a_url_with_no_host_is_refused() {
        assert!(parse_target("http://").is_err());
        assert!(parse_target("http:///v1/logs").is_err());
        assert!(parse_target("").is_err());
    }

    /// The thresholds are the receiver's, not the design doc's 1–2 s. Asserted so a future edit
    /// to either side is a deliberate divergence rather than a drift.
    /// Zero is off, not "every zero seconds" — which as a `tokio` interval would be a hot loop.
    #[test]
    fn a_zero_health_interval_disables_the_self_metrics() {
        let off = Cli { health_interval_secs: Some(0), ..Cli::default() };
        assert_eq!(Config::resolve(&off, &env(&[])).unwrap().health_interval, None);

        let on = Cli { health_interval_secs: Some(5), ..Cli::default() };
        assert_eq!(
            Config::resolve(&on, &env(&[])).unwrap().health_interval,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            Config::resolve(&Cli::default(), &env(&[])).unwrap().health_interval,
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn the_clock_threshold_matches_the_receivers_gate() {
        let c = Config::resolve(&Cli::default(), &env(&[])).unwrap();
        assert_eq!(c.clock_threshold_micros, 5_000_000);
        assert_eq!(c.clock_consecutive, 3);
        assert_eq!(c.buffer_timeout, Duration::from_secs(300));
    }

    #[test]
    fn a_configuration_that_cannot_work_is_refused_at_startup() {
        let good = Config::resolve(&Cli::default(), &env(&[])).unwrap();
        assert!(validate(&good).is_ok());

        assert!(validate(&Config { buffer_max_records: 0, ..good.clone() }).is_err());
        assert!(validate(&Config { buffer_max_bytes: 0, ..good.clone() }).is_err());
        assert!(validate(&Config { clock_consecutive: 0, ..good.clone() }).is_err());
        assert!(validate(&Config { forward_timeout: Duration::ZERO, ..good.clone() }).is_err());

        // Not a mistake: zero is how a purely local deployment opts out of backing off.
        assert!(validate(&Config { retry_max: Duration::ZERO, ..good }).is_ok());
    }

    /// The delivery timeout must be far longer than any healthy receiver takes, because a timeout
    /// that fires on a slow-but-working write makes the collector re-send work that already landed.
    /// The backoff cap must be short, because it is the delay a recovered receiver pays.
    #[test]
    fn the_delivery_defaults_are_a_long_timeout_and_a_short_backoff() {
        let c = Config::resolve(&Cli::default(), &env(&[])).unwrap();
        assert_eq!(c.forward_timeout, Duration::from_secs(30));
        assert_eq!(c.retry_max, Duration::from_secs(10));
        assert!(c.retry_max >= c.grace, "the backoff floor is the grace period");
    }

    #[test]
    fn the_delivery_timings_are_configurable() {
        let args =
            Cli { forward_timeout_secs: Some(3), retry_max_secs: Some(2), ..Cli::default() };
        let c = Config::resolve(&args, &env(&[])).unwrap();
        assert_eq!(c.forward_timeout, Duration::from_secs(3));
        assert_eq!(c.retry_max, Duration::from_secs(2));
    }
}
