//! Configuration resolution (SPEC §9.1).
//!
//! Resolution order: CLI flag → environment variable → systemd directory → relative default.
//! Resolution is a pure function over an environment map so it is testable without touching the
//! process environment.

use clap::Parser;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::clock::{
    DEFAULT_CONSECUTIVE, DEFAULT_MAX_POLLS, DEFAULT_POLL_INTERVAL_SECS, DEFAULT_THRESHOLD_MICROS,
    GateSettings,
};

pub const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "monitoring-platform", about = "OTLP measurement receiver", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Run the receiver.
    Serve(ServeArgs),

    /// Block until the system clock is verifiably synchronized; exit non-zero if it is not.
    ///
    /// Run as the service's `ExecStartPre` so the receiver never stamps a measurement with a
    /// `processed_time` it cannot stand behind (SPEC §9.4). Usable on its own to diagnose a host
    /// that will not start monitoring.
    WaitForClock(WaitForClockArgs),

    /// Issue an API key, printing the token to stdout once (SPEC §13).
    ///
    /// The token cannot be recovered afterwards: only a hash of its secret half is stored. Losing it
    /// means issuing another and deleting this one.
    CreateApiKey(CreateApiKeyArgs),

    /// List the API keys that exist, by id and label.
    ///
    /// Never prints a secret, because none is stored — this answers "which keys exist" and "was mine
    /// created", not "what was the token".
    ListApiKeys(ApiKeyArgs),

    /// Create a web interface user, reading the password from stdin (SPEC §14).
    ///
    /// The password is never a flag and never an argument. `/proc/<pid>/cmdline` is world-readable, so a
    /// password on the command line is visible to every process on the host for as long as this one runs —
    /// and lands in the shell history besides. This is the same reason the collector takes an
    /// `apiKeyFile` rather than a key.
    CreateUser(CreateUserArgs),

    /// List the web interface users, by name and creation time.
    ///
    /// Never prints a password, because none is stored.
    ListUsers(ApiKeyArgs),

    /// List the browser sessions that exist, by public id, user and expiry.
    ///
    /// Never prints a session secret, because none is stored — so nothing here can be replayed as a login.
    ListSessions(ApiKeyArgs),

    /// Delete a web interface user, and every session they hold.
    ///
    /// The sessions go too, deliberately: without that, a cookie issued before the deletion would keep
    /// working against a username that no longer exists.
    DeleteUser(DeleteUserArgs),
}

#[derive(Debug, Parser, Default)]
pub struct ServeArgs {
    /// Unix socket to listen on. Defaults to $RUNTIME_DIRECTORY/monitoring-platform.sock, else ./monitoring-platform.sock
    #[arg(long, env = "MP_SOCKET")]
    pub socket: Option<PathBuf>,

    /// SQLite database. Defaults to $STATE_DIRECTORY/measurements.db, else ./measurements.db
    #[arg(long = "db", env = "MP_DB")]
    pub database: Option<PathBuf>,

    /// Maximum wire request body, in bytes.
    #[arg(long, env = "MP_MAX_BODY_BYTES")]
    pub max_body_bytes: Option<usize>,

    /// Maximum decompressed request body, in bytes.
    #[arg(long, env = "MP_MAX_DECOMPRESSED_BYTES")]
    pub max_decompressed_bytes: Option<usize>,

    /// Log filter, e.g. `info` or `monitoring_platform=debug`.
    #[arg(long, env = "MP_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

/// Enough to reach the database, for the commands that only read or write keys.
#[derive(Debug, Parser, Default)]
pub struct ApiKeyArgs {
    /// SQLite database. Defaults to $STATE_DIRECTORY/measurements.db, else ./measurements.db
    #[arg(long = "db", env = "MP_DB")]
    pub database: Option<PathBuf>,

    /// Log filter, e.g. `info` or `monitoring_platform=debug`.
    #[arg(long, env = "MP_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Parser, Default)]
pub struct CreateApiKeyArgs {
    #[command(flatten)]
    pub common: ApiKeyArgs,

    /// Who or what this key is for. Operator-facing only; it is never checked against anything.
    #[arg(long)]
    pub label: String,
}

#[derive(Debug, Parser, Default)]
pub struct CreateUserArgs {
    #[command(flatten)]
    pub common: ApiKeyArgs,

    /// The username to log in with. Compared exactly as given, so it is case-sensitive.
    #[arg(long)]
    pub username: String,
}

#[derive(Debug, Parser, Default)]
pub struct DeleteUserArgs {
    #[command(flatten)]
    pub common: ApiKeyArgs,

    /// The user to remove, along with every session they hold.
    #[arg(long)]
    pub username: String,
}

#[derive(Debug, Parser, Default)]
pub struct WaitForClockArgs {
    /// Maximum kernel clock error to accept, in microseconds. Default 5000000 (5 s).
    #[arg(long, env = "MP_CLOCK_THRESHOLD_MICROS")]
    pub threshold_micros: Option<i64>,

    /// Seconds between polls. Default 5.
    #[arg(long, env = "MP_CLOCK_POLL_INTERVAL_SECS")]
    pub poll_interval_secs: Option<u64>,

    /// How many polls to take before giving up. Default 60, i.e. ~5 min at the default interval.
    #[arg(long, env = "MP_CLOCK_MAX_POLLS")]
    pub max_polls: Option<u32>,

    /// Consecutive good polls required. Default 3, as hysteresis against `maxerror`'s sawtooth.
    #[arg(long, env = "MP_CLOCK_CONSECUTIVE")]
    pub consecutive: Option<u32>,

    /// Log filter, e.g. `info` or `monitoring_platform=debug`.
    #[arg(long, env = "MP_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}

impl WaitForClockArgs {
    /// Pure: flags (with `MP_CLOCK_*` already applied by clap) to resolved settings.
    pub fn settings(&self) -> GateSettings {
        GateSettings {
            threshold_micros: self.threshold_micros.unwrap_or(DEFAULT_THRESHOLD_MICROS),
            poll_interval: Duration::from_secs(
                self.poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
            ),
            max_polls: self.max_polls.unwrap_or(DEFAULT_MAX_POLLS),
            consecutive: self.consecutive.unwrap_or(DEFAULT_CONSECUTIVE),
        }
    }
}

/// Where the database is, from an explicit flag or the environment.
///
/// Shared by `serve` and the key commands, so a key can never be written to a different file from the
/// one the receiver reads. With `--db` unset and `STATE_DIRECTORY` exported for the service but not
/// for an operator's shell, that is exactly the mistake available to make.
pub fn database_path(explicit: Option<&Path>, env: &HashMap<String, String>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_owned();
    }
    match env.get("STATE_DIRECTORY").and_then(|d| d.split(':').next()) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("measurements.db"),
        _ => PathBuf::from("./measurements.db"),
    }
}

impl ApiKeyArgs {
    pub fn database_path(&self) -> PathBuf {
        database_path(self.database.as_deref(), &std::env::vars().collect())
    }
}

/// Immutable resolved configuration, passed down by value. No global state, and the environment is
/// never re-read after startup.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub socket_path: PathBuf,
    pub database_path: PathBuf,
    pub max_body_bytes: usize,
    pub max_decompressed_bytes: usize,
}

impl Config {
    /// `env` supplies `RUNTIME_DIRECTORY` / `STATE_DIRECTORY`; clap has already applied `MP_*`
    /// environment variables to `args`.
    pub fn resolve(args: &ServeArgs, env: &HashMap<String, String>) -> Self {
        Config {
            socket_path: args.socket.clone().unwrap_or_else(|| {
                // systemd may hand over a colon-separated list; the first entry is ours.
                match env.get("RUNTIME_DIRECTORY").and_then(|d| d.split(':').next()) {
                    Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("monitoring-platform.sock"),
                    _ => PathBuf::from("./monitoring-platform.sock"),
                }
            }),
            database_path: database_path(args.database.as_deref(), env),
            max_body_bytes: args.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
            max_decompressed_bytes: args
                .max_decompressed_bytes
                .unwrap_or(DEFAULT_MAX_DECOMPRESSED_BYTES),
        }
    }

    pub fn from_env(args: &ServeArgs) -> Self {
        Self::resolve(args, &std::env::vars().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn falls_back_to_relative_paths_for_development() {
        let c = Config::resolve(&ServeArgs::default(), &env(&[]));
        assert_eq!(c.socket_path, PathBuf::from("./monitoring-platform.sock"));
        assert_eq!(c.database_path, PathBuf::from("./measurements.db"));
        assert_eq!(c.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(c.max_decompressed_bytes, DEFAULT_MAX_DECOMPRESSED_BYTES);
    }

    #[test]
    fn uses_systemd_directories_when_present() {
        let c = Config::resolve(
            &ServeArgs::default(),
            &env(&[("RUNTIME_DIRECTORY", "/run/mp"), ("STATE_DIRECTORY", "/var/lib/mp")]),
        );
        assert_eq!(c.socket_path, PathBuf::from("/run/mp/monitoring-platform.sock"));
        assert_eq!(c.database_path, PathBuf::from("/var/lib/mp/measurements.db"));
    }

    /// systemd sets a colon-separated list when several directories are configured.
    #[test]
    fn takes_the_first_of_a_systemd_directory_list() {
        let c = Config::resolve(
            &ServeArgs::default(),
            &env(&[("RUNTIME_DIRECTORY", "/run/mp:/run/other")]),
        );
        assert_eq!(c.socket_path, PathBuf::from("/run/mp/monitoring-platform.sock"));
    }

    #[test]
    fn explicit_flags_beat_systemd_directories() {
        let args = ServeArgs {
            socket: Some(PathBuf::from("/tmp/x.sock")),
            database: Some(PathBuf::from("/tmp/x.db")),
            max_body_bytes: Some(1),
            max_decompressed_bytes: Some(2),
            ..Default::default()
        };
        let c = Config::resolve(
            &args,
            &env(&[("RUNTIME_DIRECTORY", "/run/mp"), ("STATE_DIRECTORY", "/var/lib/mp")]),
        );
        assert_eq!(c.socket_path, PathBuf::from("/tmp/x.sock"));
        assert_eq!(c.database_path, PathBuf::from("/tmp/x.db"));
        assert_eq!(c.max_body_bytes, 1);
        assert_eq!(c.max_decompressed_bytes, 2);
    }

    #[test]
    fn empty_systemd_directory_is_ignored() {
        let c = Config::resolve(&ServeArgs::default(), &env(&[("RUNTIME_DIRECTORY", "")]));
        assert_eq!(c.socket_path, PathBuf::from("./monitoring-platform.sock"));
    }

    /// An unset flag must fall back to the documented default rather than to zero, which for
    /// `threshold_micros` would be a gate nothing can ever pass.
    #[test]
    fn clock_gate_defaults_are_the_documented_ones() {
        let s = WaitForClockArgs::default().settings();
        assert_eq!(s.threshold_micros, DEFAULT_THRESHOLD_MICROS);
        assert_eq!(s.poll_interval, Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS));
        assert_eq!(s.max_polls, DEFAULT_MAX_POLLS);
        assert_eq!(s.consecutive, DEFAULT_CONSECUTIVE);
    }

    #[test]
    fn clock_gate_flags_override_the_defaults() {
        let args = WaitForClockArgs {
            threshold_micros: Some(1),
            poll_interval_secs: Some(2),
            max_polls: Some(3),
            consecutive: Some(4),
            ..Default::default()
        };
        let s = args.settings();
        assert_eq!(s.threshold_micros, 1);
        assert_eq!(s.poll_interval, Duration::from_secs(2));
        assert_eq!(s.max_polls, 3);
        assert_eq!(s.consecutive, 4);
    }
}
