//! Configuration resolution (SPEC §9.1).
//!
//! Resolution order: CLI flag → environment variable → systemd directory → relative default.
//! Resolution is a pure function over an environment map so it is testable without touching the
//! process environment.

use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;

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
            database_path: args.database.clone().unwrap_or_else(|| {
                match env.get("STATE_DIRECTORY").and_then(|d| d.split(':').next()) {
                    Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("measurements.db"),
                    _ => PathBuf::from("./measurements.db"),
                }
            }),
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
}
