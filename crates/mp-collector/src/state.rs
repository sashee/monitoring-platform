//! Persisting the epoch table across a collector restart (design §4.1, §8.4).
//!
//! A restart must not lose offset history: the collector is ordered before the time daemons
//! precisely so it witnesses every step, and a crash-restart that forgot the pre-step offset would
//! leave every buffered record from before it unresolvable.
//!
//! **Keyed by `boot_id`, and that is the whole safety property.** Boottime values mean nothing
//! across a reboot — epoch 0 of the previous boot describes a machine that no longer exists — so a
//! file from another boot is discarded rather than merged. The same guard covers spooled records
//! (§8.4), which is why [`Snapshot`] carries the id rather than the filename encoding it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::epoch::{Epoch, EpochTable};

/// What lands on disk. Versioned so a format change is a clean discard rather than a
/// misinterpretation of old bytes as new ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    version: u32,
    pub boot_id: String,
    pub epochs: Vec<Epoch>,
}

const VERSION: u32 = 1;

impl Snapshot {
    pub fn new(boot_id: String, table: &EpochTable) -> Self {
        Self { version: VERSION, boot_id, epochs: table.epochs().to_vec() }
    }

    /// The table this snapshot describes, if it describes *this* boot.
    pub fn table_for(&self, boot_id: &str) -> Option<EpochTable> {
        (self.version == VERSION && self.boot_id == boot_id)
            .then(|| EpochTable::from_epochs(self.epochs.clone()))
            .flatten()
    }
}

/// Reads the table back, or `None` for every reason that is not worth failing a startup over.
///
/// A missing, truncated, unparsable or previous-boot file all mean the same thing operationally:
/// no history, start from a fresh reading. Failing to start instead would strand a device over a
/// corrupt cache file, which is a far worse outcome than losing correction for one boot.
pub fn load(path: &Path, boot_id: &str) -> Option<EpochTable> {
    let bytes = fs::read(path).ok()?;
    match serde_json::from_slice::<Snapshot>(&bytes) {
        Ok(snapshot) => {
            if snapshot.boot_id != boot_id {
                tracing::info!(
                    stored = %snapshot.boot_id,
                    current = %boot_id,
                    "discarding offset history from a previous boot"
                );
                return None;
            }
            snapshot.table_for(boot_id)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "unreadable offset history; starting fresh");
            None
        }
    }
}

/// Writes the table, atomically.
///
/// Temp file plus rename, because the alternative is a truncated file after a power cut on a
/// device whose whole problem is that it loses power at inconvenient moments. A reader then sees
/// either the old snapshot or the new one, never half of either.
pub fn save(path: &Path, boot_id: &str, table: &EpochTable) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating state directory {}", parent.display()))?;
    }

    let snapshot = Snapshot::new(boot_id.to_owned(), table);
    let json = serde_json::to_vec(&snapshot).context("serializing the epoch table")?;

    let temp = path.with_extension("tmp");
    fs::write(&temp, &json).with_context(|| format!("writing {}", temp.display()))?;
    fs::rename(&temp, path)
        .with_context(|| format!("renaming {} into place", temp.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::Source;

    const SEC: i64 = 1_000_000_000;
    const WALL: i64 = 1_785_924_000 * SEC;
    const BOOT: &str = "4f2e1c9a-8b7d-6e5f-4a3b-2c1d0e9f8a7b";

    fn table() -> EpochTable {
        EpochTable::new(Epoch { boot_start: 0, offset: WALL - 99 * SEC, source: Source::Startup })
            .with(Epoch { boot_start: 30 * SEC, offset: WALL, source: Source::Step })
    }

    #[test]
    fn a_table_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epochs.json");

        save(&path, BOOT, &table()).unwrap();
        assert_eq!(load(&path, BOOT), Some(table()));
    }

    /// §8.4. Boottime values from a previous boot describe a machine that no longer exists, and
    /// silently reusing them would produce confidently wrong corrections rather than none.
    #[test]
    fn history_from_a_previous_boot_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epochs.json");

        save(&path, BOOT, &table()).unwrap();
        assert_eq!(load(&path, "00000000-0000-0000-0000-000000000000"), None);
    }

    #[test]
    fn a_missing_file_is_simply_no_history() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("absent.json"), BOOT), None);
    }

    /// A device that lost power mid-write must still start. The failure mode to avoid is a
    /// collector that refuses to run because of its own cache file.
    #[test]
    fn a_corrupt_file_starts_fresh_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epochs.json");

        for junk in [b"".as_slice(), b"{", b"not json", b"{\"version\":1}"] {
            fs::write(&path, junk).unwrap();
            assert_eq!(load(&path, BOOT), None, "junk {junk:?} should degrade, not explode");
        }
    }

    /// A snapshot written by a future format is discarded, not reinterpreted.
    #[test]
    fn a_future_version_is_discarded() {
        let snapshot = Snapshot { version: VERSION + 1, boot_id: BOOT.into(), epochs: vec![] };
        assert_eq!(snapshot.table_for(BOOT), None);
    }

    /// The rename is what makes a reader see one whole snapshot or the other, never a prefix.
    #[test]
    fn saving_replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epochs.json");

        save(&path, BOOT, &table()).unwrap();
        let newer = table().with(Epoch { boot_start: 60 * SEC, offset: WALL + SEC, source: Source::Step });
        save(&path, BOOT, &newer).unwrap();

        assert_eq!(load(&path, BOOT), Some(newer));
        assert!(!path.with_extension("tmp").exists(), "the temp file was left behind");
    }

    #[test]
    fn saving_creates_the_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/epochs.json");
        save(&path, BOOT, &table()).unwrap();
        assert_eq!(load(&path, BOOT), Some(table()));
    }
}
