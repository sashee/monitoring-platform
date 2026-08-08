//! Disk spill for the buffer (design §4.6, §8.4).
//!
//! Layout is `<state_dir>/spool/<boot_id>/<seq>.pb`, one encoded `ExportLogsServiceRequest` per
//! file. The boot id is a **directory**, not a filename suffix, so a reboot's worth of leftovers is
//! one `read_dir` to find and one `remove_dir_all` to retire.
//!
//! Sequence numbers are zero-padded and monotonic, so lexicographic order is arrival order and
//! reading the spool back needs no index — the filesystem is the index.

use anyhow::{Context, Result};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message;
use std::fs;
use std::path::{Path, PathBuf};

use crate::buffer::Pending;

/// A batch read back off disk.
#[derive(Debug)]
pub struct Spooled {
    request: ExportLogsServiceRequest,
    /// Whether it was written during *this* boot. `false` means its carried boottimes are
    /// meaningless and it must ship uncorrected (§8.4).
    pub same_boot: bool,
    path: PathBuf,
}

impl Spooled {
    /// The decoded batch. Takes it out rather than lending it, since the caller rewrites it in
    /// place and the entry itself is still needed afterwards to [`remove`](Self::remove) the file.
    pub fn take_request(&mut self) -> ExportLogsServiceRequest {
        std::mem::take(&mut self.request)
    }

    /// Read-only view, for callers that only want to look.
    pub fn peek(&self) -> &ExportLogsServiceRequest {
        &self.request
    }

    /// Deletes the file. Called only after the batch has been accepted downstream, so a crash
    /// between reading and acknowledging re-sends rather than loses — and re-sending is free,
    /// because the receiver's ids are content hashes (SPEC.md §6.6).
    pub fn remove(&self) {
        if let Err(e) = fs::remove_file(&self.path) {
            tracing::warn!(path = %self.path.display(), error = %e, "could not remove spooled batch");
        }
    }
}

/// The spool directory for one boot.
#[derive(Debug)]
pub struct Spool {
    root: PathBuf,
    boot_id: String,
    next_seq: u64,
}

impl Spool {
    /// Opens (and creates) this boot's spool directory, resuming the sequence where a previous
    /// run of the collector left off.
    pub fn open(root: &Path, boot_id: &str) -> Result<Self> {
        let dir = root.join(boot_id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating spool directory {}", dir.display()))?;

        // Resuming rather than restarting at zero: a collector restart within one boot must not
        // overwrite the files the previous run spilled.
        let next_seq = list(&dir)?
            .iter()
            .filter_map(|p| p.file_stem()?.to_str()?.parse::<u64>().ok())
            .max()
            .map_or(0, |n| n + 1);

        Ok(Self { root: root.to_owned(), boot_id: boot_id.to_owned(), next_seq })
    }

    /// Writes one batch out, atomically.
    pub fn write(&mut self, pending: &Pending) -> Result<()> {
        let dir = self.root.join(&self.boot_id);
        let path = dir.join(format!("{:020}.pb", self.next_seq));
        let temp = path.with_extension("tmp");

        fs::write(&temp, pending.request.encode_to_vec())
            .with_context(|| format!("writing {}", temp.display()))?;
        fs::rename(&temp, &path)
            .with_context(|| format!("renaming {} into place", temp.display()))?;

        self.next_seq += 1;
        Ok(())
    }

    /// Everything on disk, this boot's first and in arrival order, then any left by a previous
    /// boot.
    ///
    /// This boot's come first because they can be corrected and the previous boot's cannot; a
    /// downstream reader sees the good data without waiting behind the salvage.
    pub fn read_all(&self) -> Result<Vec<Spooled>> {
        let mut out = Vec::new();
        let mut foreign = Vec::new();

        for boot_dir in list(&self.root)? {
            let Some(name) = boot_dir.file_name().and_then(|n| n.to_str()) else { continue };
            if !boot_dir.is_dir() {
                continue;
            }
            let same_boot = name == self.boot_id;
            for path in list(&boot_dir)? {
                if path.extension().is_none_or(|e| e != "pb") {
                    continue;
                }
                match read_one(&path, same_boot) {
                    Ok(spooled) if same_boot => out.push(spooled),
                    Ok(spooled) => foreign.push(spooled),
                    Err(e) => {
                        // A truncated file is a power cut mid-write, not a reason to strand every
                        // other batch behind it.
                        tracing::warn!(path = %path.display(), error = %e, "discarding unreadable spooled batch");
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }

        out.append(&mut foreign);
        Ok(out)
    }

    /// Removes spool directories from other boots once their contents have been dealt with.
    pub fn retire_other_boots(&self) -> Result<()> {
        for boot_dir in list(&self.root)? {
            let Some(name) = boot_dir.file_name().and_then(|n| n.to_str()) else { continue };
            if boot_dir.is_dir() && name != self.boot_id {
                tracing::info!(boot = name, "retiring the spool of a previous boot");
                fs::remove_dir_all(&boot_dir)
                    .with_context(|| format!("removing {}", boot_dir.display()))?;
            }
        }
        Ok(())
    }
}

fn read_one(path: &Path, same_boot: bool) -> Result<Spooled> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let request = ExportLogsServiceRequest::decode(bytes.as_slice())
        .with_context(|| format!("decoding {}", path.display()))?;
    Ok(Spooled { request, same_boot, path: path.to_owned() })
}

/// Sorted directory listing. Sorted because the sequence numbers are zero-padded precisely so
/// lexicographic order is arrival order, and `read_dir` promises no order at all.
fn list(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries.filter_map(|e| Some(e.ok()?.path())).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

    const BOOT: &str = "4f2e1c9a-8b7d-6e5f-4a3b-2c1d0e9f8a7b";
    const OTHER: &str = "00000000-0000-0000-0000-000000000000";

    fn pending(name: &str) -> Pending {
        Pending {
            request: ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: vec![LogRecord {
                            event_name: name.to_owned(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            },
            bytes: 32,
            queued_at: 0,
            tally: crate::correct::Tally { exact: 1, ..Default::default() },
        }
    }

    fn names(spooled: &[Spooled]) -> Vec<String> {
        spooled
            .iter()
            .map(|s| s.peek().resource_logs[0].scope_logs[0].log_records[0].event_name.clone())
            .collect()
    }

    #[test]
    fn a_batch_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        spool.write(&pending("cpu")).unwrap();

        let back = spool.read_all().unwrap();
        assert_eq!(names(&back), vec!["cpu"]);
        assert!(back[0].same_boot);
    }

    /// Zero-padded sequence numbers exist so lexicographic order is arrival order; without the
    /// padding, batch 10 sorts before batch 2 and a burst comes back shuffled.
    #[test]
    fn batches_come_back_in_arrival_order_past_ten() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        for i in 0..12 {
            spool.write(&pending(&format!("m{i}"))).unwrap();
        }
        assert_eq!(
            names(&spool.read_all().unwrap()),
            (0..12).map(|i| format!("m{i}")).collect::<Vec<_>>()
        );
    }

    /// A collector restart within one boot must not overwrite what the previous run spilled.
    #[test]
    fn reopening_resumes_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        Spool::open(dir.path(), BOOT).unwrap().write(&pending("first")).unwrap();
        Spool::open(dir.path(), BOOT).unwrap().write(&pending("second")).unwrap();

        assert_eq!(names(&Spool::open(dir.path(), BOOT).unwrap().read_all().unwrap()), vec![
            "first", "second"
        ]);
    }

    /// §8.4. A previous boot's batches are found and flagged, not silently mixed in with this
    /// boot's — their carried boottimes describe a machine that no longer exists.
    #[test]
    fn a_previous_boots_batches_are_flagged_and_ordered_last() {
        let dir = tempfile::tempdir().unwrap();
        Spool::open(dir.path(), OTHER).unwrap().write(&pending("from-before")).unwrap();

        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        spool.write(&pending("from-now")).unwrap();

        let back = spool.read_all().unwrap();
        assert_eq!(names(&back), vec!["from-now", "from-before"], "correctable data first");
        assert!(back[0].same_boot);
        assert!(!back[1].same_boot, "a previous boot's batch must not claim to be correctable");
    }

    #[test]
    fn retiring_removes_other_boots_and_keeps_this_one() {
        let dir = tempfile::tempdir().unwrap();
        Spool::open(dir.path(), OTHER).unwrap().write(&pending("old")).unwrap();
        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        spool.write(&pending("new")).unwrap();

        spool.retire_other_boots().unwrap();
        assert!(!dir.path().join(OTHER).exists());
        assert_eq!(names(&spool.read_all().unwrap()), vec!["new"]);
    }

    /// A power cut mid-write leaves a truncated file. It must not strand every other batch behind
    /// it, and it must not come back on the next read either.
    #[test]
    fn a_truncated_file_is_discarded_without_taking_the_rest_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        spool.write(&pending("good")).unwrap();
        fs::write(dir.path().join(BOOT).join("00000000000000000099.pb"), b"\xff\xff\xff").unwrap();

        assert_eq!(names(&spool.read_all().unwrap()), vec!["good"]);
        assert_eq!(names(&spool.read_all().unwrap()), vec!["good"], "the junk was cleaned up");
    }

    #[test]
    fn removing_a_batch_takes_it_out_of_the_next_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path(), BOOT).unwrap();
        spool.write(&pending("a")).unwrap();
        spool.write(&pending("b")).unwrap();

        let back = spool.read_all().unwrap();
        back[0].remove();
        assert_eq!(names(&spool.read_all().unwrap()), vec!["b"]);
    }

    #[test]
    fn an_empty_spool_reads_as_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), BOOT).unwrap();
        assert!(spool.read_all().unwrap().is_empty());
        assert!(spool.retire_other_boots().is_ok());
    }

    /// Files the collector did not write must be ignored rather than decoded as protobuf.
    #[test]
    fn foreign_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), BOOT).unwrap();
        fs::write(dir.path().join(BOOT).join("README"), b"not a batch").unwrap();
        fs::write(dir.path().join("stray-file"), b"not a boot directory").unwrap();

        assert!(spool.read_all().unwrap().is_empty());
    }
}
