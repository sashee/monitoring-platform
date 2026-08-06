//! Reconstructing offset history from journald (design §4.2). Parsing and folding are pure; only
//! [`read_this_boot`] runs a process.
//!
//! journald runs from very early boot and stamps every entry with both `__REALTIME_TIMESTAMP` and
//! `__MONOTONIC_TIMESTAMP`. Their difference is the offset at that moment, and a discontinuity in
//! the series is a step. That covers the window before the collector existed.
//!
//! **Soft dependency.** With applications ordered after the collector (design §7) the pre-collector
//! window contains no application-generated events and this finds nothing relevant. It matters for
//! processes outside the unit ordering — manually launched binaries, containers. A journal that is
//! unavailable or `Storage=volatile`-wiped degrades to no history, not to a failure.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::process::Command;

use crate::epoch::{Epoch, Source};

/// One entry, reduced to the three fields that matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `__REALTIME_TIMESTAMP`, microseconds since the Unix epoch.
    pub realtime_micros: i64,
    /// `__MONOTONIC_TIMESTAMP`, microseconds since boot. `CLOCK_MONOTONIC`, *not* boottime.
    pub monotonic_micros: i64,
    /// `_BOOT_ID`, as journald writes it: 32 hex digits, no dashes.
    pub boot_id: String,
}

/// How far the offset must move between two entries to count as a step rather than slew.
///
/// Slew is bounded at the kernel's 500 ppm, so two entries a minute apart can legitimately differ
/// by 30 ms. 100 ms clears that for any realistic entry spacing while sitting far below chrony's
/// 1 s `makestep` threshold, so every step chrony actually takes is caught.
pub const DEFAULT_STEP_THRESHOLD_NANOS: i64 = 100_000_000;

/// journald writes boot ids as bare hex; `/proc/sys/kernel/random/boot_id` writes them dashed.
/// Comparing the two forms directly silently matches nothing, which looks exactly like "no history
/// in this boot" and is the kind of bug that never reports itself.
pub fn same_boot(journal_form: &str, proc_form: &str) -> bool {
    let normalize = |s: &str| s.chars().filter(|c| *c != '-').flat_map(char::to_lowercase).collect::<String>();
    !journal_form.is_empty() && normalize(journal_form) == normalize(proc_form)
}

/// Folds a boot's entries into the offset history they imply.
///
/// `suspended_nanos` is `boottime − monotonic` from `mp_host::clock::suspended_nanos`, added to
/// every monotonic value to bring it into the boottime frame the epoch table works in. On a host
/// that never suspends it is zero; on one that does, skipping it skews all imported history.
///
/// The caller is expected to have this be the *only* source of the returned epochs' ordering —
/// entries arrive from `journalctl` in time order, but this sorts anyway rather than trusting it.
pub fn epochs(
    entries: &[Entry],
    this_boot: &str,
    suspended_nanos: i64,
    step_threshold_nanos: i64,
) -> Vec<Epoch> {
    let mut samples: Vec<(i64, i64)> = entries
        .iter()
        .filter(|e| same_boot(&e.boot_id, this_boot))
        .map(|e| (e.monotonic_micros * 1_000 + suspended_nanos, e.realtime_micros * 1_000))
        .collect();
    samples.sort_unstable();

    let Some(&(_, first_realtime)) = samples.first() else { return Vec::new() };
    let first_boottime = samples[0].0;

    // The first epoch is dated to boot, not to the first entry: journald starts early enough that
    // the offset it observed first is the one the machine booted with, and dating it later would
    // leave a gap that every pre-journald record falls into.
    let mut out = vec![Epoch {
        boot_start: 0,
        offset: first_realtime - first_boottime,
        source: Source::Journal,
    }];

    let mut previous_boottime = first_boottime;
    for &(boottime, realtime) in &samples[1..] {
        let offset = realtime - boottime;
        let current = out.last().expect("seeded above").offset;
        if (offset - current).abs() > step_threshold_nanos {
            // Dated to the LAST entry that still showed the old offset, not to this one. The step
            // happened somewhere in between and the bracket is all we know; taking the earlier end
            // means a record from just after the real step still falls inside the new epoch. The
            // later end would leave such a record to be explained by the *old* offset, which
            // produces a confidently wrong answer instead of a passthrough.
            out.push(Epoch { boot_start: previous_boottime, offset, source: Source::Journal });
        }
        previous_boottime = boottime;
    }

    out
}

/// The command that dumps this boot's entries.
///
/// Shelling out rather than linking `sd-journal`: the collector is deployed as a static-ish Rust
/// binary through nixpkgs' `rustPlatform`, and adding a `libsystemd` link dependency to buy a
/// startup-only read of at most a few thousand entries is a poor trade.
pub const JOURNALCTL: (&str, &[&str]) = (
    "journalctl",
    &["--boot", "--output=json", "--output-fields=_BOOT_ID", "--no-pager"],
);

/// `journalctl -o json` for the current boot.
pub fn read_this_boot() -> Result<Vec<Entry>> {
    let (program, args) = JOURNALCTL;
    read_with(program, args)
}

/// Runs `program` and parses its stdout as journal entries.
///
/// The program is a parameter so the invocation itself is testable — the exit-status check and the
/// stderr surfacing below are the parts that decide whether a broken backfill reports itself or
/// silently yields no history, and neither is reachable by testing [`parse`] alone.
pub fn read_with(program: &str, args: &[&str]) -> Result<Vec<Entry>> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program} for offset backfill"))?;

    if !output.status.success() {
        // stderr in the message, not just the status: "journalctl exited with 1" tells an operator
        // nothing, where "Failed to open files: Permission denied" tells them the unit is missing
        // its systemd-journal group.
        anyhow::bail!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

/// One JSON object per line. Lines that do not carry all three fields are skipped rather than
/// failing the backfill: journald emits entries with missing metadata, and losing resolution is a
/// far better outcome than losing the history.
pub fn parse(stdout: &str) -> Vec<Entry> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(rename = "__REALTIME_TIMESTAMP")]
        realtime: Option<String>,
        #[serde(rename = "__MONOTONIC_TIMESTAMP")]
        monotonic: Option<String>,
        #[serde(rename = "_BOOT_ID")]
        boot_id: Option<String>,
    }

    stdout
        .lines()
        .filter_map(|line| {
            let raw: Raw = serde_json::from_str(line).ok()?;
            Some(Entry {
                realtime_micros: raw.realtime?.parse().ok()?,
                monotonic_micros: raw.monotonic?.parse().ok()?,
                boot_id: raw.boot_id?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "4f2e1c9a8b7d6e5f4a3b2c1d0e9f8a7b";
    const DASHED: &str = "4f2e1c9a-8b7d-6e5f-4a3b-2c1d0e9f8a7b";
    /// 2026-08-06T10:00:00Z in microseconds.
    const WALL_US: i64 = 1_785_924_000_000_000;

    fn entry(monotonic_us: i64, realtime_us: i64) -> Entry {
        Entry { realtime_micros: realtime_us, monotonic_micros: monotonic_us, boot_id: BOOT.into() }
    }

    /// The two spellings of a boot id. Getting this wrong matches nothing and looks identical to
    /// an empty journal.
    #[test]
    fn boot_ids_match_across_the_dashed_and_bare_spellings() {
        assert!(same_boot(BOOT, DASHED));
        assert!(same_boot(BOOT, BOOT));
        assert!(same_boot(&BOOT.to_uppercase(), DASHED));
        assert!(!same_boot(BOOT, "0000000000000000000000000000000f"));
        assert!(!same_boot("", DASHED), "an absent id must not match everything");
    }

    #[test]
    fn a_steady_clock_yields_one_epoch_dated_to_boot() {
        let entries: Vec<_> =
            (1..=5).map(|i| entry(i * 1_000_000, WALL_US + i * 1_000_000)).collect();
        let out = epochs(&entries, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].boot_start, 0, "the first epoch must reach back to boot");
        assert_eq!(out[0].offset, WALL_US * 1_000, "realtime - boottime, both at 1 s");
        assert_eq!(out[0].source, Source::Journal);
    }

    /// The cold-boot shape: the clock sits days in the past, then a daemon steps it.
    #[test]
    fn a_step_opens_a_second_epoch() {
        let stale = WALL_US - 3 * 86_400 * 1_000_000;
        let entries = vec![
            entry(1_000_000, stale + 1_000_000),
            entry(2_000_000, stale + 2_000_000),
            // The step lands between 2 s and 3 s of monotonic.
            entry(3_000_000, WALL_US + 3_000_000),
            entry(4_000_000, WALL_US + 4_000_000),
        ];
        let out = epochs(&entries, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS);

        assert_eq!(out.len(), 2, "expected exactly one boundary: {out:?}");
        assert_eq!(out[0].offset, stale * 1_000);
        // Dated to the last old-offset entry, so a record from just after the real step still
        // falls inside the new epoch.
        assert_eq!(out[1].boot_start, 2_000_000_000);
        assert_eq!(out[1].offset, WALL_US * 1_000);
    }

    /// Slewing is not stepping. At 500 ppm a minute of wall time moves the offset 30 ms, which
    /// must not manufacture an epoch boundary per journal entry.
    #[test]
    fn slew_within_the_threshold_does_not_open_an_epoch() {
        // 10 ms of drift accumulated over four entries.
        let entries: Vec<_> = (1..=4)
            .map(|i| entry(i * 10_000_000, WALL_US + i * 10_000_000 + i * 2_500))
            .collect();
        let out = epochs(&entries, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS);
        assert_eq!(out.len(), 1, "slew was mistaken for steps: {out:?}");
    }

    /// Entries from a previous boot carry meaningless monotonic values and must not contribute.
    #[test]
    fn entries_from_another_boot_are_ignored() {
        let mut entries = vec![entry(1_000_000, WALL_US + 1_000_000)];
        entries.push(Entry {
            boot_id: "ffffffffffffffffffffffffffffffff".into(),
            ..entry(500_000, WALL_US - 99 * 86_400 * 1_000_000)
        });
        let out = epochs(&entries, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset, WALL_US * 1_000);
    }

    #[test]
    fn an_empty_journal_yields_no_history_rather_than_a_fabricated_epoch() {
        assert!(epochs(&[], DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS).is_empty());
        let foreign = vec![Entry { boot_id: "aa".into(), ..entry(1, 2) }];
        assert!(epochs(&foreign, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS).is_empty());
    }

    /// The normalization the design calls out: journald's monotonic field is `CLOCK_MONOTONIC`,
    /// and the epoch table is in `CLOCK_BOOTTIME`. Skipping it skews every imported offset by the
    /// total suspend time — silently, and in the same direction for all of them.
    #[test]
    fn suspend_time_shifts_the_imported_frame() {
        let entries = vec![entry(1_000_000, WALL_US + 1_000_000)];
        let suspended = 90 * 1_000_000_000; // a minute and a half asleep

        let naive = epochs(&entries, DASHED, 0, DEFAULT_STEP_THRESHOLD_NANOS)[0].offset;
        let corrected = epochs(&entries, DASHED, suspended, DEFAULT_STEP_THRESHOLD_NANOS)[0].offset;
        assert_eq!(naive - corrected, suspended);
    }

    #[test]
    fn parses_journalctl_json_and_skips_unusable_lines() {
        let stdout = format!(
            r#"{{"__REALTIME_TIMESTAMP":"{WALL_US}","__MONOTONIC_TIMESTAMP":"1000000","_BOOT_ID":"{BOOT}","MESSAGE":"hi"}}
not json at all
{{"__REALTIME_TIMESTAMP":"{WALL_US}","_BOOT_ID":"{BOOT}"}}
{{"__REALTIME_TIMESTAMP":"nope","__MONOTONIC_TIMESTAMP":"2000000","_BOOT_ID":"{BOOT}"}}
{{"__REALTIME_TIMESTAMP":"{WALL_US}","__MONOTONIC_TIMESTAMP":"2000000","_BOOT_ID":"{BOOT}"}}
"#
        );
        let entries = parse(&stdout);
        assert_eq!(entries.len(), 2, "expected the two complete lines: {entries:?}");
        assert_eq!(entries[0].monotonic_micros, 1_000_000);
        assert_eq!(entries[1].monotonic_micros, 2_000_000);
        assert_eq!(entries[0].boot_id, BOOT);
    }

    #[test]
    fn parsing_empty_output_is_not_an_error() {
        assert!(parse("").is_empty());
        assert!(parse("\n\n").is_empty());
    }

    /// The invocation itself, with a stand-in for `journalctl`. Covers the pieces `parse` cannot:
    /// that stdout is actually read, and that a successful run with output yields entries.
    #[test]
    fn reads_and_parses_a_commands_output() {
        let line = format!(
            r#"{{"__REALTIME_TIMESTAMP":"{WALL_US}","__MONOTONIC_TIMESTAMP":"1000000","_BOOT_ID":"{BOOT}"}}"#
        );
        let entries = read_with("printf", &["%s\\n", &line]).expect("the fixture command runs");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].monotonic_micros, 1_000_000);
        assert_eq!(entries[0].boot_id, BOOT);
    }

    /// A journal that yields nothing is not a failure — it is the `Storage=volatile` case §4.2
    /// calls a soft dependency, and it has to degrade to "no history" rather than to an error.
    #[test]
    fn a_command_with_no_output_yields_no_entries() {
        assert!(read_with("true", &[]).expect("a successful empty run").is_empty());
    }

    /// A failing backfill must report itself. The realistic cause is a missing systemd-journal
    /// group, which journalctl explains on stderr — so the message has to carry stderr, not just
    /// the exit status.
    #[test]
    fn a_failing_command_is_an_error_carrying_its_stderr() {
        let err = read_with("sh", &["-c", "echo 'Failed to open files: Permission denied' >&2; exit 1"])
            .expect_err("a non-zero exit must not look like an empty journal");
        let message = err.to_string();

        assert!(message.contains("exit"), "the status should be reported: {message}");
        assert!(
            message.contains("Permission denied"),
            "stderr is the only thing that names the cause: {message}"
        );
    }

    /// A journalctl that is not installed at all — plausible on a minimal image — is an error
    /// rather than a panic, so startup degrades instead of dying.
    #[test]
    fn a_missing_program_is_an_error_not_a_panic() {
        let err = read_with("definitely-not-a-real-program-9f2e", &[]).unwrap_err();
        assert!(
            err.to_string().contains("definitely-not-a-real-program-9f2e"),
            "the program should be named: {err}"
        );
    }

    /// The production invocation, checked against what it has to produce: JSON, this boot only,
    /// and `_BOOT_ID` present. Dropping `--output-fields=_BOOT_ID` in particular would leave
    /// `same_boot` matching nothing, which looks exactly like an empty journal.
    #[test]
    fn the_production_invocation_asks_for_what_the_parser_needs() {
        let (program, args) = JOURNALCTL;
        assert_eq!(program, "journalctl");
        assert!(args.contains(&"--output=json"), "{args:?}");
        assert!(args.contains(&"--boot"), "another boot's entries are useless here: {args:?}");
        assert!(args.contains(&"--output-fields=_BOOT_ID"), "{args:?}");
        assert!(args.contains(&"--no-pager"), "a pager would hang the startup path: {args:?}");
    }
}
