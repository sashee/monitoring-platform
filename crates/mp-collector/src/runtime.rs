//! The two long-lived tasks, and the handle the HTTP layer talks to them through.
//!
//! - [`clock_task`] owns the epoch table and the sync decision. It is the only writer.
//! - [`flush_task`] owns the buffer, the spool and the forwarder. It is the only writer of those.
//!
//! Single-owner-per-thing, with `watch` for broadcast and `mpsc` for handoff, so there is no lock
//! anywhere and no state two tasks can disagree about. `watch` carries a *snapshot*: a reader gets
//! a consistent table and sync verdict together, never a table from one instant paired with a
//! verdict from another.

use anyhow::{Context, Result};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

use crate::buffer::{Buffer, Decision, Limits, Pending, decide};
use crate::config::{ApiKey, Config};
use crate::correct::{Correction, Flush, Tally, apply_correction};
use crate::epoch::{Epoch, EpochTable, Source};
use crate::forward::Forwarder;
use crate::metrics::{self, Health};
use crate::retry::backoff;
use crate::spool::Spool;
use crate::state;
use crate::stepwatch::StepWatch;
use crate::sync::{self, SyncSource};

/// Everything the rest of the collector needs to know about the clock, as one consistent snapshot.
#[derive(Clone, Debug)]
pub struct ClockState {
    pub table: EpochTable,
    /// `Some` when the clock is trustworthy right now, and which condition said so.
    pub sync_source: Option<SyncSource>,
    /// Whether it has *ever* been trustworthy this boot. Sticky, and the reason §8.2 works: a
    /// later loss of discipline must not re-arm the buffer.
    pub ever_synchronized: bool,
    pub steps: u64,
    /// `CLOCK_BOOTTIME` of the last observed step, for the §9 metric.
    pub last_step: Option<i64>,
    pub max_error_micros: i64,
    /// Whether anything is disciplining the clock at all — the §9 bullet that turns "every
    /// timestamp is three days old" into "no time daemon has ever run here".
    pub disciplined: bool,
}

/// Counters the health endpoint and the self-metrics read.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub buffered_records: u64,
    pub buffered_batches: u64,
    pub oldest_age: Duration,
    pub exact: u64,
    pub ambiguous: u64,
    pub passthrough: u64,
    pub authoritative: u64,
    pub forwarded_batches: u64,
    pub shed_batches: u64,
}

/// What `/healthz` reports.
#[derive(Debug)]
pub struct Status {
    pub synchronized: bool,
    pub ever_synchronized: bool,
    /// Whether *anything* is disciplining the clock. Weaker than `synchronized`, and exposed
    /// separately because it is the signal that separates "no time daemon is running on this
    /// device" from "the network is down" — and because it is readable before the collector has
    /// ever synchronized, which is when the §9 health events do not yet exist to carry it.
    pub disciplined: bool,
    pub sync_source: Option<SyncSource>,
    pub epochs: usize,
    pub steps: u64,
    pub buffered_records: u64,
}

/// The HTTP layer's view of the tasks. Cheap to clone: two watch receivers and a channel sender.
#[derive(Clone)]
pub struct Handle {
    clock: watch::Receiver<ClockState>,
    stats: watch::Receiver<Stats>,
    inbox: mpsc::Sender<Pending>,
}

impl Handle {
    /// The epoch table as it stands. Cloned rather than borrowed: holding a `watch` read guard
    /// across frame resolution would block the clock task from recording a step for as long as a
    /// large batch takes to resolve.
    pub fn table(&self) -> EpochTable {
        self.clock.borrow().table.clone()
    }

    pub fn status(&self) -> Status {
        let clock = self.clock.borrow();
        Status {
            synchronized: clock.sync_source.is_some(),
            ever_synchronized: clock.ever_synchronized,
            disciplined: clock.disciplined,
            sync_source: clock.sync_source,
            epochs: clock.table.len(),
            steps: clock.steps,
            buffered_records: self.stats.borrow().buffered_records,
        }
    }

    pub fn stats(&self) -> Stats {
        *self.stats.borrow()
    }

    /// Hands a resolved batch to the flush task.
    ///
    /// `try_send`, not `send`: a full channel means the flush task is wedged, and blocking the
    /// HTTP handler would turn that into an application stalling on its own telemetry. A 503 lets
    /// the SDK retry, which is what its retry policy is for.
    pub fn accept(
        &self,
        request: ExportLogsServiceRequest,
        bytes: usize,
        received: i64,
        tally: Tally,
    ) -> Result<()> {
        self.inbox
            .try_send(Pending { request, bytes, queued_at: received, tally })
            .map_err(|_| anyhow::anyhow!("the collector's flush queue is full"))?;
        Ok(())
    }
}

/// Builds the handle and the two task futures.
///
/// Returned rather than spawned so `main` decides the shutdown ordering, and so a test can drive
/// either task on its own.
pub fn build(config: Arc<Config>, boot_id: String) -> Result<(Handle, Tasks)> {
    let table = initial_table(&config, &boot_id)?;
    tracing::info!(epochs = table.len(), offset = table.current().offset, "offset history ready");

    let (clock_tx, clock_rx) = watch::channel(ClockState {
        table,
        sync_source: None,
        ever_synchronized: false,
        steps: 0,
        last_step: None,
        max_error_micros: 0,
        disciplined: false,
    });
    let (stats_tx, stats_rx) = watch::channel(Stats::default());
    // Deep enough to absorb a burst while a flush is in flight, shallow enough that a wedged
    // flush task surfaces as backpressure within a second rather than as unbounded memory.
    let (inbox_tx, inbox_rx) = mpsc::channel(1024);

    let handle = Handle { clock: clock_rx.clone(), stats: stats_rx, inbox: inbox_tx };
    let tasks = Tasks {
        clock: ClockTask { config: Arc::clone(&config), boot_id: boot_id.clone(), tx: clock_tx },
        flush: FlushTask { config, boot_id, rx: inbox_rx, clock: clock_rx, stats: stats_tx },
    };
    Ok((handle, tasks))
}

pub struct Tasks {
    pub clock: ClockTask,
    pub flush: FlushTask,
}

/// Which source supplied the starting history.
///
/// Returned rather than only logged: when a device is not correcting timestamps, "where did the
/// history come from" is the first question, and `Journal` versus `Startup` is the difference
/// between "the backfill worked and found one epoch" and "the backfill found nothing and this
/// collector knows only what it has seen since it started".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Resumed from disk — a collector restart within one boot.
    Persisted,
    /// Reconstructed from journald (§4.2).
    Journal,
    /// Neither was available; only the collector's own first reading.
    Startup,
}

/// The precedence chain, pure. Persisted history wins, then journald's, then nothing.
///
/// The live reading is appended in **all three** cases, and that is the load-bearing part: a step
/// during the collector's own downtime is exactly the gap a persisted table cannot know about, and
/// journald's reconstruction stops wherever its last entry is.
pub fn choose_initial_table(
    persisted: Option<EpochTable>,
    backfilled: Vec<Epoch>,
    now: mp_host::clock::Sample,
) -> (EpochTable, Origin) {
    let live = Epoch { boot_start: now.boottime, offset: now.offset(), source: Source::Startup };

    if let Some(table) = persisted {
        return (table.with(live), Origin::Persisted);
    }
    if let Some(table) = EpochTable::from_epochs(backfilled) {
        return (table.with(live), Origin::Journal);
    }
    // `boot_start: 0` rather than `now.boottime`: with no history at all, the only useful
    // assumption is that this offset has held since boot. Dating it later would leave every
    // record from before the collector started with no epoch to fall in.
    (EpochTable::new(Epoch { boot_start: 0, ..live }), Origin::Startup)
}

/// Gathers the three inputs and hands them to [`choose_initial_table`].
fn initial_table(config: &Config, boot_id: &str) -> Result<EpochTable> {
    let now = mp_host::clock::sample().context("sampling the clocks at startup")?;
    let persisted = state::load(&config.epochs_path(), boot_id);

    let backfilled = match (persisted.is_some(), config.journal_backfill) {
        // No point running journalctl when the answer is already on disk.
        (true, _) | (false, false) => Vec::new(),
        (false, true) => backfill(config, boot_id).unwrap_or_else(|e| {
            // §4.2 is explicit that this is a soft dependency: degrade to no history rather than
            // failing to start, which would strand a device whose journal is volatile.
            tracing::warn!(error = %e, "journal backfill failed; continuing without history");
            Vec::new()
        }),
    };

    let (table, origin) = choose_initial_table(persisted, backfilled, now);
    match origin {
        Origin::Persisted => tracing::info!(epochs = table.len(), "resumed offset history from disk"),
        Origin::Journal => {
            tracing::info!(epochs = table.len(), "reconstructed offset history from journald");
        }
        Origin::Startup => tracing::info!("no prior offset history; starting from this reading"),
    }
    Ok(table)
}

/// Blocking, and deliberately left that way: it runs once, before readiness is signalled, and
/// occupies one runtime worker for as long as `journalctl` takes to dump a boot. Moving it to
/// `spawn_blocking` would buy nothing — there is nothing else to overlap it with, since no socket
/// is being served yet.
fn backfill(config: &Config, boot_id: &str) -> Result<Vec<Epoch>> {
    let entries = crate::journal::read_this_boot()?;
    let suspended = mp_host::clock::suspended_nanos().context("reading the suspend offset")?;
    Ok(crate::journal::epochs(
        &entries,
        boot_id,
        suspended,
        config.journal_step_threshold_nanos,
    ))
}

/// Once the clock is good, the 1 Hz poll only runs every this many ticks.
const SETTLED_POLL_TICKS: u64 = 60;

/// Everything the flush task owns and mutates, in one place.
///
/// Grouped rather than threaded through as six `&mut` parameters — not only for the argument
/// count, but because these six are one thing: the state of "what is in hand and how delivery is
/// going". Nothing outside this task ever sees it.
struct InFlight {
    buffer: Buffer,
    spool: Spool,
    /// Corrected batches awaiting delivery. Durable retry toward the server is out of scope
    /// (design §3), so this is bounded and sheds the oldest with a loud counter rather than
    /// growing without limit while the receiver is down.
    outbox: VecDeque<ExportLogsServiceRequest>,
    totals: Stats,
    /// When the current hold began, for the timeout. `None` when nothing is held.
    holding_since: Option<i64>,
    /// Consecutive failed delivery attempts. Drives the backoff, and doubles as the "are we
    /// currently failing" flag so the log records *transitions* rather than one line per retry — a
    /// receiver down for an hour would otherwise bury whatever else went wrong under thousands of
    /// identical warnings.
    failures: u32,
    /// `CLOCK_BOOTTIME` before which there is no point attempting delivery again. `None` when
    /// delivery is healthy.
    retry_at: Option<i64>,
    /// Whether the spool might hold anything.
    ///
    /// Without this the steady state costs two `read_dir` calls per flush cycle — twice a second,
    /// forever, on a device whose storage is an SD card — to discover an empty directory. Starts
    /// `true` so the first cycle does look, which is what finds a previous boot's leftovers.
    spool_dirty: bool,
}

/// Watches the clock: steps, and whether it can be trusted yet.
pub struct ClockTask {
    config: Arc<Config>,
    boot_id: String,
    tx: watch::Sender<ClockState>,
}

impl ClockTask {
    pub async fn run(self) -> Result<()> {
        let watch_fd = StepWatch::new().context("setting up live step detection")?;
        let mut streak = 0u32;
        let mut ticks = 0u64;

        // ONE interval, ticking at 1 Hz for the life of the task. Backing off by replacing it
        // with a slower one looks obvious and is a hot loop: `tokio::time::interval` fires its
        // first tick immediately, so a replacement built inside the loop is instantly ready, the
        // select wakes, builds another, and the task spins at full tilt — on a device whose whole
        // problem is that it is small and battery-adjacent. Backing off by *skipping* ticks has
        // no such edge.
        let mut poll = tokio::time::interval(Duration::from_secs(1));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                stepped = watch_fd.stepped() => {
                    stepped?;
                    self.on_step()?;
                    // The first correction on a clockless Pi usually exceeds chrony's `makestep`
                    // threshold and arrives as a step, so checking here is what resolves the
                    // common case without waiting for the next poll.
                    streak = self.on_poll(streak)?;
                }
                _ = poll.tick() => {
                    ticks += 1;
                    // 1 Hz until the clock is good, then once a minute. It never stops entirely:
                    // the offset consistency check rides on this tick, and it is what catches a
                    // boundary the step watch missed.
                    if !self.tx.borrow().ever_synchronized || ticks.is_multiple_of(SETTLED_POLL_TICKS) {
                        streak = self.on_poll(streak)?;
                    }
                }
            }
        }
    }

    fn on_step(&self) -> Result<()> {
        let now = mp_host::clock::sample().context("sampling the clocks after a step")?;
        self.tx.send_modify(|state| {
            state.steps += 1;
            state.last_step = Some(now.boottime);
            state.table = state.table.with(Epoch {
                boot_start: now.boottime,
                offset: now.offset(),
                source: Source::Step,
            });
        });
        let table = self.tx.borrow().table.clone();
        tracing::info!(
            offset = now.offset(),
            boottime = now.boottime,
            epochs = table.len(),
            "clock stepped"
        );
        self.persist(&table);
        Ok(())
    }

    fn on_poll(&self, streak: u32) -> Result<u32> {
        let reading = sync::read().context("reading the kernel clock state")?;
        let poll = sync::evaluate(
            reading,
            self.config.clock_threshold_micros,
            self.config.clock_consecutive,
            streak,
        );

        // A boundary the step watch did not report — a step during the collector's own downtime,
        // or a timerfd that failed to re-arm. Slewing cannot move this quantity, so any
        // disagreement at all is a genuine discontinuity.
        let now = mp_host::clock::sample().context("sampling the clocks")?;
        let missed = self
            .tx
            .borrow()
            .table
            .disagrees_with(now.offset(), self.config.resync_threshold_nanos);

        let was_synchronized = self.tx.borrow().ever_synchronized;
        self.tx.send_modify(|state| {
            state.max_error_micros = reading.max_error_micros;
            state.disciplined = sync::is_disciplined(reading);
            state.sync_source = poll.source;
            state.ever_synchronized |= poll.released;
            if missed {
                state.table = state.table.with(Epoch {
                    boot_start: now.boottime,
                    offset: now.offset(),
                    source: Source::Resync,
                });
            }
        });

        if missed {
            tracing::warn!(
                offset = now.offset(),
                "the offset moved without a step notification; recording the boundary"
            );
            self.persist(&self.tx.borrow().table.clone());
        }
        if poll.released && !was_synchronized {
            tracing::info!(
                clock_error_us = reading.max_error_micros,
                source = poll.source.map(SyncSource::label),
                "clock synchronized; releasing the buffer"
            );
        } else if !poll.released {
            tracing::debug!(
                clock_error_us = reading.max_error_micros,
                good_streak = poll.streak,
                "waiting for the clock"
            );
        }
        Ok(poll.streak)
    }

    /// Best-effort. Losing the persisted copy costs history across a restart, which is worth a
    /// warning; failing the task over it would cost the running collector, which is worse.
    fn persist(&self, table: &EpochTable) {
        if let Err(e) = state::save(&self.config.epochs_path(), &self.boot_id, table) {
            tracing::warn!(error = %e, "could not persist the epoch table");
        }
    }
}

/// Owns the buffer, the spool and the forwarder.
pub struct FlushTask {
    config: Arc<Config>,
    boot_id: String,
    rx: mpsc::Receiver<Pending>,
    clock: watch::Receiver<ClockState>,
    stats: watch::Sender<Stats>,
}

impl FlushTask {
    pub async fn run(mut self) -> Result<()> {
        let limits = Limits {
            max_records: self.config.buffer_max_records,
            max_bytes: self.config.buffer_max_bytes,
        };
        let mut forwarder = Forwarder::new(
            self.config.target.clone(),
            self.config.forward_timeout,
            self.config.api_key.as_ref().map(ApiKey::as_str),
        );
        let mut state = InFlight {
            buffer: Buffer::new(limits),
            spool: Spool::open(&self.config.spool_dir(), &self.boot_id)
                .context("opening the spool directory")?,
            outbox: VecDeque::new(),
            totals: Stats::default(),
            holding_since: None,
            failures: 0,
            retry_at: None,
            spool_dirty: true,
        };

        let mut tick = tokio::time::interval(self.config.grace);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Emitted only once the clock is good, so the health event never needs correcting itself.
        // When switched off the interval is parked at an hour and the arm is guarded, rather than
        // built from a zero duration — which `tokio::time::interval` rejects outright.
        let emit_health = self.config.health_interval.is_some();
        let mut health = tokio::time::interval(
            self.config.health_interval.unwrap_or(Duration::from_secs(3600)),
        );
        health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        health.tick().await; // the first tick is immediate; nothing to report yet

        loop {
            tokio::select! {
                received = self.rx.recv() => {
                    let Some(pending) = received else { break };
                    // Counted here rather than at flush: a batch that gets spilled to disk loses
                    // its tally on the way, and these counters must not depend on memory pressure.
                    state.totals.exact += pending.tally.exact;
                    state.totals.ambiguous += pending.tally.ambiguous;
                    state.totals.passthrough += pending.tally.passthrough;
                    state.totals.authoritative += pending.tally.authoritative;
                    state.holding_since.get_or_insert(pending.queued_at);
                    for spilled in state.buffer.push(pending) {
                        state.spool_dirty = true;
                        if let Err(e) = state.spool.write(&spilled) {
                            tracing::error!(error = %e, "could not spill a batch to disk");
                        }
                    }
                }
                _ = tick.tick() => {}
                _ = health.tick(), if emit_health => self.emit_health(&mut state),
                // A step or a sync verdict is worth acting on immediately rather than waiting out
                // the grace period: this is what makes a correction land promptly after NTP.
                changed = self.clock.changed() => {
                    if changed.is_err() { break }
                }
            }

            self.cycle(&mut state, &mut forwarder).await;
        }

        // Drain on shutdown, so a stop does not strand whatever is in hand. The backoff is cleared
        // first: there is no next cycle to wait for, so a pending retry deadline would skip the one
        // remaining attempt and strand exactly the batches this drain exists to deliver.
        state.retry_at = None;
        self.cycle(&mut state, &mut forwarder).await;
        Ok(())
    }

    /// Builds the §9 health event and queues it like any other batch.
    ///
    /// Queued rather than sent directly so it goes through the same forwarding, retry and
    /// ordering as everything else — a self-metric on a separate path would be the one thing
    /// still working when the real path is broken, which is precisely backwards.
    fn emit_health(&self, state: &mut InFlight) {
        let clock = self.clock.borrow().clone();
        if !clock.ever_synchronized {
            return;
        }
        let Ok(now) = mp_host::clock::sample() else { return };

        state.outbox.push_back(metrics::to_request(
            Health {
                max_error_micros: clock.max_error_micros,
                since_last_step: clock.last_step.map(|at| {
                    Duration::from_nanos(now.boottime.saturating_sub(at).max(0) as u64)
                }),
                steps: clock.steps,
                disciplined: clock.disciplined,
                epochs: clock.table.len() as u64,
                resolved_exact: state.totals.exact,
                resolved_ambiguous: state.totals.ambiguous,
                resolved_passthrough: state.totals.passthrough,
                resolved_authoritative: state.totals.authoritative,
                buffered_records: state.buffer.depth(),
                oldest_buffered: state.buffer.oldest_age(now.boottime).unwrap_or_default(),
                forwarded_batches: state.totals.forwarded_batches,
                shed_batches: state.totals.shed_batches,
            },
            now.realtime,
            &self.boot_id,
        ));
    }

    async fn cycle(&self, state: &mut InFlight, forwarder: &mut Forwarder) {
        let now = mp_host::clock::now_boottime().unwrap_or(0);
        let clock = self.clock.borrow().clone();
        let waited = state
            .holding_since
            .map(|since| Duration::from_nanos(now.saturating_sub(since).max(0) as u64))
            .unwrap_or_default();

        let decision = decide(
            clock.sync_source.is_some(),
            clock.ever_synchronized,
            waited,
            self.config.buffer_timeout,
        );

        // Nothing in memory and nothing on disk means nothing to correct, and the check for
        // "nothing on disk" is itself the disk access worth avoiding.
        if decision != Decision::Hold && (!state.buffer.is_empty() || state.spool_dirty) {
            self.correct_into_outbox(state, &clock, decision);
            state.holding_since = None;
        }

        self.deliver(forwarder, state, now).await;

        let _ = self.stats.send(Stats {
            buffered_records: state.buffer.depth(),
            buffered_batches: state.outbox.len() as u64,
            oldest_age: state.buffer.oldest_age(now).unwrap_or_default(),
            ..state.totals
        });
    }

    /// Applies one frozen offset to everything in hand and moves it to the outbox.
    fn correct_into_outbox(&self, state: &mut InFlight, clock: &ClockState, decision: Decision) {
        let uncertain = decision == Decision::FlushUncertain;

        // **The active epoch's offset, not a fresh sample.** The design doc's §6.2 says the
        // opposite, on the grounds that a stored offset goes stale under slew. It does not: both
        // clocks are slewed by the same frequency adjustment, so `realtime − boottime` is
        // untouched by slewing and moves only on a step, which opens a new epoch. Two properties
        // follow, and both are lost by re-sampling:
        //
        // - **resolve and project are exact inverses.** A record that resolved in the epoch still
        //   in force comes out with the timestamp it went in with, to the nanosecond, instead of
        //   being perturbed by the jitter between two independent clock reads.
        // - **two deliveries of one batch are identical.** The receiver's measurement id is a
        //   content hash over `event_time` and the attributes (SPEC.md §6.6), and
        //   `mp.clock.correction_ns` is one of those attributes. A re-sampled offset differs by a
        //   nanosecond or two between deliveries, changes the hash, and turns an application's
        //   ordinary retry into a duplicate row — defeating the deduplication entirely.
        let correction = (!uncertain).then(|| Correction { offset: clock.table.current().offset });

        let flush = Flush { uncertain, sync_source: clock.sync_source };

        // Spool first: those batches arrived earliest, so shipping them first preserves order.
        let spooled = state.spool.read_all().unwrap_or_else(|e| {
            tracing::error!(error = %e, "could not read the spool");
            Vec::new()
        });
        for mut entry in spooled {
            // A previous boot's batches carry boottimes that describe a machine which no longer
            // exists (§8.4), so there is nothing to project them with.
            let same_boot = entry.same_boot;
            let usable = if same_boot { correction } else { None };
            let mut request = entry.take_request();
            apply_correction(
                &mut request,
                usable,
                Flush { uncertain: uncertain || !same_boot, ..flush },
            );
            state.outbox.push_back(request);
            entry.remove();
        }

        for pending in state.buffer.drain() {
            let mut request = pending.request;
            apply_correction(&mut request, correction, flush);
            state.outbox.push_back(request);
        }

        if let Err(e) = state.spool.retire_other_boots() {
            tracing::warn!(error = %e, "could not retire a previous boot's spool");
        }
        // Everything on disk has been read and removed, so the next idle cycle can skip the scan
        // until something is spilled again.
        state.spool_dirty = false;

        // The bound. Shedding is counted and logged, never silent.
        while state.outbox.len() > self.config.buffer_max_records {
            state.outbox.pop_front();
            state.totals.shed_batches += 1;
        }
        if state.totals.shed_batches > 0 {
            tracing::error!(
                shed = state.totals.shed_batches,
                "the outbox is full and the receiver is not accepting; batches are being dropped"
            );
        }
    }

    async fn deliver(&self, forwarder: &mut Forwarder, state: &mut InFlight, now: i64) {
        // A failing target is retried on a backoff rather than on every cycle, and this early
        // return is what makes the send timeout worth having. `cycle` runs once per *received*
        // batch, so without it every arrival would pay the full timeout before the task got back to
        // reading its inbox; the inbox would fill, and the HTTP layer would answer 503 — an
        // application stalling on its own telemetry, which is what the buffer exists to prevent.
        if state.retry_at.is_some_and(|at| now < at) {
            return;
        }

        while let Some(request) = state.outbox.front() {
            match forwarder.send(request).await {
                Ok(()) => {
                    state.outbox.pop_front();
                    state.totals.forwarded_batches += 1;
                    state.retry_at = None;
                    if std::mem::take(&mut state.failures) > 0 {
                        tracing::info!(
                            delivered = state.totals.forwarded_batches,
                            "forwarding recovered"
                        );
                    }
                }
                Err(e) => {
                    // Left at the front, unmodified. Retrying it verbatim is safe because the
                    // correction is already baked in and frozen, so the receiver sees the same
                    // content hash and deduplicates (SPEC.md §6.6).
                    let first = state.failures == 0;
                    state.failures = state.failures.saturating_add(1);

                    let wait = backoff(state.failures, self.config.grace, self.config.retry_max);
                    // `try_from` rather than `as`: a `retry_max` of absurd size would otherwise
                    // wrap into the past and defeat the backoff entirely.
                    let wait_nanos = i64::try_from(wait.as_nanos()).unwrap_or(i64::MAX);
                    state.retry_at = Some(now.saturating_add(wait_nanos));

                    if first {
                        tracing::warn!(error = %e, queued = state.outbox.len(), retry_in = ?wait, "forwarding failed; will retry");
                    } else {
                        tracing::debug!(error = %e, queued = state.outbox.len(), retry_in = ?wait, failures = state.failures, "forwarding still failing");
                    }
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp_host::clock::Sample;

    const SEC: i64 = 1_000_000_000;
    const WALL: i64 = 1_785_924_000 * SEC;

    /// The collector's own reading at startup: boottime 100 s, and a correct offset.
    fn now() -> Sample {
        Sample { realtime: WALL + 100 * SEC, boottime: 100 * SEC }
    }

    fn epoch(boot_start: i64, offset: i64, source: Source) -> Epoch {
        Epoch { boot_start, offset, source }
    }

    /// A restart within one boot. The persisted table is authoritative and journald is not even
    /// consulted — it could only re-derive what is already on disk, more slowly and less exactly.
    #[test]
    fn persisted_history_wins() {
        let persisted = EpochTable::new(epoch(0, WALL - 3 * 86_400 * SEC, Source::Journal));
        let ignored = vec![epoch(0, WALL - 999 * SEC, Source::Journal)];

        let (table, origin) = choose_initial_table(Some(persisted), ignored, now());

        assert_eq!(origin, Origin::Persisted);
        assert_eq!(table.epochs()[0].offset, WALL - 3 * 86_400 * SEC, "the journal's value leaked in");
    }

    /// First start of a boot: nothing on disk, so journald's reconstruction is the history.
    #[test]
    fn journald_is_used_when_there_is_nothing_on_disk() {
        let backfilled = vec![
            epoch(0, WALL - 3 * 86_400 * SEC, Source::Journal),
            epoch(30 * SEC, WALL, Source::Journal),
        ];

        let (table, origin) = choose_initial_table(None, backfilled, now());

        assert_eq!(origin, Origin::Journal);
        assert_eq!(table.epochs()[0].source, Source::Journal);
        assert_eq!(table.epochs()[0].offset, WALL - 3 * 86_400 * SEC);
    }

    /// Neither source available — a volatile journal, or `--journal-backfill false`. The collector
    /// still starts, knowing only what it can see.
    #[test]
    fn a_lone_reading_is_dated_to_boot_not_to_now() {
        let (table, origin) = choose_initial_table(None, Vec::new(), now());

        assert_eq!(origin, Origin::Startup);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.epochs()[0].boot_start, 0,
            "with no history, this offset has to be assumed to hold since boot — dating it at \
             `now` would leave every earlier record with no epoch to fall in"
        );
    }

    /// An empty backfill is not history. `Vec::new()` and "journald returned entries that folded
    /// to nothing" are the same case, and both fall through to the collector's own reading.
    #[test]
    fn an_empty_backfill_falls_through_to_startup() {
        assert_eq!(choose_initial_table(None, Vec::new(), now()).1, Origin::Startup);
    }

    /// The load-bearing part, in all three branches: the live reading is always appended. A step
    /// during the collector's own downtime is exactly the gap a persisted table cannot know about,
    /// and journald's reconstruction stops wherever its last entry happens to be.
    #[test]
    fn the_live_reading_is_appended_whatever_the_source() {
        let stale = WALL - 3 * 86_400 * SEC;
        let cases = [
            (Some(EpochTable::new(epoch(0, stale, Source::Journal))), Vec::new(), Origin::Persisted),
            (None, vec![epoch(0, stale, Source::Journal)], Origin::Journal),
        ];

        for (persisted, backfilled, expected) in cases {
            let (table, origin) = choose_initial_table(persisted, backfilled, now());

            assert_eq!(origin, expected);
            assert_eq!(
                table.current().offset,
                now().offset(),
                "{expected:?}: the collector's own reading must be the active epoch"
            );
            assert_eq!(table.current().boot_start, now().boottime);
            assert_eq!(table.len(), 2, "{expected:?}: the prior history must survive too");
        }
    }

    /// When the live reading agrees with the history, `with` collapses it — so a restart on an
    /// undisturbed clock does not grow the table by one epoch every time.
    #[test]
    fn a_restart_on_an_unchanged_clock_does_not_grow_the_table() {
        let persisted = EpochTable::new(epoch(0, now().offset(), Source::Journal));

        let (table, _) = choose_initial_table(Some(persisted), Vec::new(), now());
        assert_eq!(table.len(), 1);
    }
}
