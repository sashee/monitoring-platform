# Telemetry Collector: Retroactive Clock Correction

**Status:** Implemented as `crates/mp-collector`, deployed by `nix/collector-module.nix`.
**Scope:** On-host OTLP collector for Raspberry Pi (and similar RTC-less Linux hosts)

Section references from the code point here. Where building it changed the design, this document
has been corrected and the change is marked **[revised]** with the reason — the original reasoning
is kept where it explains why the answer is not obvious.

**Relationship to `SPEC.md`.** This is the device-side answer to `SPEC.md` §12's open question about
device clocks. It is also the strategic *inverse* of `SPEC.md` §9.4: the receiver fails closed on a
bad clock and refuses to start, while the collector never refuses and corrects afterwards. Both are
right for their own job, and they cannot be the same unit — §7 orders this one *before* the time
daemons, which is flatly incompatible with a gate that waits for them.

---

## 1. Problem

A central monitoring server ingests OTLP logs, metrics, and traces. OTLP timestamps
(`time_unix_nano`) are absolute nanoseconds since the Unix epoch. The protocol has no
representation for monotonic, boot-relative, or otherwise frame-qualified time.

A Raspberry Pi has no battery-backed RTC. At boot the system clock is restored from
`fake-hwclock` to approximately the last shutdown time, and remains wrong until a time
daemon corrects it — typically seconds after boot, but indefinitely if there is no network.

Any application that logs during that window stamps its records with a wrong wall-clock
time. Those records are otherwise valid and should not be lost or mis-dated.

### Goal

Applications remain unmodified. They read the system clock, produce ordinary OTLP, and
send it to a local collector. The collector is responsible for detecting incorrect
timestamps, identifying which clock frame they came from, and rewriting them once the
true time is known.

### Non-goals

- Correcting timestamps that did not originate from this host's clock.
- Sub-millisecond accuracy. Target is "correct to within the app→collector delay."
- Replacing NTP. A hardware RTC (e.g. DS3231, ~$5) removes most of this problem at the
  source and is recommended independently of this design.

---

## 2. Core insight

The collector and the instrumented applications run on the same kernel, so they share
both `CLOCK_REALTIME` and `CLOCK_BOOTTIME`. The relationship between them:

```
offset O = realtime − boottime
```

`O` is piecewise constant. It changes only when something steps the realtime clock. If the
collector maintains a history of `O` over time, then any wall-clock timestamp produced on this host
can be mapped back to a boottime value — a frame-invariant quantity — and later re-projected into
the corrected wall-clock frame.

**[revised] Slewing does not move `O`.** The original text said it "drifts slowly under NTP slewing
(bounded at 500 ppm)". It does not: `CLOCK_REALTIME` and `CLOCK_BOOTTIME` are driven by the same
timekeeper and receive the *same* frequency adjustment, so a slewed correction shifts both by an
equal amount and leaves their difference untouched. Only a discontinuity —`settimeofday`,
`clock_settime`, `ADJ_SETOFFSET`, resume-from-suspend — changes `O`, and every one of those calls
`clock_was_set()`, which is exactly what §4.3 detects.

Measured on a host under active NTP discipline (`maxerror` 258 ms, `STA_PLL` set), `O` held
constant to within ±500 ns over twelve seconds — the interleave between the two `clock_gettime`
calls and nothing else. This correction propagates to §4.3, §6.2 and §8.3 below, and it simplifies
all three.

**Boottime, not monotonic.** `CLOCK_MONOTONIC` stops during suspend; `CLOCK_BOOTTIME`
does not. Use `BOOTTIME` throughout. The difference between the two equals total time
suspended, which matters when importing journald values (§4.2).

---

## 3. Architecture

```
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │    app A    │   │    app B    │   │   nginx     │      unmodified OTLP SDKs
  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘      batch delay ≈ 0
         │                 │                 │
         └─────────────────┼─────────────────┘
                           ▼
              /run/mp-collector/mp-collector.sock  (systemd socket unit)
                           │
         ┌─────────────────┴──────────────────┐
         │            COLLECTOR               │
         │                                    │
         │  ingest ──► frame resolution ──►   │
         │                    │               │
         │  ┌─────────────────▼────────────┐  │
         │  │      offset epoch table      │  │
         │  │  ◄── journal backfill (§4.2) │  │
         │  │  ◄── timerfd steps  (§4.3)   │  │
         │  └──────────────────────────────┘  │
         │                    │               │
         │            buffer (pre-sync only)  │
         │                    │               │
         │            sync detect (§4.4)      │
         │                    │               │
         │            flush + rewrite         │
         └─────────────────┬──────────────────┘
                           ▼
                  central monitoring server
```

Credentials, retry, and batching toward the server also live in the collector. Those are
out of scope here — which is a real boundary, not a deferral: delivery retry is in-memory and
bounded, and the one place the collector can lose data is an outbox that fills while the receiver
is unreachable. That is counted and logged (§9), never silent.

Two tasks in the implementation, single-owner-per-thing so there is no lock and no state the two
can disagree about. `runtime::ClockTask` owns the epoch table and the sync verdict and is their
only writer; `runtime::FlushTask` owns the buffer, the spool and the forwarder. A `watch` channel
carries a *snapshot* between them, so a reader gets a table and a verdict from the same instant
rather than one of each from different ones.

---

## 4. Components

### 4.1 Offset epoch table

The central data structure. A list of intervals:

```rust
struct Epoch {
    boot_start: i64,   // boottime at which this offset became active
    offset:     i64,   // realtime − boottime, nanoseconds
    source:     enum { Journal, Step, Resync, Startup },
}
```

**[revised] no `boot_end`, and `i64` not `i128`.** An epoch ends where the next one begins and the
last one has not ended, so storing both ends is two facts for one boundary that can disagree.
`i64` nanoseconds spans ±292 years. `Resync` replaces `Timerfd` for boundaries found by the
periodic consistency check rather than by the watch — see §4.3.

Built once at startup from the journal, appended to live from the timerfd, and persisted
to disk keyed by `boot_id` so a collector restart does not lose history.

Epoch boundaries are fuzzy by the collector's wakeup latency — a step is learned about
slightly after it happens. A record landing near a seam may match two epochs or none;
see §5.2.

### 4.2 Journal backfill

At startup, scan `journalctl -b` output (or use the sd-journal API). Every entry carries
`__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`, and `_BOOT_ID`. Their difference gives
the offset at that moment. Discontinuities in the series are steps. journald runs from
very early boot, so this reconstructs offset history for the period before the collector
existed. Resolution is limited by log volume, but the stepping daemon logs its own step
(chrony and timesyncd both write a line), so transitions are usually bracketed tightly.

**Normalization required.** journald's monotonic field is `CLOCK_MONOTONIC`, not
`BOOTTIME`. Read both clocks once at collector startup, store the difference, and add it
when importing. Skipping this silently skews all imported history on any host that
suspends.

Read **monotonic first**, then boottime. The two reads are not atomic and the microsecond between
them advances both clocks, so the other order returns a *negative* suspend time on a host that has
never suspended — where the true answer is exactly zero. That is not a small error but a sign error
in a value added to every imported timestamp, and it is what the unit test for this catches.

One residual inaccuracy, accepted: a single startup-sampled difference is applied to *all* imported
entries, including any recorded before a suspend earlier in the same boot. Irrelevant on the
target host, which does not suspend; the alternative is per-entry suspend accounting the journal
does not carry.

**Soft dependency.** If applications are ordered after the collector (§7), the
pre-collector window contains no application-generated events and the backfill finds
nothing relevant. It matters only for processes outside the unit ordering — manually
launched binaries, containers. If journald is unavailable or `Storage=volatile` wiped it,
degrade to passing old records through uncorrected rather than failing.

### 4.3 Live step detection

`timerfd` with `TFD_TIMER_CANCEL_ON_SET`. Create against `CLOCK_REALTIME`, arm far in the
future with that flag; when anything steps the clock, the kernel cancels the timer and
`read()` fails with `ECANCELED`. The timer expiry itself is irrelevant — the cancellation
is the notification.

`INT64_MAX` seconds is accepted rather than rejected — `timerfd_settime` validates with the
non-strict `timespec64_valid`, and `ktime_set()` saturates at `KTIME_MAX` — but mirror systemd's
`time_change_fd()` and fall back to `INT32_MAX` on failure, for kernels without 64-bit time
support. A watch that silently failed to arm looks exactly like a clock that never gets stepped.

```c
int fd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);
struct itimerspec ts = { .it_value = { .tv_sec = INT64_MAX } };
timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &ts, NULL);

// in the epoll loop, on readable:
uint64_t n;
if (read(fd, &n, sizeof n) < 0 && errno == ECANCELED) {
    sample_both_clocks();     // closes old epoch, opens new one
    check_sync_state();       // §4.4
    rearm(fd);                // MANDATORY
}
```

Two constraints: **re-arm after every cancellation**, or only the first step is ever seen.
And this fires on steps only — chrony slews corrections under one second (`makestep`
threshold), which produces no notification.

**[revised] Slew needs no handling at all.** The original text deferred it to §6.2. Per §2, slewing
moves both clocks together and leaves the offset unchanged, so there is nothing to detect and
nothing to correct for. What the implementation adds instead is a **consistency check**, not slew
tracking: the 1 Hz poll of §4.4 also samples `realtime − boottime` and compares it against the
active epoch. Since slew cannot move that quantity, *any* disagreement beyond 200 ms is a genuine
discontinuity the watch missed — a `timerfd` that failed to re-arm, or a step landing in the
microseconds between a cancellation being read and the watch being armed again. Such a boundary is
recorded with `source: Resync`.

**`Resync` is near-unreachable by construction, and is tested accordingly.** `clock_was_set()`
fires for every offset change and the watch is re-armed before `stepped()` returns, so there is no
ordinary path to it. The case that looks like one — a step while the collector is *down* — does not
produce it either: startup appends the live reading to whatever history it loaded, so the boundary
is recorded as `Startup`. It is therefore covered by unit tests on the threshold rule
(`epoch::disagrees_with`) and deliberately not chased in a VM, where any scenario contrived enough
to force it would be testing the contrivance.

### 4.4 Sync detection

Determining "is the clock now trustworthy" is the least clean part of this design. Three
candidate signals, in preference order.

**`maxerror` from `adjtimex()` — primary.**

The kernel grows `maxerror` by the frequency tolerance (500 ppm) each second and
initializes it at the 16-second phase limit. Only a daemon calling `ntp_adjtime()` with
`ADJ_MAXERROR` resets it. Verified behavior as of this writing:

| Daemon | Sets maxerror | Value written |
|---|---|---|
| chrony | Yes — `sys_timex.c`, `set_sync_status()` | `root_delay/2 + root_dispersion` (true root distance); pinned to 16.0 s when unsynchronized |
| systemd-timesyncd | Yes — `timesyncd-manager.c`, `manager_adjust_clock()` | **Zero** (`ADJ_MAXERROR` set in modes, field never assigned). Carries recency only, not accuracy |
| ntpd-rs | Yes — `error_estimate_update()` from the Kalman filter | `root_delay` |

Critically, **chrony writes maxerror regardless of the `rtcsync` setting**. The
`if (!CNF_GetRtcSync()) synchronised = 0;` guard in `set_sync_status()` is applied after
`max_error` is computed and affects only the `STA_UNSYNC` status bit. This is why
maxerror is preferred over the status flag.

**`STA_UNSYNC` from `adjtimex()` — secondary, hazardous.**

Note this reverses a decision the receiver made deliberately: `SPEC.md` §9.4 and
`monitoring_platform::clock` ignore this bit entirely. The asymmetry is in the cost of being wrong.
The receiver's gate refuses to *start a service*, so a false "synchronized" there admits silently
bad rows forever; the collector's worst case is flushing a few seconds early with
`mp.clock.sync_source` recording exactly which condition fired.

chrony clears this flag *only* when `rtcsync` is enabled, because clearing it is what
activates the kernel's 11-minute RTC-write mode. `rtcsync` conflicts with `rtcfile`, and
a Pi with a DS3231 plausibly wants `rtcfile` — in which case chrony is fully synchronized
and the flag still reads unsynchronized, indefinitely. This is the documented cause of
`timedatectl` reporting "System clock synchronized: no" on healthy chrony hosts. Do not
rely on this flag alone, and note that D-Bus `org.freedesktop.timedate1.NTPSynchronized`
inherits the same defect.

**[revised] Daemon query — designed, then dropped.**

The original proposed a third signal: `chronyc tracking` over chrony's command socket for root
delay and root dispersion, or `systemd-time-wait-sync`'s `/run/systemd/timesync/synchronized`
marker. It is **not implemented**, and deliberately so rather than deferred.

The two signals above already cover every daemon in the table — `maxerror` catches chrony and
ntpd-rs, the status flag catches systemd-timesyncd — and there is no daemon the pair misses. The
third would have meant a chrony-specific socket protocol, with its own binary dependency, timeout
and failure handling, for a case that cannot arise. It survived in the code for a while as an
`Option` that was always `None`, which is worse than either implementing it or removing it: a
disjunct that can never fire reads as coverage and is not.

**Recommendation:** treat sync as a disjunction — maxerror below threshold *or* status flag
cleared — and record which condition fired as an attribute on the flushed records.

**[revised] Threshold: 5 seconds, with three consecutive good readings.** The original said 1–2 s.
That is too tight, for the reason `monitoring_platform::clock::DEFAULT_THRESHOLD_MICROS` already
documents: `maxerror` grows continuously between updates at the kernel's 500 ppm tolerance, so with
chrony's default `maxpoll 10` (~1024 s) it routinely reaches ~0.5 s in entirely healthy operation.
At 1 s the test flaps against that sawtooth — and here flapping means releasing the buffer and
re-arming it repeatedly. The collector therefore uses the receiver's value and the receiver's
hysteresis.

The reasoning behind "loose" still holds and is the point: the three daemons write three different
quantities, so the magnitude is not comparable across them. What the test reliably distinguishes is
*disciplined* from *never touched*, which is the question that matters. The weaker
"is anything disciplining this clock at all" test is reported separately — on `/healthz` and in the
§9 metrics — because a device parked at the kernel's 16 s ceiling an hour after boot has a
configuration problem an operator can fix, where one with a large but *moving* `maxerror` has a
network problem. It is on `/healthz` and not only in the health events because those are emitted
only once the clock is good, which is exactly when the answer stops being interesting.

**No notification mechanism exists.** `adjtimex` is request/response; the kernel emits no
clock-quality event. Poll at 1 Hz in the same loop, and drop to once a minute once synced —
**[revised]** rather than disarming entirely, because the §4.3 offset consistency check rides on
the same tick and is worth keeping. The syscall costs roughly a microsecond and runs only
during the pre-sync window. Also check maxerror inside the `ECANCELED` handler — on a
clock-less Pi the first correction usually exceeds `makestep` and arrives as a step, so
the common case resolves without any polling at all.

### 4.5 Ingest and frame resolution

Resolution happens **at receipt**, not at flush, while peer credentials and stream
position are still available. See §5.

A consequence worth stating, because it surprised the first end-to-end test: a batch written to a
file by one process and posted later by another is correctly classified `passthrough`. The poster
started *after* those timestamps were taken and cannot have produced them, so the
`[B_start, B_recv]` bound rejects every candidate. This is the design working, not a defect — but
it means testing the correction path needs one process that both stamps and sends, which is what
`mp-make-sample --post` exists for.

### 4.6 Buffer

Holds resolved records until sync.

**[revised] The record keeps its original timestamp while buffered.** The original said the buffer
holds "boottime values, no residual wall-clock ambiguity" — i.e. that the receipt pass overwrites
`time_unix_nano` with the boottime. The implementation instead leaves the arriving stamp in place
and carries the resolved boottime *alongside* it, in an internal attribute stripped at flush.

The property that buys is worth the extra attribute: **a buffered record is always valid, shippable
OTLP.** Which in turn makes §8.4 disappear as a special case — a record spooled across a reboot has
a boottime that means nothing on the new boot, so the flush simply drops the attribute and ships
the stamp the record arrived with. "Pass them through uncorrected" needs no code of its own.
Active only while the clock has never been set this boot.

- Cap by count and bytes; spill to disk keyed by `boot_id`.
- On timeout (suggested: 5 minutes), flush anyway with `clock.uncertain=true` rather than
  dropping. A Pi that boots with no network may never sync.
- A short grace buffer (a few seconds) should remain active even after sync. It costs
  almost nothing, smooths batching, and guarantees a step never arrives with zero
  correctable records in hand.

---

## 5. Frame resolution algorithm

### 5.1 Inputs

For each incoming record with wall-clock timestamp `T`:

- `B_recv` — `CLOCK_BOOTTIME` sampled at dequeue. Exact.
- `B_start` — sending process's start time. From `SO_PEERCRED` → PID → field 22 of
  `/proc/PID/stat` (ticks since boot; divide by `sysconf(_SC_CLK_TCK)`). A hard lower
  bound on any timestamp that process could have produced.
- The epoch table.

### 5.2 Resolution

```
candidates = []
for i, epoch in enumerate(epochs):                    # sorted by boot_start
    boot_end = epochs[i+1].boot_start if i+1 < len(epochs) else +inf
    B_evt = T - epoch.offset
    if epoch.boot_start - ε <= B_evt < boot_end + ε
       and B_start - ε <= B_evt <= B_recv + ε
       and not any(abs(c - B_evt) < ε for c in candidates):
        candidates.append(B_evt)

match len(candidates):
    1  -> resolved, exact
    0  -> foreign frame or pre-history; pass through untouched,
          tag mp.clock.corrected=false
    >1 -> ambiguous; pick nearest to B_recv, tag mp.clock.resolution=ambiguous
          and record the spread
```

`boot_end` is read off the next epoch rather than stored — see §4.1. `ε` applies to the epoch
bounds too, not only the process window: a step is learned about slightly after it happens, so a
record landing near a seam would otherwise fall through to `passthrough`.

**[revised] Near-identical candidates collapse.** Two epochs with offsets close together can both
explain one timestamp at almost the same boottime; reporting that as ambiguous with a nanosecond
spread would be technically true and useless. Without this, a boundary witnessed twice — once by
the journal backfill, once by the live watch — manufactures ambiguity out of nothing.

The `[B_start, B_recv]` window is the key constraint. It requires no application
cooperation, no configuration constant, and is far tighter than "within N seconds of now."

An epoch's own `[boot_start, boot_end)` bounds do real work alongside it, which is easy to
under-rate: most pairs of epochs *cannot* both explain the same timestamp, because a candidate has
to land inside the epoch that produced it. Constructing a genuinely ambiguous case takes care.

**Tie-breaking.** Records arriving in order on a single connection are monotonic in
boottime, which further constrains candidates. Interleaving known-good records with
ambiguous ones brackets an unknown epoch from both sides.

**Impossible values are informative.** A `B_evt` that resolves to before boot proves an
epoch existed that the table does not know about. The bounds above still recover it to
within the width of the process-start-to-receipt window. This failure is loud, not
silent — that is the property the whole design is built around.

### 5.3 What must not be corrected

The distinction is **not** past versus present. It is which clock frame the timestamp came
from:

- **Read from this host's clock at event time** — correctable. Includes derived values
  like `boot_time = realtime_now − uptime`, which is wrong by exactly the same offset and
  needs exactly the same correction.
- **Obtained elsewhere** — a remote server's `Date` header, GPS, a journal entry from a
  prior boot. Foreign frame. Must pass through untouched.

Provide an opt-out attribute for the second category. It is opt-*out* on rare records, not
opt-in on every record, so the coupling cost is negligible: an application deliberately
re-emitting foreign timestamps is doing something unusual and can be asked for one
attribute.

**Prefer durations to derived timestamps.** Report uptime as a duration rather than boot
time as a timestamp. Durations are frame-invariant and survive any correction unchanged.
This sidesteps the problem rather than solving it, and is the better answer wherever it
applies.

**One case needing cooperation:** an application forwarding journal entries from the
*current* boot on an unsynced clock. Those are in the bad frame and do need correction,
but will be older than any receipt-proximity heuristic. journald exposes
`__MONOTONIC_TIMESTAMP` alongside the realtime value, so such an application already has
the boottime figure and can attach it (§6.1). This is the one place the explicit attribute
genuinely earns its keep.

---

## 6. Correction and emission

### 6.1 Optional application attributes

All optional. Tier 0 — a completely unmodified OTLP SDK — is fully supported.

| Tier | Application does | Attribute | Accuracy |
|---|---|---|---|
| 0 | Nothing | — | Limited by app→collector delay |
| 1 | Attaches boottime per record | `mp.clock.boottime_ns` | Immune to app-side buffering |
| 2 | Marks record authoritative | `mp.clock.authoritative` | Passed through untouched |

Reading either attribute **consumes** it, so a caller cannot use a hint without also stripping it.
That makes the cardinality hazard below structural rather than a rule someone has to remember.

**Placement.** `boot_id` belongs in Resource attributes — constant for the process
lifetime, sits naturally beside `service.name` and `host.*`. Only the boottime value is
per-record. Use a private namespace so a future OTel semantic convention cannot collide.

**Cardinality hazard.** Metric data point attributes are part of time series identity. A
per-record boottime there creates a new series per point. The collector **must** strip
these after applying the correction: for metrics, remove entirely; for logs and spans,
replace with a small fixed summary.

**Batching.** Standard OTel SDKs batch log records with a delay of seconds by default,
which undermines tier 0. The local hop over a UDS is nearly free — configure app-side
batch delay to near zero and let the collector do all real batching. Tier 0 is then
accurate to milliseconds.

### 6.2 Applying the correction at flush

```
O = epoch_table.current().offset         # the ACTIVE EPOCH's offset, not a fresh reading
for record in batch:
    record.time = record.B_evt + O
```

**[revised] Use the active epoch's offset. Do not sample the clock here.** The original said the
opposite — "do not reuse stored epoch offsets" — on the grounds that a stored offset goes stale
under slew. Per §2 it does not: slewing cannot move `realtime − boottime`. With that reason gone,
sampling fresh is not merely unnecessary, it is actively wrong in two ways, and both showed up as
failing tests before they showed up as arguments:

- **resolve and project stop being inverses.** Resolution subtracts the epoch's offset; a fresh
  sample adds a slightly different number, so a record that resolved in the epoch still in force
  comes out perturbed by the jitter between two independent clock reads. With the epoch's own
  offset the round trip is the identity, exactly, and a record from an *earlier* epoch moves by
  precisely the size of the step between them — the whole correction and nothing else.
- **it breaks the receiver's deduplication.** `SPEC.md` §6.6 makes a measurement's id a content
  hash over `event_time` and the attributes, which is what turns a retry after a lost
  acknowledgement into a no-op rather than a second row. A re-sampled offset differs by a nanosecond
  or two between deliveries, so the projected `event_time` differs, the hash differs, and an
  application's ordinary retry becomes a duplicate measurement — silently defeating the property
  commit b6477b0 exists to provide.

  **[revised] this argument used to rest on the attribute as well, and no longer needs to.** It
  originally noted that `mp.clock.correction_ns` was itself one of the hashed attributes, so a
  re-sampled offset perturbed the hash twice over. §6.3 no longer stamps that attribute, which
  removes one of the two mechanisms — but not the conclusion, and not even the weaker half of it:
  `event_time` is hashed directly, and it is `event_time` that a re-sampled offset moves.

**One offset per flush, not per record**, or records drift relative to each other and ordering
within a burst can break.

The correction is a uniform additive offset, so apply it to *every* timestamp field in the
payload — span `start_time` and `end_time`, metric `start_time` and `time`. Durations and
rates come out unchanged.

### 6.3 Attributes on emitted records

**[revised] stamped by exception; an ordinary corrected record carries none.** The original list was
unconditional — `corrected`, `correction_ns`, `resolution` and `sync_source` on every emitted record —
and that was wrong on two counts once there was a year of real data to look at.

*Cardinality.* `correction_ns` is effectively a new distinct value per boot, written onto every one of
the millions of rows a year a busy host produces. §6.1 refuses a per-record boottime for exactly this
reason; stamping the offset it was corrected with is the same mistake one step later. It also clutters
every attribute filter in the read UI with a value nobody filters on.

*Redundancy.* On the normal path the four say the same thing on every row, and the aggregate they add up
to — how synchronized this host is, how many records were corrected, by how much — is already reported
once a minute by §9's own health event. That is the right place for "how is this host's clock doing";
per-row copies of it are not evidence, just volume.

What is kept is the part no aggregate can reconstruct: **which individual records are not ordinary.**

| Emitted | When |
|---|---|
| *(nothing)* | corrected, from a synchronized clock, unambiguous — the overwhelming majority |
| `mp.clock.resolution` — `exact` \| `ambiguous` \| `passthrough` \| `authoritative` | the record was **not** corrected, or was uncertain, or was ambiguous |
| `mp.clock.ambiguity_spread_ns` | ambiguous: how far apart the candidates were |
| `mp.clock.uncertain` | flushed on timeout without sync |
| `observed_time_unix_nano` | always (collector receipt time, OTLP log records) |

So the happy path is identified by **absence**, which is the one encoding that costs nothing to store,
and a timestamp that silently degraded to `passthrough` is still visible per row — the §4.2 failure this
labelling exists to make loud. `mp.clock.resolution` also remains the carrier the flush pass reads to
decide correctability (§6.2), so it is always written at receipt and *removed* at flush unless the
outcome was exceptional.

`mp.clock.corrected` is gone: it is now implied, and inverted, by the presence of `resolution`.
`mp.clock.sync_source` is gone too — which clock source was trusted is a property of the host at that
moment rather than of the record, and §9 reports it.

**[revised] namespaced `mp.clock.`, and note where they land.** The original wrote them bare. The
`mp.` prefix is the private namespace §6.1 asks for. Downstream, the receiver prefixes record
attributes structurally (`SPEC.md` §5.2), so these arrive in the database as
`record.attributes.mp.clock.*` — that is not a collision, but a query has to spell it.

Two further attributes exist only *inside* the collector, between receipt and flush:
`mp.clock.internal.event_boottime_ns` and `mp.clock.internal.receipt_boottime_ns`. They are
consumed and removed by the flush pass and never reach the wire, for the §6.1 cardinality reason.

A bad correction must be debuggable after the fact rather than invisible.

### 6.4 Server-side requirement

Corrected records arrive at the monitoring server well after their event time — minutes or
hours in the worst case. Verify the ingestion path and database do not drop or mis-bucket
timestamps older than arrival. This is a real constraint on the server, not just the
collector.

**Checked, and satisfied.** `SPEC.md` §5.3 applies no plausibility test to `event_time`, the index
is `(event_time DESC, id DESC)`, and `processed_time` is a separate column, so a late arrival is
stored and ordered correctly. One caveat, which is `SPEC.md` §12's own second open question: there
is no way to *query* by `processed_time`, so "what arrived in the last hour" is unanswerable and a
late-arriving batch is invisible to it.

---

## 7. systemd integration

**Collector socket unit** — creates the UDS early, before any client can connect, removing
the startup ordering race entirely. Clients block rather than fail.

**Collector service** — started eagerly at boot, *not* lazily on first connect. Lazy
activation guarantees the socket exists but not that the process is running, and a
collector that is not running observes no clock steps. Enable both units: the socket unit
creates the endpoint early, the service receives the listening fd through it.

```ini
# mp-collector.service
[Unit]
DefaultDependencies=no
Requires=mp-collector.socket
After=mp-collector.socket
Before=chronyd.service systemd-timesyncd.service
# [revised] Everything DefaultDependencies=no silently removed and this unit still needs:
Conflicts=shutdown.target
Before=shutdown.target
After=local-fs.target
RequiresMountsFor=/var/lib
```

**[revised] `DefaultDependencies=no` has to be paid for.** The original snippet had the first four
lines only. Dropping the default dependencies also drops the shutdown ordering, which leaves the
unit to be killed at an arbitrary point during shutdown — here, mid-flush, with the buffer still
holding records — and the ordering against `local-fs.target`, which the state directory needs.

The **socket** unit needs the same treatment, which is less obvious: with default dependencies it
is `After=sysinit.target`, `systemd-timesyncd` is *part of* sysinit.target, and a service that must
wait for its own socket therefore cannot possibly precede it. Ordering the service alone is
vacuous.

Ordering before the time daemons means the collector is running before anything is in a
position to step the clock. The only remaining pre-collector offset change is the kernel's
initial set from `fake-hwclock`, which happens before userspace and therefore before any
application timestamp exists. In practice this eliminates the unknown-epoch case.

**Application units:**

```ini
[Unit]
Requires=otel-collector.service
After=otel-collector.service
```

This is the load-bearing requirement, and it is weaker than it first appears. The
requirement is *not* "connect before logging" — it is "the collector process is running
before the application starts." An application may buffer internally for ten minutes and
then dump everything; the collector was running throughout, so its offset history already
covers the entire period. Worst case a record is ambiguous among *known* epochs, which §5.2
handles.

**Optional:** `OpenFile=/run/otel-collector.sock:otel` (systemd 253+) hands the application
an already-connected fd at exec. Useful for processes whose startup ordering you do not
control, or that would otherwise fail on a missing socket. Belt-and-braces, not
load-bearing. Note Bookworm-era Pi OS ships systemd 252.

**Credentials:** `SO_PEERCRED` lets the collector derive the sending process's identity
itself rather than trusting an application-supplied `service.name`.

**[revised] Two sandbox settings the receiver's unit uses cannot be copied.** Both fail *silently*
if they are, which is why they are called out rather than left to be discovered:

- **`ProtectProc=` must not be `invisible`.** §5.1 reads `/proc/PID/stat` for the *sending*
  process, which belongs to another user. `invisible` hides it, the read fails, the lower bound of
  the `[B_start, B_recv]` window collapses to zero, and every record quietly degrades toward
  `passthrough`. Nothing reports this but a rising counter — which is why §9 counts it.
- **`ProtectClock=` must be off and `@clock` named**, exactly as `SPEC.md` §9.4 already documents
  for the receiver's gate: the option cannot permit a *read* of `adjtimex(2)` and kills with
  SIGSYS instead. `CapabilityBoundingSet=` empty still withholds `CAP_SYS_TIME`, so the collector
  can read the clock and not set it.

And one that is merely easy to forget: forwarding to the receiver's unix socket needs membership
of the receiver's group, because that socket's access control is the mode on its containing
runtime directory (`SPEC.md` §8.1). Without it every flush fails with a permission error and the
collector buffers indefinitely.

---

## 8. Degraded operation

### 8.1 Never synchronized

No network at boot, or NTP unreachable. Buffer fills, timeout fires, records flush with
`clock.uncertain=true`. Data is preserved and marked, not dropped.

### 8.2 Desynchronization after a good sync

**Do not buffer in this case.** If chrony dies or the NTP server disappears, nothing
steps — the clock keeps running on the local oscillator and drifts at perhaps 10–50 ppm,
a few seconds per day. maxerror climbs past the threshold within an hour or two, but that
is the conservative *bound* growing, not the clock going bad. Actual error remains in the
milliseconds.

Buffering on that signal would halt telemetry during a network outage — precisely when it
is most wanted — to avoid an error smaller than the transmission delay, and would blow any
reasonable buffer cap.

Correct behavior:

| State | Action |
|---|---|
| Clock never set this boot | Buffer (bounded) |
| Clock set, quality degrading | Ship immediately, attach current error bound |

Frame resolution (§5) continues in **all** states. It is cheap and it is what makes
correction possible. Only the withholding policy is conditional.

### 8.3 Late recovery

**[revised] The premise of the original was wrong twice over.** It read: "chrony recovers after a
long gap, finds real error, and steps. The timerfd fires."

- Under the chrony configuration `SPEC.md` §9.4 recommends — `makestep 1.0 3` — chrony stops
  stepping after the third update. A late recovery therefore *slews*, and no timerfd fires.
- But that is fine, and it is why nothing needed adding here. Per §2, a slewed correction moves
  `CLOCK_REALTIME` and `CLOCK_BOOTTIME` together and leaves the offset unchanged. There is no
  frame discontinuity to detect and no epoch to open. Records stamped during the slew resolve
  against the same offset they were stamped under, which is exactly correct; what improves over
  the course of the slew is the clock's absolute accuracy, which no bookkeeping here could
  recover anyway.

If a step *does* happen — a host with `makestep` budget left, or one where an operator sets the
clock — the timerfd fires and anything still buffered or in flight is corrected for free. Records
already sent cannot be fixed, and the step is recorded: the §9 self-metrics carry the step count
and the time since the last one, so downstream analysis can reason about the affected window
rather than silently trusting it.

### 8.4 Reboot with spooled data

Boottime values from a previous boot are meaningless. Tag spooled records with `boot_id`
and pass them through uncorrected on restart.

---

## 9. Self-monitoring

Export as metrics from the collector. Nearly free, and turns a class of confusing
incidents into an obvious one: "every timestamp from this device is three days old" is a mystery,
where "no daemon has disciplined this device's clock since boot, and 4000 records are sitting in
the buffer" is a work item.

- current `maxerror`
- seconds since last observed step — **null, not a sentinel**, when none has happened
- count of steps this boot
- whether any daemon is disciplining the clock at all
- records resolved exact / ambiguous / passthrough / authoritative
- current buffer depth and age of oldest buffered record
- batches forwarded, and batches **shed** because the outbox filled (§3)

**[revised] Emitted as an ordinary OTLP Event through the collector's own forwarder**, under
`event_name = mp.collector.health`, with the values in the record *body*. The receiver takes logs
only and only Events (`SPEC.md` §2, §4.4), so an OTLP metric would be rejected — and going through
the same forwarder is the right call anyway, because a self-metric on a separate path would be the
one thing still working when the real path is broken.

The consequence, which is easy to forget: these are **real measurements** and land in the same
table as everything else. Anything counting rows sees them. The interval is therefore configurable
and can be switched off (`healthIntervalSecs = 0`), which is what the test harness does everywhere
except the one case that checks them.

---

## 10. Rejected alternatives

**Mandatory per-record boottime attribute.** Solves the problem completely but couples
every producer to the collector, and breaks the property that an application can point at
either the collector or the monitoring server unchanged. Retained as an optional tier.

**Receipt-time-only stamping.** Simple, but loses accuracy for any application that
buffers internally, and cannot distinguish a foreign timestamp from a local one.
Subsumed as the `N=0` case of §5.

**Boot-window test** ("is `T` between boot and now?"). Has an unbounded failure mode: a Pi
without an RTC boots with the clock restored to roughly the last shutdown time, so the
unsynced window sits days in the past — exactly where genuinely historical timestamps
live. Replaced by the `[B_start, B_recv]` bound, which is tighter and has no magic
constant.

**Fixed receipt-proximity window** ("within N seconds of now"). Workable — damage is
bounded by N, since a foreign timestamp landing within N of now implies that clock agrees
with ours to within N — but the epoch table plus process-start bounds make it unnecessary.
Retained only as a tie-break between ambiguous candidates.

**Buffering on mid-run desync.** See §8.2.

**[revised] Sampling the clock at flush.** Was the design in §6.2. It makes resolution and
projection non-inverse, and it breaks the receiver's content-hash deduplication by perturbing the
projected `event_time` between deliveries. Replaced by the active epoch's offset. (Originally this
also cited `correction_ns`, which §6.3 no longer stamps; the timestamp itself is the reason that
survives.)

**[revised] Detecting slew.** Considered while implementing §8.3, then dropped: `realtime −
boottime` is invariant under slewing, so there is nothing to detect. What survives is a cheap
consistency check for a *step* the watch missed (§4.3), which is a different thing with a
different threshold.

---

## 11. Open questions

1. **Open.** Confirm systemd version on the target image — `OpenFile=` requires 253+. Not
   load-bearing: the socket unit is what removes the ordering race, and `OpenFile=` was only ever
   belt-and-braces (§7).
2. **Open, and now instrumented rather than needing a manual check.** The §9 self-metrics report
   `clock.max_error_micros` and `clock.disciplined` per device, which answers this continuously
   and per host instead of once at a terminal. The manual version is still
   `watch -n1 'adjtimex --print | grep -E "maxerror|status"'`.
3. **Open.** Buffer caps default to 100 000 records / 64 MiB with a 5-minute timeout, chosen to
   match the receiver's own clock-gate budget rather than measured against a real workload.
4. **Answered — none exists.** `SPEC.md` §12 covers the same ground: every timestamp field across
   all ten OTLP protos is absolute `*_unix_nano`, the only relative value anywhere is
   `duration_nano` in the profiles signal, and `observed_time_unix_nano` distinguishes two clocks
   without substituting for a missing one. The Tier 1 attribute in §6.1 is the same scheme
   `SPEC.md` §12 sketches, which is why it uses a private namespace.
5. **Answered — yes.** See §6.4.

---

## 12. Implementation checklist

- [x] Socket unit + service unit, eager start, ordered before time daemons — `nix/collector-module.nix`
- [x] Async loop: UDS accept, cancel-on-set timerfd, 1 Hz poll — `runtime.rs`, `stepwatch.rs`
- [x] Epoch table with `boot_id`-keyed persistence — `epoch.rs`, `state.rs`
- [x] Journal backfill at startup, with `MONOTONIC`→`BOOTTIME` normalization — `journal.rs`
- [x] `SO_PEERCRED` → `/proc/PID/stat` field 22 process-start lookup, cached per connection —
      `peer.rs`, `receive.rs`
- [x] Frame resolution at receipt (§5.2) — `epoch.rs`, `correct.rs`
- [x] Sync detection disjunction (§4.4) — **two disjuncts, not three**: the daemon query was
      designed, found unreachable, and removed rather than left as an `Option` that is always
      `None`. The 1 Hz poll drops to 1/min after sync rather than stopping, because the §4.3
      consistency check rides on it
- [x] Bounded buffer with disk spill and timeout flush — `buffer.rs`, `spool.rs`
- [x] Flush-time correction with **the active epoch's offset**, not a fresh sample (§6.2)
- [x] Attribute stripping for cardinality safety — `correct.rs`
- [x] Clock-health self-metrics — `metrics.rs`
- [x] Test: boot with no network, verify timeout flush and `mp.clock.uncertain` —
      `nix/tests/cases/collector-clock.nix`
- [x] Test: wrong clock, verify step detection and retroactive correction — the same VM case
      (a real `date -s`, so the cancel-on-set path runs), plus
      `crates/mp-collector/tests/end_to_end.rs`
- [x] Test: replay of historical data, verify passthrough without corruption
- [x] Test: `boot_id` guard on spooled data

Two properties worth naming that the original checklist did not ask for, because they only became
visible once there was something to run:

- [x] **resolve-then-project is the identity** when the offset has not moved (§6.2)
- [x] **two deliveries of one batch are byte-identical**, so an application's retry deduplicates at
      the receiver instead of landing as a second row (`SPEC.md` §6.6)

And the one the checklist *did* ask for but the first round of tests did not actually establish:

- [x] **a record held while the clock is untrusted is released and corrected by a real step** —
      `nix/tests/cases/collector-step.nix`. The original version of this assertion lived in
      `collector-clock` and was satisfied by rows an earlier subtest had already inserted, so it
      passed against a collector that was not doing the work. The replacement was verified by
      stubbing out `apply_correction` and confirming it goes red.
