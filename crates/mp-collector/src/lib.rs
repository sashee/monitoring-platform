//! `mp-collector` — an on-host OTLP collector that retroactively corrects timestamps produced by
//! an unsynchronized clock. See `collector-clock-correction-design.md`; section references in
//! comments point at it, and `SPEC.md` references point at the receiver's specification.
//!
//! The shape of the crate is the shape of the design. Everything that decides is pure and takes
//! its clock readings as arguments; everything that reads a clock, a socket or `/proc` is a thin
//! shell around it:
//!
//! | Pure | Effectful |
//! |---|---|
//! | [`epoch`] — the offset table and frame resolution | [`stepwatch`] — the cancel-on-set timerfd |
//! | [`correct`] — the receipt and flush rewrites | [`journal`] — running `journalctl` |
//! | [`sync`] — is the clock trustworthy yet | [`peer`] — `/proc/PID/stat` |
//!
//! This is not decoration. The interesting cases — a clock three days behind, a step mid-batch, a
//! reboot with data spooled — are all reachable by handing a pure function a table and a couple of
//! integers, and none of them are reachable by waiting for a real clock to misbehave.

pub mod buffer;
pub mod config;
pub mod correct;
pub mod epoch;
pub mod forward;
pub mod journal;
pub mod metrics;
pub mod peer;
pub mod receive;
pub mod retry;
pub mod runtime;
pub mod spool;
pub mod state;
pub mod stepwatch;
pub mod sync;
