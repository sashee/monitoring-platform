//! Host primitives shared by the receiver (`monitoring-platform`) and the clock-correcting
//! collector (`mp-collector`).
//!
//! Everything here is a thin, honest wrapper over a syscall or a `/proc` file — no policy, no
//! state. The decisions built on top live in the consuming crates, where they are pure and
//! testable without a clock: `monitoring_platform::clock` for the §9.4 boot gate, and
//! `mp_collector::{epoch, sync}` for frame resolution.
//!
//! This crate exists so those two binaries cannot drift onto different definitions of "what
//! time is it" — they have to agree, since one rewrites timestamps the other stores.

pub mod clock;
pub mod uds;
