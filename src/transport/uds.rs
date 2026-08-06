//! Unix socket lifecycle (SPEC.md §8.1).
//!
//! The implementation lives in `mp_host::uds`, shared with the collector so the two binaries
//! cannot end up with different ideas about reclaiming a stale socket or who owns the path. The
//! behaviour and its tests moved with it; this is the receiver's name for it.

pub use mp_host::uds::{bind, cleanup};
