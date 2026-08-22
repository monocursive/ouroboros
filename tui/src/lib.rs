//! The `ouro` client, as a library so the binary and the tests speak to it the same way.
//!
//! Slice 3a is plumbing: a transport that speaks `Ouroboros.Gateway`'s line protocol, a
//! process supervisor that can start a runtime and find one it already started, and the
//! tolerant wire types both need. There is no terminal UI here — Slice 3b adds it on top
//! of exactly these modules, and the seams it will need (the reconnect hook, the bounded
//! log ring, the notification channel) exist and are exercised now so that adding a UI
//! does not move them.

pub mod cli;
pub mod config;
pub mod fleet;
pub mod fleet_add;
pub mod model;
pub mod proto;
pub mod run;
pub mod runtime;
pub mod status;
pub mod transport;
pub mod ui;
