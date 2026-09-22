//! `ouro-jail`: run an operator-supplied argv under an explicit policy and
//! record what was applied, what was observed and what remains unknown.
//!
//! The module layout follows jail-v1 §4. Portable code owns CLI parsing,
//! configuration provenance, policy narrowing, profile expansion, capability
//! requirements, lifecycle transitions, redaction, record encoding and resource
//! budgets; [`platform`] owns everything native.

pub mod canonical;
pub mod capability;
pub mod cleanup;
pub mod cli;
pub mod config;
pub mod network;
pub mod observer;
pub mod platform;
pub mod policy;
pub mod profiles;
// J3-P begin: the outside HTTP proxy library (jail-v1 §10)
pub mod proxy;
// J3-P end
pub mod records;
pub mod state;
pub mod supervisor;
pub mod trace;
