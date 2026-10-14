//! The Linux platform.
//!
//! The mechanisms of jail-v1 §9, each with a test that runs on the reference
//! host, and `platform` wiring them into the portable `Platform` seam.
//!
//! `bpf` and `seccomp` describe the Linux ABI but call nothing, so they build
//! and test on every host; everything below them is gated.

pub mod abi;
pub mod bpf;
// The loopback bridge is a portable byte relay; only its
// hidden subcommand and its place in the sandbox are Linux's
pub mod bridge;
// The host manifest `doctor --json` produces (§3.2, §14.1); its
// parsing is portable, its reads are gated inside
pub mod host;
// the canonical renderings the milestone freeze pins (§16)
pub mod freeze;
// The supervisor's own delegated scope (§9.3); the
// decision is portable, the host that acts on it is gated inside
pub mod scope;
pub mod seccomp;

// The `agent` profile's proxy, mediator and bridge wiring
#[cfg(target_os = "linux")]
pub mod agent;
#[cfg(target_os = "linux")]
pub mod audit;
#[cfg(target_os = "linux")]
pub mod bwrap;
#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod clock;
#[cfg(target_os = "linux")]
pub mod exec;
#[cfg(target_os = "linux")]
pub mod fs;
#[cfg(target_os = "linux")]
pub mod identity;
#[cfg(target_os = "linux")]
pub mod launch;
// Observer event consumption shared by both boundaries
#[cfg(target_os = "linux")]
pub mod observed;
#[cfg(target_os = "linux")]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod probe;
#[cfg(target_os = "linux")]
mod storage;
// `gc` reconciliation of a dead supervisor's execution cgroup
#[cfg(target_os = "linux")]
pub mod reconcile;
// N05 mechanism modules
#[cfg(target_os = "linux")]
pub mod sockdiag;
#[cfg(target_os = "linux")]
pub mod sys;
#[cfg(target_os = "linux")]
pub mod tracer;
#[cfg(target_os = "linux")]
pub mod unixpeer;
// The uncontained `none` boundary (§9.3)
#[cfg(target_os = "linux")]
pub mod uncontained;
#[cfg(target_os = "linux")]
pub mod watch;
