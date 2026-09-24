//! The Linux platform.
//!
//! The mechanisms of jail-v1 §9, each with a test that runs on the reference
//! host, and `platform` wiring them into the portable `Platform` seam.
//!
//! `bpf` and `seccomp` describe the Linux ABI but call nothing, so they build
//! and test on every host; everything below them is gated.

pub mod bpf;
// J3-agent begin: the loopback bridge is a portable byte relay; only its
// hidden subcommand and its place in the sandbox are Linux's
pub mod bridge;
// J3-agent end
// J5-D begin: the host manifest `doctor --json` produces (§3.2, §14.1); its
// parsing is portable, its reads are gated inside
pub mod host;
// J5-D end
// J4 autoscope begin: the supervisor's own delegated scope (§9.3); the
// decision is portable, the host that acts on it is gated inside
pub mod scope;
// J4 autoscope end
pub mod seccomp;

// J3-agent begin: the `agent` profile's proxy, mediator and bridge wiring
#[cfg(target_os = "linux")]
pub mod agent;
// J3-agent end
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
// J3-none begin: observer event consumption shared by both boundaries
#[cfg(target_os = "linux")]
pub mod observed;
// J3-none end
#[cfg(target_os = "linux")]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod probe;
// J4-G begin: `gc` reconciliation of a dead supervisor's execution cgroup
#[cfg(target_os = "linux")]
pub mod reconcile;
// J4-G end
// J3-unixpeer begin: N05 mechanism modules
#[cfg(target_os = "linux")]
pub mod sockdiag;
#[cfg(target_os = "linux")]
pub mod unixpeer;
// J3-unixpeer end
#[cfg(target_os = "linux")]
pub mod sys;
#[cfg(target_os = "linux")]
pub mod tracer;
// J3-none begin: the uncontained `none` boundary (§9.3)
#[cfg(target_os = "linux")]
pub mod uncontained;
// J3-none end
#[cfg(target_os = "linux")]
pub mod watch;
