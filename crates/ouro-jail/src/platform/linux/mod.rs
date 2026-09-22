//! The Linux platform.
//!
//! The mechanisms of jail-v1 §9, each with a test that runs on the reference
//! host, and `platform` wiring them into the portable `Platform` seam.
//!
//! `bpf` and `seccomp` describe the Linux ABI but call nothing, so they build
//! and test on every host; everything below them is gated.

pub mod bpf;
pub mod seccomp;

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
#[cfg(target_os = "linux")]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod probe;
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
