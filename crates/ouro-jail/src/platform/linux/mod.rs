//! The Linux platform.
//!
//! Phase 1 of J1: the mechanisms, each with a test that runs on the reference
//! host. Wiring them into the portable `Platform` trait is phase 2.
//!
//! `bpf` and `seccomp` describe the Linux ABI but call nothing, so they build
//! and test on every host; everything below them is gated.

pub mod bpf;
pub mod seccomp;

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
pub mod probe;
#[cfg(target_os = "linux")]
pub mod sys;
#[cfg(target_os = "linux")]
pub mod tracer;
