//! The Linux platform.
//
// filled by the linux slice: bubblewrap plan, seccomp baseline, cgroup leaf,
// launcher, ptrace observer, tree termination and the Linux `doctor` probes.
// Until then `platform::current()` returns `platform::Unimplemented` on Linux,
// which refuses with `backend_unavailable` instead of doing nothing quietly.

pub mod tracer;
