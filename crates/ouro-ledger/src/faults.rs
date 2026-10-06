//! Fault controls compiled only into the library test executable. Production
//! binaries have no environment switch, IPC operation, or reachable fault hook.
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub kind: String,
    pub point: String,
    pub action: String,
    pub marker: PathBuf,
}
thread_local! {
    static PLAN: RefCell<Option<Plan>> = const { RefCell::new(None) };
    static KIND: RefCell<String> = const { RefCell::new(String::new()) };
}
pub(crate) fn arm(plan: Plan) {
    PLAN.with(|p| *p.borrow_mut() = Some(plan));
}
pub(crate) fn disarm() {
    PLAN.with(|p| p.borrow_mut().take());
}
pub(crate) struct Scope(String);
pub(crate) fn scope(kind: &str) -> Scope {
    Scope(KIND.with(|current| std::mem::replace(&mut *current.borrow_mut(), kind.into())))
}
impl Drop for Scope {
    fn drop(&mut self) {
        KIND.with(|current| *current.borrow_mut() = std::mem::take(&mut self.0));
    }
}
pub(crate) fn active(point: &str) -> bool {
    PLAN.with(|p| {
        p.borrow()
            .as_ref()
            .is_some_and(|p| p.point == point && KIND.with(|kind| *kind.borrow() == p.kind))
    })
}
pub(crate) fn hit(point: &str) -> std::io::Result<()> {
    if !active(point) {
        return Ok(());
    }
    let plan = PLAN.with(|p| p.borrow_mut().take().unwrap());
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(plan.marker)?;
    marker.write_all(format!("{}:{point}:{}\n", plan.kind, plan.action).as_bytes())?;
    marker.sync_all()?;
    match plan.action.as_str() {
        "error" => Err(std::io::Error::from_raw_os_error(
            if point.ends_with("before_write") {
                libc::ENOSPC
            } else {
                libc::EIO
            },
        )),
        "kill" => {
            // Signal this process only: no cached or reusable external pid.
            unsafe {
                libc::raise(libc::SIGKILL);
            }
            panic!("SIGKILL returned unexpectedly")
        }
        _ => panic!("unknown test fault action"),
    }
}

pub(crate) fn request_kind(request: &crate::protocol::Request) -> &str {
    use crate::protocol::Request;
    match request {
        Request::Prepare { .. } => "prepared",
        Request::ClaimOwner { .. } => "owner_claimed",
        Request::AppendOwner { kind, .. } => kind,
        Request::AppendSource { .. } => "source",
        _ => "",
    }
}
