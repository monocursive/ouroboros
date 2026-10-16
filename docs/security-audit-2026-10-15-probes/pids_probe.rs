// One-shot: print the cgroup_pids probe status on this host.
use std::path::Path;
fn main() {
    let probe = ukai_jail::platform::linux::probe::run_one(
        "cgroup_pids",
        Path::new("/home/ubuntu/ukai-review/target/release/ukai-jail"),
        Path::new("/usr/bin/bwrap"),
    );
    println!("status={:?} detail={}", probe.status, probe.detail);
}
