//! Shared test support.
//!
//! Not a test target: Cargo builds only the top-level `.rs` files in `tests/`,
//! so this is compiled into each binary that declares `mod common;`.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;

use tempfile::TempDir;

/// A temporary directory created mode 0700, whatever the umask is.
///
/// `tempfile::tempdir()` creates with 0777 masked by the process umask, so the
/// result is 0755 on a host whose umask is 022 and 0775 on one whose umask is
/// 002. A state root under a group-writable ancestor is refused by
/// `state::check_state_ancestors`, and rightly: §6.2 rejects "unsafe parent
/// replacement", and anyone in that group can swap the next component for
/// their own. The check stays strict; the tests stop handing it a directory
/// that fails it for reasons that have nothing to do with what they test.
///
/// Every test file uses this, not only the ones that build a state root today:
/// which temporary directory ends up as a state-root ancestor is a detail that
/// changes when a test is edited, and the umask of the machine running it is
/// not something a test should depend on either way.
pub fn private_tempdir() -> TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}
