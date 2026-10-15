#![cfg(target_os = "linux")]
//! Records on a live host (jail-v1 §7, §13): what the real jail writes holds
//! its frozen contract under every profile, and a crash at any point of any
//! persistence site leaves valid records that `gc` completes.
//!
//! - `contract`: every receipt, trace and control transcript of real runs,
//!   held to the schemas and the semantic rules (R01, O01);
//! - `replacement`: a crash at each point of each of the run's own
//!   replacements (R02);
//! - `recovery`: a crash at each point of the writes `gc` and the execution
//!   leaf make, and the faults the persistence seam injects there (R02.3,
//!   R02.4).

use std::path::Path;

use serde_json::Value;

mod common;

#[path = "records_linux/contract.rs"]
mod contract;
#[path = "records_linux/recovery.rs"]
mod recovery;
#[path = "records_linux/replacement.rs"]
mod replacement;

/// A crash point of a durable replacement, and what the records must show
/// after it.
#[derive(Clone, Copy, Debug)]
struct Point {
    name: &'static str,
    /// The new content is visible under the target name.
    published: bool,
    /// The temporary name is still there.
    temp_left: bool,
}

/// The four points of a durable replacement, in order.
const POINTS: [Point; 4] = [
    Point {
        name: "temp_written",
        published: false,
        temp_left: true,
    },
    Point {
        name: "temp_synced",
        published: false,
        temp_left: true,
    },
    Point {
        name: "renamed",
        published: true,
        temp_left: false,
    },
    Point {
        name: "dir_synced",
        published: true,
        temp_left: false,
    },
];

/// A record file's JSON, `None` when it is absent; an unreadable or
/// unparsable file is the problem it reports.
fn parse(path: &Path) -> Result<Option<Value>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{} does not parse: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{} cannot be read: {error}", path.display())),
    }
}
