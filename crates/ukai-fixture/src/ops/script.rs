//! `script`: several modes, parsed first, then run in one process.

use std::ffi::OsStr;

use clap::Parser as _;

use crate::cli::{Mode, ProcessMode, Step};

use super::{Session, Stop, run_in};

/// Does this mode end the process, so that nothing after it can run?
fn terminates_the_process(mode: &Mode) -> Option<&'static str> {
    match mode {
        Mode::Process(ProcessMode::Exit { .. }) => Some("exit"),
        Mode::Process(ProcessMode::ExecReplace { .. }) => Some("exec-replace"),
        Mode::SandboxExec { .. } => Some("sandbox-exec"),
        Mode::Process(ProcessMode::Raise { .. }) => Some("raise"),
        _ => None,
    }
}

/// Run the JSON array of argv arrays in FILE, each step a mode of this
/// process. True when every step's expectations held.
pub(crate) fn run(session: &Session<'_>, file: &OsStr) -> Result<bool, Stop> {
    let text = std::fs::read_to_string(std::path::Path::new(file)).map_err(|e| {
        Stop::Usage(format!(
            "cannot read script {}: {e}",
            file.to_string_lossy()
        ))
    })?;
    let steps: Vec<Vec<String>> = serde_json::from_str(&text)
        .map_err(|e| Stop::Usage(format!("script must be a JSON array of argv arrays: {e}")))?;
    let count = steps.len();
    // Every step is parsed before any runs, so an argument the command line
    // refuses in a later step is found before an earlier one has acted.
    let mut parsed = Vec::with_capacity(count);
    for (i, argv) in steps.into_iter().enumerate() {
        if argv.is_empty() {
            return Err(Stop::Usage(format!("script step {i} is empty")));
        }
        let step = Step::try_parse_from(std::iter::once("ukai-fixture".to_string()).chain(argv))
            .map_err(|e| Stop::Usage(format!("script step {i}: {e}")))?;
        if let Some(name) = terminates_the_process(&step.mode)
            && i + 1 != count
        {
            return Err(Stop::Usage(format!(
                "script step {i} is `{name}`, which ends the process: \
                 the {} step(s) after it could never run",
                count - i - 1
            )));
        }
        parsed.push(step.mode);
    }
    let mut all_ok = true;
    for (i, mode) in parsed.into_iter().enumerate() {
        match run_in(session, mode) {
            Ok(ok) => all_ok &= ok,
            // A value only the mode itself checks (a mode string, a signal,
            // an address) is refused when its step runs. After earlier steps
            // have acted, that refusal can no longer say nothing ran.
            Err(Stop::Usage(why)) if i > 0 => {
                return Err(Stop::Failed(format!(
                    "script step {i} was refused after the {i} step(s) before it ran: {why}"
                )));
            }
            Err(stop) => return Err(stop),
        }
    }
    Ok(all_ok)
}
