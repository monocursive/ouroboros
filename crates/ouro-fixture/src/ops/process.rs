//! The process and lifetime modes: children, threads, clones, signals,
//! sleeping, spinning and exiting.

use std::ffi::{OsStr, OsString, c_int};

use serde_json::Value;

use crate::cli::{ExecVia, ProcessMode};
use crate::raw;
use crate::report::{Expect, OpReport, Reporter, path_value};

use super::exec::{do_exec, exec_and_wait, exec_replace, image};
use super::{Session, Stop, check, cloexec_pipe, finish, raw_errno, refuse_path};

/// Run one process or lifetime mode.
pub(crate) fn run(session: &Session<'_>, rep: &Reporter, mode: ProcessMode) -> Result<bool, Stop> {
    match mode {
        ProcessMode::Exec { via, expect, argv } => exec_and_wait(rep, via, &argv, &expect),
        ProcessMode::ExecReplace { via, expect, argv } => {
            exec_replace(session, rep, via, &argv, &expect)
        }
        ProcessMode::Sleep { ms } => {
            let mut r = OpReport::new("sleep");
            r.set("ms", ms);
            rep.emit(&r);
            sleep_ms(ms);
            Ok(true)
        }
        ProcessMode::Spin { ms } => {
            let mut r = OpReport::new("spin");
            r.set("ms", ms);
            rep.emit(&r);
            spin_ms(ms);
            Ok(true)
        }
        ProcessMode::Background { ms, argv } => background(rep, ms, &argv),
        ProcessMode::IgnoreTerm { ms } => {
            ignore_term();
            let mut r = OpReport::new("ignore-term");
            r.set("ms", ms);
            r.set("signal", "SIGTERM");
            rep.emit(&r);
            sleep_ms(ms);
            Ok(true)
        }
        ProcessMode::ForkStorm { count } => Ok(fork_storm(rep, count)),
        ProcessMode::Thread => Ok(thread(rep)),
        ProcessMode::CloneUntraced { path, expect } => Ok(clone_untraced(rep, &path, &expect)),
        ProcessMode::Clone3 { expect } => {
            let emitted = finish(OpReport::new("clone3"), raw::clone3_probe());
            Ok(check(rep, emitted, &expect))
        }
        ProcessMode::Exit { code } => exit(session, rep, code),
        ProcessMode::Raise { signal } => raise(rep, &signal),
    }
}

/// Report, then end the process with `code`; when an earlier step of this
/// process did not meet its expectation, with
/// [`crate::EXIT_EXPECTATION_FAILED`] instead, so a script's last `exit 0`
/// cannot report success over a failure. The line says why the code
/// changed.
fn exit(session: &Session<'_>, rep: &Reporter, code: u8) -> ! {
    let earlier = session.failed_earlier();
    let actual = if earlier {
        crate::EXIT_EXPECTATION_FAILED
    } else {
        code
    };
    let mut r = OpReport::new("exit");
    r.set("code", code);
    r.set("earlier_expectation_failed", earlier);
    r.set("exit_code", actual);
    r.result(i64::from(actual), None);
    rep.emit(&r);
    std::process::exit(i32::from(actual));
}

fn background(rep: &Reporter, ms: u64, argv: &[OsString]) -> Result<bool, Stop> {
    let img = if argv.is_empty() {
        None
    } else {
        Some(image(argv)?)
    };

    // The child reports whether `setsid` succeeded, so `detached` is a
    // measurement rather than an assumption. One byte, no sleep.
    let (sr, sw) = cloexec_pipe()
        .map_err(|e| Stop::Failed(format!("could not create the detach pipe: {e}")))?;

    // SAFETY: single-threaded at this point; the child runs only `setsid`,
    // `write`, `close`, `nanosleep`, the exec syscall and `_exit`, all
    // async-signal-safe, over buffers built before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: both descriptors are owned here.
        unsafe {
            libc::close(sr);
            libc::close(sw);
        }
        return Err(Stop::Failed(format!(
            "fork failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        // SAFETY: async-signal-safe; detaches the descendant from this session.
        let sid = unsafe { libc::setsid() };
        // SAFETY: the child owns the read end and writes one byte of result
        // through the write end; `close` and `write` are async-signal-safe.
        unsafe {
            libc::close(sr);
            let byte = [u8::from(sid >= 0)];
            libc::write(sw, byte.as_ptr().cast::<libc::c_void>(), 1);
            libc::close(sw);
        }
        sleep_ms(ms);
        if let Some(img) = &img {
            let _ = do_exec(img, ExecVia::Execve);
        }
        // SAFETY: the only correct exit from a forked child that did not exec.
        unsafe { libc::_exit(0) };
    }

    // SAFETY: the parent owns the write end and closes it so the read ends.
    unsafe { libc::close(sw) };
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is live; the child writes exactly one byte right after
    // `setsid`, so this returns immediately and never sleeps.
    let got = unsafe { libc::read(sr, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
    // SAFETY: the parent owns the read end.
    unsafe { libc::close(sr) };
    let detached = got == 1 && byte[0] == 1;

    let mut report = OpReport::new("background");
    report.set("pid", pid);
    report.set("delay_ms", ms);
    report.set("argc", argv.len());
    report.set("detached", detached);
    report.result(i64::from(pid), None);
    rep.emit(&report);
    Ok(detached)
}

fn fork_storm(rep: &Reporter, count: u32) -> bool {
    let mut forked = 0u32;
    // Reserve for what a process could plausibly fork, not for what was
    // asked: `fork-storm 4000000000` reserved about 16 GB before forking once.
    let mut pids: Vec<libc::pid_t> = Vec::with_capacity(std::cmp::min(count, 4096) as usize);
    for _ in 0..count {
        // SAFETY: single-threaded; the child only calls `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            break;
        }
        if pid == 0 {
            // SAFETY: the only correct exit from a forked child.
            unsafe { libc::_exit(0) };
        }
        forked += 1;
        pids.push(pid);
    }
    let mut reaped = 0u32;
    for pid in pids {
        let mut status: c_int = 0;
        // SAFETY: `status` is live; `pid` is this process's own child.
        if unsafe { libc::waitpid(pid, &raw mut status, 0) } == pid {
            reaped += 1;
        }
    }
    let mut report = OpReport::new("fork-storm");
    report.set("requested", count);
    report.set("forked", forked);
    report.set("reaped", reaped);
    report.result(i64::from(reaped), None);
    rep.emit(&report);
    forked == count && reaped == count
}

fn thread(rep: &Reporter) -> bool {
    let handle = std::thread::spawn(|| {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `gettid` takes no arguments and only reads kernel state.
            unsafe { libc::syscall(libc::SYS_gettid) }
        }
        #[cfg(not(target_os = "linux"))]
        {
            -1i64
        }
    });
    let mut report = OpReport::new("thread");
    match handle.join() {
        Ok(tid) => {
            report.set(
                "tid",
                if tid >= 0 {
                    Value::from(tid)
                } else {
                    Value::Null
                },
            );
            report.set("joined", true);
            report.result(0, None);
            rep.emit(&report);
            true
        }
        Err(_) => {
            report.set("joined", false);
            report.result(-1, None);
            rep.emit(&report);
            false
        }
    }
}

fn clone_untraced(rep: &Reporter, path: &OsStr, expect: &Expect) -> bool {
    let report = OpReport::new("clone");
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => {
            let e = refuse_path(report, "path", path, e.reason);
            rep.emit(&e.report);
            return false;
        }
    };
    let mut report = report;
    report.set("flags", "CLONE_UNTRACED|SIGCHLD");
    report.set("mechanism", raw::mechanism());
    let (attempt, status) = raw::clone_untraced_mkdir(c.as_ptr());
    let emitted = finish(report, attempt);
    rep.emit(&emitted.report);
    if let Some(status) = status {
        let mut child = OpReport::new("untraced-mkdir");
        path_value(&mut child.args, "path", path);
        let exited = libc::WIFEXITED(status);
        child.set("exited", exited);
        let code = if exited {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        if code == 0 {
            child.result(0, None);
        } else if code > 0 {
            child.result(-1, Some(code));
        } else {
            child.set("signal", libc::WTERMSIG(status));
            child.result(-1, None);
        }
        rep.emit(&child);
    }
    emitted.satisfies(expect)
}

fn raise(rep: &Reporter, signal: &str) -> Result<bool, Stop> {
    let sig = parse_signal(signal)?;
    let mut report = OpReport::new("raise");
    report.set("signal", signal.to_uppercase());
    report.set("signum", sig);
    // SAFETY: restoring the default disposition of a valid signal number.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
    report.result(0, None);
    rep.emit(&report);
    // SAFETY: sending a signal to this very process.
    let r = unsafe { libc::kill(libc::getpid(), sig) };
    Ok(r == 0)
}

fn parse_signal(s: &str) -> Result<c_int, Stop> {
    if let Ok(n) = s.parse::<c_int>() {
        if n > 0 && n < 64 {
            return Ok(n);
        }
        return Err(Stop::Usage(format!(
            "`{s}` is not a signal number in 1..63"
        )));
    }
    let upper = s.to_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let sig = match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "ABRT" => libc::SIGABRT,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "SEGV" => libc::SIGSEGV,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "CHLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        _ => return Err(Stop::Usage(format!("unknown signal `{s}`"))),
    };
    Ok(sig)
}

fn ignore_term() {
    // SAFETY: setting SIG_IGN for a valid signal number.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
}

pub(crate) fn sleep_ms(ms: u64) {
    let mut req = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as _,
    };
    loop {
        // SAFETY: both arguments are live timespec values.
        let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let r = unsafe { libc::nanosleep(&raw const req, &raw mut rem) };
        if r == 0 {
            return;
        }
        if raw_errno() != libc::EINTR {
            return;
        }
        req = rem;
    }
}

fn spin_ms(ms: u64) {
    let start = std::time::Instant::now();
    let target = std::time::Duration::from_millis(ms);
    let mut acc: u64 = 0;
    while start.elapsed() < target {
        for i in 0..10_000u64 {
            acc = acc.wrapping_add(i).wrapping_mul(2_654_435_761);
        }
    }
    std::hint::black_box(acc);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_parse_by_name_number_and_sig_prefix() {
        assert_eq!(parse_signal("TERM").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("9").unwrap(), 9);
        assert!(parse_signal("NOPE").is_err());
        assert!(parse_signal("0").is_err());
        assert!(parse_signal("999").is_err());
    }
}
