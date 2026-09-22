//! The `ouro-fixture` command line.
//!
//! The same `Mode` parses a process argv and a step of a `script` file, so a
//! scripted step and a standalone invocation cannot drift apart.

use std::ffi::OsString;

use clap::{Parser, Subcommand, ValueEnum};

use crate::report::Expect;

#[derive(Parser, Debug)]
#[command(
    name = "ouro-fixture",
    about = "Conformance child for ouro-jail: performs one named syscall per operation and reports its raw result",
    long_about = None,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Descriptor the JSON report lines are written to (default: 1, stdout).
    #[arg(long, value_name = "FD", default_value_t = 1, global = true)]
    pub report_fd: i32,

    /// Emit no report lines at all. The byte-stream modes need this when the
    /// stream itself is under byte comparison.
    #[arg(long, global = true)]
    pub no_report: bool,

    #[command(subcommand)]
    pub mode: Mode,
}

/// One step of a `script` file: the same subcommands, without the globals.
#[derive(Parser, Debug)]
#[command(name = "ouro-fixture", disable_help_subcommand = true)]
pub struct Step {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OpenVia {
    Openat,
    Open,
    Creat,
    Openat2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MkdirVia {
    Mkdir,
    Mkdirat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum RenameVia {
    Rename,
    Renameat,
    Renameat2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum UnlinkVia {
    Unlink,
    Unlinkat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum RmdirVia {
    Rmdir,
    Unlinkat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LinkVia {
    Link,
    Linkat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SymlinkVia {
    Symlink,
    Symlinkat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MknodVia {
    Mknod,
    Mknodat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExecVia {
    Execve,
    Execveat,
}

/// The `addrlen` a pathname `sockaddr_un` is passed with.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum UnixLen {
    /// `offsetof(sun_path) + strlen(path)`: no terminating NUL.
    Exact,
    /// `offsetof(sun_path) + strlen(path) + 1`: the NUL included, as the Rust
    /// standard library and `SUN_LEN(..) + 1` pass it. The default.
    Nul,
    /// `sizeof(struct sockaddr_un)`, as most C programs pass it.
    Full,
}

#[derive(Subcommand, Debug)]
pub enum Mode {
    /// Open a path. `--via creat` implies create, truncate and write-only.
    Open {
        path: OsString,
        #[arg(long, value_enum, default_value_t = OpenVia::Openat)]
        via: OpenVia,
        #[arg(long)]
        create: bool,
        #[arg(long)]
        trunc: bool,
        /// Request write access (`O_WRONLY`); without it the open is read-only.
        #[arg(long)]
        write: bool,
        /// Request read and write access (`O_RDWR`).
        #[arg(long)]
        rdwr: bool,
        /// Creation mode, octal.
        #[arg(long, value_name = "OCTAL", default_value = "600")]
        mode: String,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Create a directory.
    Mkdir {
        path: OsString,
        #[arg(long, value_enum, default_value_t = MkdirVia::Mkdirat)]
        via: MkdirVia,
        #[arg(long, value_name = "OCTAL", default_value = "700")]
        mode: String,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Rename a directory entry.
    Rename {
        from: OsString,
        to: OsString,
        #[arg(long, value_enum, default_value_t = RenameVia::Renameat)]
        via: RenameVia,
        /// `RENAME_NOREPLACE`; only meaningful with `--via renameat2`.
        #[arg(long)]
        noreplace: bool,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Remove a non-directory entry.
    Unlink {
        path: OsString,
        #[arg(long, value_enum, default_value_t = UnlinkVia::Unlinkat)]
        via: UnlinkVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Remove a directory.
    Rmdir {
        path: OsString,
        #[arg(long, value_enum, default_value_t = RmdirVia::Unlinkat)]
        via: RmdirVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Create a hard link.
    Link {
        from: OsString,
        to: OsString,
        #[arg(long, value_enum, default_value_t = LinkVia::Linkat)]
        via: LinkVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Create a symbolic link named LINKPATH pointing at TARGET.
    Symlink {
        target: OsString,
        linkpath: OsString,
        #[arg(long, value_enum, default_value_t = SymlinkVia::Symlinkat)]
        via: SymlinkVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Create a filesystem node. The default `--fifo` is the one kind an
    /// unprivileged user may create on Linux; `--regular` makes a plain file.
    /// Character and block nodes need CAP_MKNOD and are not offered.
    Mknod {
        path: OsString,
        #[arg(long, value_enum, default_value_t = MknodVia::Mknodat)]
        via: MknodVia,
        /// S_IFIFO. The default.
        #[arg(long, conflicts_with = "regular")]
        fifo: bool,
        /// S_IFREG.
        #[arg(long)]
        regular: bool,
        /// Permission bits, octal. The file-type bits come from the kind.
        #[arg(long, value_name = "OCTAL", default_value = "600")]
        mode: String,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Set a file's length by path.
    Truncate {
        path: OsString,
        #[arg(value_name = "LEN")]
        length: i64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Open PATH, then set its length through the descriptor. The open is
    /// reported too, so a test can put the descriptor-based mutation beside
    /// the path-based one and see which of them a tracer reports.
    Ftruncate {
        path: OsString,
        #[arg(value_name = "LEN")]
        length: i64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Connect a socket to a numeric address. Names are refused: a lookup
    /// would issue its own connects and pollute the trace.
    Connect {
        #[arg(value_name = "ADDR")]
        addr: String,
        #[arg(long)]
        udp: bool,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Send N bytes (`byte i = i % 256`) to a numeric ADDR:PORT through an
    /// unconnected UDP socket (`sendto` with a destination).
    UdpSendto {
        #[arg(value_name = "ADDR")]
        addr: String,
        #[arg(long, value_name = "N", default_value_t = 16)]
        bytes: usize,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Send one DNS A query over UDP to RESOLVER (`IP`, `IP:PORT` or
    /// `[IPv6]:PORT`; port 53 by default) and report what came back. `--expect
    /// ok` means a response with the query's id arrived; `ETIMEDOUT` (marked
    /// as the fixture's own deadline) means none did.
    DnsQuery {
        #[arg(value_name = "RESOLVER")]
        resolver: String,
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "MS", default_value_t = 3000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// HTTP/1.1 GET of an `http://` URL. With `http_proxy`/`HTTP_PROXY` set
    /// (lowercase first) the request goes to the proxy in absolute form;
    /// otherwise straight to the URL's numeric host. Plain TCP, no TLS.
    HttpGet {
        #[arg(value_name = "URL")]
        url: String,
        /// Ignore the proxy variables and connect directly: the bypass a
        /// contained profile must defeat.
        #[arg(long)]
        no_proxy: bool,
        /// Send this Host header instead of the URL's authority.
        #[arg(long, value_name = "VALUE")]
        host_header: Option<String>,
        #[arg(long, value_name = "MS", default_value_t = 10_000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// HTTP/1.1 CONNECT HOST:PORT through `https_proxy`/`HTTPS_PROXY`
    /// (lowercase first). Without a proxy variable the mode refuses: a
    /// CONNECT names a proxy by definition.
    HttpConnect {
        #[arg(value_name = "HOST:PORT")]
        authority: String,
        /// After a 2xx, send `GET PATH` through the tunnel and report that
        /// response too.
        #[arg(long, value_name = "PATH")]
        then_get: Option<String>,
        /// Send this Host header instead of HOST:PORT.
        #[arg(long, value_name = "VALUE")]
        host_header: Option<String>,
        #[arg(long, value_name = "MS", default_value_t = 10_000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Connect an AF_UNIX stream (or seqpacket) socket to a pathname.
    /// `--expect` applies to the `connect`.
    UnixConnect {
        path: OsString,
        /// SOCK_SEQPACKET instead of SOCK_STREAM (Linux).
        #[arg(long)]
        seqpacket: bool,
        #[arg(long, value_enum, default_value_t = UnixLen::Nul)]
        len: UnixLen,
        /// After connecting, send one line and wait for it to come back.
        #[arg(long)]
        exchange: bool,
        #[arg(long, value_name = "MS", default_value_t = 5000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Connect an AF_UNIX stream (or seqpacket) socket to an abstract name
    /// (Linux). NAME is the name without the leading NUL.
    UnixAbstractConnect {
        name: OsString,
        #[arg(long)]
        seqpacket: bool,
        #[arg(long)]
        exchange: bool,
        #[arg(long, value_name = "MS", default_value_t = 5000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Bind PATH, listen, then accept N connections and echo one line (one
    /// record for seqpacket) on each. The `listen` line is written before
    /// the first accept, so a reader can synchronise on it. With a trailing
    /// `-- ARGV`, that program is started once the socket listens (so it
    /// cannot race the bind) and waited for at the end. `--expect` applies to
    /// the `bind`.
    UnixListen {
        path: OsString,
        #[arg(long)]
        seqpacket: bool,
        #[arg(long, value_name = "N")]
        accept: u32,
        #[arg(long, value_name = "MS", default_value_t = 10_000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
        #[arg(last = true, num_args = 0.., value_name = "ARGV")]
        spawn: Vec<OsString>,
    },
    /// Create an AF_UNIX SOCK_DGRAM socket and report the result.
    UnixSocketDgram {
        /// Ask for SOCK_RAW, which Linux treats as SOCK_DGRAM for AF_UNIX.
        #[arg(long)]
        raw: bool,
        /// OR SOCK_CLOEXEC into the type argument (Linux).
        #[arg(long)]
        cloexec: bool,
        /// OR SOCK_NONBLOCK into the type argument (Linux).
        #[arg(long)]
        nonblock: bool,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Create an AF_UNIX SOCK_DGRAM socket pair and report the result.
    UnixSocketpairDgram {
        #[arg(long)]
        raw: bool,
        #[arg(long)]
        cloexec: bool,
        #[arg(long)]
        nonblock: bool,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Open FD_PATH read-only, connect a stream socket to SOCKET_PATH and send
    /// the descriptor with SCM_RIGHTS. `--expect` applies to the `connect`.
    ScmSend {
        #[arg(value_name = "SOCKET_PATH")]
        socket: OsString,
        #[arg(value_name = "FD_PATH")]
        fd_path: OsString,
        #[arg(long, default_value = "ok")]
        expect: Expect,
    },
    /// Bind PATH, listen, accept one connection, receive descriptors with
    /// SCM_RIGHTS and report each one's `fstat` file type. A trailing
    /// `-- ARGV` is started once the socket listens, as for `unix-listen`.
    /// `--expect` applies to the `bind`.
    ScmRecv {
        path: OsString,
        #[arg(long, value_name = "MS", default_value_t = 10_000)]
        timeout_ms: u64,
        #[arg(long, default_value = "ok")]
        expect: Expect,
        #[arg(last = true, num_args = 0.., value_name = "ARGV")]
        spawn: Vec<OsString>,
    },
    /// Wrap a command the way a vendor agent's own sandbox wraps its tools
    /// (Linux): set no_new_privs, install a Landlock ruleset granting the
    /// listed trees, install a seccomp filter returning EPERM for the listed
    /// syscalls (x86_64 numbers, architecture checked), report each step, then
    /// replace this process with ARGV. Any failed step stops before the exec.
    SandboxExec {
        /// Grant every filesystem right beneath DIR.
        #[arg(long = "landlock-rw", value_name = "DIR")]
        landlock_rw: Vec<OsString>,
        /// Grant execute, read-file and read-dir beneath DIR.
        #[arg(long = "landlock-ro", value_name = "DIR")]
        landlock_ro: Vec<OsString>,
        /// Handle LANDLOCK_ACCESS_NET_CONNECT_TCP with no port rule, so every
        /// TCP connect is denied. Needs Landlock ABI 4.
        #[arg(long)]
        landlock_deny_tcp: bool,
        /// Return EPERM for this syscall (an x86_64 name, or a number).
        #[arg(long = "seccomp-errno", value_name = "SYSCALL")]
        seccomp_errno: Vec<String>,
        #[arg(last = true, required = true, num_args = 1.., value_name = "ARGV")]
        argv: Vec<OsString>,
    },
    /// Fork, exec ARGV in the child, wait. Reports the exec result and the
    /// child's raw wait status as two lines.
    Exec {
        #[arg(long, value_enum, default_value_t = ExecVia::Execve)]
        via: ExecVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
        #[arg(last = true, required = true, num_args = 1.., value_name = "ARGV")]
        argv: Vec<OsString>,
    },
    /// Replace this process image with ARGV. On success nothing is reported:
    /// the reporting process no longer exists, which is the point.
    ExecReplace {
        #[arg(long, value_enum, default_value_t = ExecVia::Execve)]
        via: ExecVia,
        #[arg(long, default_value = "ok")]
        expect: Expect,
        #[arg(last = true, required = true, num_args = 1.., value_name = "ARGV")]
        argv: Vec<OsString>,
    },
    /// Report, then sleep MS milliseconds.
    Sleep { ms: u64 },
    /// Report, then burn CPU for MS milliseconds.
    Spin { ms: u64 },
    /// Report, then spawn a detached descendant in its own session that
    /// outlives this process, and exit 0.
    Background {
        ms: u64,
        #[arg(last = true, num_args = 0.., value_name = "ARGV")]
        argv: Vec<OsString>,
    },
    /// Ignore SIGTERM, report, then sleep MS milliseconds.
    IgnoreTerm { ms: u64 },
    /// Fork N children that exit immediately, and reap them all.
    ForkStorm { count: u32 },
    /// Report the trailing arguments as exact length-prefixed bytes.
    EchoArgs {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        argv: Vec<OsString>,
    },
    /// Write N bytes of a deterministic pattern to stdout.
    StdoutBytes { count: u64 },
    /// Write N bytes of a deterministic pattern to stderr.
    StderrBytes { count: u64 },
    /// Report the sorted names of the environment. Never a value.
    Env,
    /// Report every open descriptor and its kind. Never a path.
    Fds,
    /// Report the privilege-relevant fields of `/proc/self/status` (Linux).
    Status,
    /// Open PATH, write through the descriptor, then through a shared mapping.
    WriteMmap { path: OsString },
    /// Spawn one thread, have it run, and join it.
    Thread,
    /// Report, then exit with CODE.
    Exit { code: i32 },
    /// Report, then raise SIGNAL on self (name without `SIG`, or a number).
    Raise { signal: String },
    /// Run a JSON array of argv arrays in this one process.
    Script { file: OsString },
}

/// Parse an octal mode string.
pub fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8).map_err(|_| format!("`{s}` is not an octal mode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ouro-fixture").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn open_defaults_to_openat_and_expects_success() {
        let cli = parse(&["open", "/tmp/x"]);
        assert_eq!(cli.report_fd, 1);
        match cli.mode {
            Mode::Open {
                via, expect, mode, ..
            } => {
                assert_eq!(via, OpenVia::Openat);
                assert_eq!(expect, Expect::Ok);
                assert_eq!(parse_mode(&mode).unwrap(), 0o600);
            }
            other => panic!("wrong mode: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_expectation_is_a_parse_error() {
        let e = Cli::try_parse_from(["ouro-fixture", "open", "/tmp/x", "--expect", "ENOPE"])
            .unwrap_err();
        assert!(e.to_string().contains("unknown expectation"), "{e}");
    }

    #[test]
    fn exec_argv_only_comes_after_a_double_dash() {
        let cli = parse(&["exec", "--", "/bin/echo", "-n", "hi"]);
        match cli.mode {
            Mode::Exec { argv, .. } => assert_eq!(argv, ["/bin/echo", "-n", "hi"]),
            other => panic!("wrong mode: {other:?}"),
        }
        assert!(Cli::try_parse_from(["ouro-fixture", "exec"]).is_err());
    }

    #[test]
    fn echo_args_keeps_hyphenated_and_metacharacter_arguments() {
        let cli = parse(&["echo-args", "--", "-x", "a b", "$(id)", "a\nb"]);
        match cli.mode {
            Mode::EchoArgs { argv } => assert_eq!(argv, ["-x", "a b", "$(id)", "a\nb"]),
            other => panic!("wrong mode: {other:?}"),
        }
    }

    #[test]
    fn a_script_step_parses_exactly_like_a_process_argv() {
        let step =
            Step::try_parse_from(["ouro-fixture", "mkdir", "/tmp/d", "--via", "mkdir"]).unwrap();
        match step.mode {
            Mode::Mkdir { via, .. } => assert_eq!(via, MkdirVia::Mkdir),
            other => panic!("wrong mode: {other:?}"),
        }
    }

    #[test]
    fn mknod_defaults_to_mknodat_and_a_fifo() {
        let cli = parse(&["mknod", "/tmp/p"]);
        match cli.mode {
            Mode::Mknod {
                via,
                fifo,
                regular,
                mode,
                expect,
                ..
            } => {
                assert_eq!(via, MknodVia::Mknodat);
                assert!(!fifo, "the flag is off; the kind still defaults to a fifo");
                assert!(!regular);
                assert_eq!(parse_mode(&mode).unwrap(), 0o600);
                assert_eq!(expect, Expect::Ok);
            }
            other => panic!("wrong mode: {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["ouro-fixture", "mknod", "/tmp/p", "--fifo", "--regular"])
                .is_err(),
            "the two kinds are mutually exclusive"
        );
    }

    #[test]
    fn the_truncation_modes_take_a_signed_length() {
        match parse(&["truncate", "/tmp/f", "4096"]).mode {
            Mode::Truncate { length, .. } => assert_eq!(length, 4096),
            other => panic!("wrong mode: {other:?}"),
        }
        match parse(&["ftruncate", "/tmp/f", "0"]).mode {
            Mode::Ftruncate { length, .. } => assert_eq!(length, 0),
            other => panic!("wrong mode: {other:?}"),
        }
        // A negative length must reach the kernel, which answers EINVAL; the
        // fixture does not pre-judge it.
        match parse(&["truncate", "/tmp/f", "--", "-1"]).mode {
            Mode::Truncate { length, .. } => assert_eq!(length, -1),
            other => panic!("wrong mode: {other:?}"),
        }
    }

    #[test]
    fn octal_modes_parse_as_octal() {
        assert_eq!(parse_mode("600").unwrap(), 0o600);
        assert_eq!(parse_mode("0755").unwrap(), 0o755);
        assert!(parse_mode("9").is_err());
    }

    #[test]
    fn report_fd_and_no_report_are_available_to_every_mode() {
        let cli = parse(&["--report-fd", "7", "--no-report", "env"]);
        assert_eq!(cli.report_fd, 7);
        assert!(cli.no_report);
    }
}
