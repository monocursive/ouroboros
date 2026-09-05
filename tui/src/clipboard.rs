//! Reading an image out of the system clipboard, for `Ctrl+V` in the composer (B4).
//!
//! There is no portable clipboard API here and deliberately no clipboard *crate*: `ouro`
//! already shells out for `pbcopy` and OSC 52 on the way out, and a crate that links
//! against X11 or AppKit to do the same thing would trade one dependency on the operator's
//! environment for a larger one on this binary's.
//!
//! So this module runs the tool the machine actually has. Two rules make that honest:
//!
//! * **Probe, never assume.** Every candidate is checked with `command -v` before it is
//!   run. A machine with none of them is told so, once, rather than silently doing nothing
//!   — an undiscoverable non-feature is the OpenCode-fork-keybind mistake (R1 §4d(8)).
//! * **Fall through, never swallow.** A clipboard holding text and no image is an ordinary
//!   paste, and it is performed as one. `Ctrl+V` never becomes a key that does nothing
//!   because the operator copied a sentence instead of a screenshot.
//!
//! Everything is bounded: [`IMAGE_LIMIT`] bytes read at all, [`TIMEOUT`] for the tool, and
//! the file is written `0600` with `O_NOFOLLOW` under a directory this process creates.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

/// The largest clipboard image this client will carry into a turn.
///
/// The wire has no byte cap on outbound payloads (X6) and an attachment is a *path*, so
/// this bounds the file rather than the frame — but a 200 MB screenshot in a session's
/// workspace is still a surprise nobody asked for, and the number has to be somewhere.
pub const IMAGE_LIMIT: usize = 16 * 1024 * 1024;

/// How long a clipboard tool gets. Long enough for `osascript` to start, short enough that
/// a wedged helper does not become a wedged composer.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Where in the session workspace pasted images are kept.
///
/// Inside the workspace because that is the only place the runtime will take an attachment
/// from: `authorize_turn_attachments` canonicalises every path against the session's
/// workspace root and refuses an outsider. A file under this client's own data directory
/// would be refused by the runtime the moment it was attached.
pub const IMAGE_DIR: &str = ".ouroboros/images";

/// Where a tool puts what it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// The bytes arrive on stdout (`wl-paste`, `xclip`, `pngpaste -`).
    Stdout,
    /// The tool writes the file itself, at the path substituted for `{}` in its arguments
    /// (`osascript`, which cannot put binary on stdout).
    File,
}

/// One way of asking this machine for the clipboard's image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reader {
    pub program: String,
    pub args: Vec<String>,
    pub sink: Sink,
}

impl Reader {
    pub fn stdout(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            sink: Sink::Stdout,
        }
    }

    pub fn file(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            sink: Sink::File,
        }
    }
}

/// What the clipboard turned out to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Clip {
    /// PNG bytes, already bounded.
    Image(Vec<u8>),
    /// No image; this is the text, for the ordinary paste path.
    Text(String),
    /// Nothing this client can read, and nothing to say about it beyond that.
    Empty,
    /// This machine has none of the tools. Said once, by the caller.
    NoTool,
}

/// The image readers to try, in order, on this platform.
///
/// `OURO_CLIPBOARD_IMAGE_COMMAND` overrides the list with one `sh -c` command whose stdout
/// is the image. It exists so this path can be exercised end to end without a desktop
/// session — a test injects the command — and it is documented rather than hidden because
/// an operator on a platform none of the probes cover deserves the same escape hatch.
pub fn image_readers() -> Vec<Reader> {
    if let Some(command) = std::env::var("OURO_CLIPBOARD_IMAGE_COMMAND")
        .ok()
        .map(|command| command.trim().to_string())
        .filter(|command| !command.is_empty())
    {
        return vec![Reader::stdout("sh", &["-c", &command])];
    }

    if cfg!(target_os = "macos") {
        return vec![
            // Homebrew's `pngpaste`, which is the only macOS tool that puts the image on
            // stdout. Tried first because it needs no temporary file.
            Reader::stdout("pngpaste", &["-"]),
            // Always present on macOS. AppleScript cannot write binary to stdout, so it
            // writes the file itself at the path substituted for `{}`.
            Reader::file(
                "osascript",
                &[
                    "-e",
                    "set png to (the clipboard as «class PNGf»)",
                    "-e",
                    "set handle to open for access POSIX file \"{}\" with write permission",
                    "-e",
                    "write png to handle",
                    "-e",
                    "close access handle",
                ],
            ),
        ];
    }

    vec![
        Reader::stdout("wl-paste", &["--no-newline", "--type", "image/png"]),
        Reader::stdout(
            "xclip",
            &["-selection", "clipboard", "-t", "image/png", "-o"],
        ),
    ]
}

/// The text readers, for the fall-through when the clipboard holds no image.
pub fn text_readers() -> Vec<Reader> {
    if cfg!(target_os = "macos") {
        return vec![Reader::stdout("pbpaste", &[])];
    }

    vec![
        Reader::stdout("wl-paste", &["--no-newline"]),
        Reader::stdout("xclip", &["-selection", "clipboard", "-o"]),
    ]
}

/// Whether this machine has `program` at all. `command -v` through `sh`, because that is
/// the one spelling every POSIX shell agrees on.
pub fn available(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program} >/dev/null 2>&1"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Reads the clipboard: an image if there is one, otherwise the text, otherwise nothing.
///
/// `scratch` is where a [`Sink::File`] reader is told to write. It is removed before this
/// returns whatever happened — the caller writes the real file itself, under the session
/// workspace, with the permissions it wants.
pub fn read(images: &[Reader], texts: &[Reader], scratch: &Path) -> Clip {
    let mut any_tool = false;

    for reader in images {
        if !available(&reader.program) {
            continue;
        }

        any_tool = true;

        match run(reader, scratch) {
            Ok(bytes) if !bytes.is_empty() => return Clip::Image(bytes),
            // An empty answer is the ordinary "no image on the clipboard" reply from every
            // one of these tools, and an error is the other one. Neither is a reason to
            // stop asking, and neither is worth a sentence: the fall-through below is what
            // the operator will see.
            _other => {}
        }
    }

    for reader in texts {
        if !available(&reader.program) {
            continue;
        }

        any_tool = true;

        if let Ok(bytes) = run(reader, scratch) {
            if let Ok(text) = String::from_utf8(bytes) {
                if !text.is_empty() {
                    return Clip::Text(text);
                }
            }
        }
    }

    if any_tool {
        Clip::Empty
    } else {
        Clip::NoTool
    }
}

/// Runs one reader and returns what it produced, bounded in bytes and wall time.
fn run(reader: &Reader, scratch: &Path) -> Result<Vec<u8>> {
    run_with_timeout(reader, scratch, TIMEOUT)
}

fn run_with_timeout(
    reader: &Reader,
    scratch: &Path,
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    let args = reader.args.iter().map(|arg| match reader.sink {
        Sink::File => arg.replace("{}", &scratch.to_string_lossy()),
        Sink::Stdout => arg.clone(),
    });

    let mut command = Command::new(&reader.program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(match reader.sink {
            Sink::Stdout => Stdio::piped(),
            Sink::File => Stdio::null(),
        })
        .stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("running {}", reader.program))?;

    let mut reader_thread = None;
    let mut receiver = None;

    if reader.sink == Sink::Stdout {
        let mut stdout = child.stdout.take().expect("a piped stdout");
        let (sender, output) = std::sync::mpsc::sync_channel(1);
        reader_thread = Some(std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = std::io::copy(
                &mut Read::by_ref(&mut stdout).take(IMAGE_LIMIT as u64 + 1),
                &mut bytes,
            )
            .map(|_| bytes);
            let _ = sender.send(result);
        }));
        receiver = Some(output);
    }

    let deadline = std::time::Instant::now() + timeout;
    let mut status = None;
    let mut captured = None;

    loop {
        if captured.is_none() {
            if let Some(output) = receiver.as_ref() {
                match output.try_recv() {
                    Ok(result) => captured = Some(result),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        captured = Some(Err(std::io::Error::other(
                            "clipboard output reader exited without a result",
                        )));
                    }
                }
            }
        }

        if let Some(Ok(bytes)) = captured.as_ref() {
            if bytes.len() > IMAGE_LIMIT {
                terminate_process_group(&mut child);
                if let Some(thread) = reader_thread.take() {
                    let _ = thread.join();
                }
                bail!("{} produced more than {IMAGE_LIMIT} bytes", reader.program);
            }
        }

        if reader.sink == Sink::File
            && std::fs::metadata(scratch).is_ok_and(|metadata| metadata.len() > IMAGE_LIMIT as u64)
        {
            terminate_process_group(&mut child);
            let _ = std::fs::remove_file(scratch);
            bail!("{} produced more than {IMAGE_LIMIT} bytes", reader.program);
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(result)) => status = Some(result),
                Ok(None) => {}
                Err(error) => {
                    terminate_process_group(&mut child);
                    return Err(error).with_context(|| format!("waiting for {}", reader.program));
                }
            }
        }

        let output_complete = reader.sink == Sink::File || captured.is_some();
        if status.is_some() && output_complete {
            break;
        }

        if std::time::Instant::now() >= deadline {
            terminate_process_group(&mut child);
            if let Some(thread) = reader_thread.take() {
                let _ = thread.join();
            }
            let _ = std::fs::remove_file(scratch);
            bail!("{} did not finish within {timeout:?}", reader.program);
        }

        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    if let Some(thread) = reader_thread {
        let _ = thread.join();
    }

    let status = status.expect("the completion condition requires a status");
    if !status.success() {
        let _ = std::fs::remove_file(scratch);
        bail!("{} exited with {status}", reader.program);
    }

    match reader.sink {
        Sink::Stdout => captured
            .expect("the completion condition requires captured output")
            .with_context(|| format!("reading stdout from {}", reader.program)),
        Sink::File => {
            let length = std::fs::metadata(scratch)
                .with_context(|| format!("inspecting what {} wrote", reader.program))?
                .len();

            if length > IMAGE_LIMIT as u64 {
                let _ = std::fs::remove_file(scratch);
                bail!("{} produced more than {IMAGE_LIMIT} bytes", reader.program);
            }

            let result = std::fs::read(scratch).with_context(|| {
                format!(
                    "reading what {} wrote to {}",
                    reader.program,
                    scratch.display()
                )
            });
            let _ = std::fs::remove_file(scratch);
            result
        }
    }
}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) {
    let group = -(child.id() as i32);
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }

    // The group may still contain pipe-holding descendants after the leader exited.
    // Always escalate the group after the grace; waiting only on `child` would recreate
    // the exact stdout-EOF hang this function exists to break.
    std::thread::sleep(std::time::Duration::from_millis(200));
    unsafe {
        libc::kill(group, libc::SIGKILL);
    }
    let _ = child.wait();
}
#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Whether these bytes are a PNG. The eight-byte signature, nothing cleverer: the file is
/// named `.png` and handed to a provider that will decode it, so a JPEG wearing the name
/// would be a lie this client told.
pub fn is_png(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a])
}

/// Writes `bytes` as `image-<id>.png` under the session workspace, `0600`.
///
/// Returns the path **relative to the workspace**, which is what the attachment carries:
/// the runtime canonicalises against its own copy of the workspace root, and a session on
/// another machine resolves the same relative path against a different absolute prefix.
pub fn write_image(workspace: &Path, id: &str, bytes: &[u8]) -> Result<String> {
    if !workspace.is_dir() {
        bail!(
            "this session's workspace ({}) is not a directory on this machine, so there is \
             nowhere here to put a pasted image",
            workspace.display()
        );
    }

    if bytes.len() > IMAGE_LIMIT {
        bail!(
            "the clipboard image is {} bytes; the limit is {IMAGE_LIMIT}",
            bytes.len()
        );
    }

    if !is_png(bytes) {
        bail!("the clipboard did not hold a PNG");
    }

    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("the clipboard image id is not a safe file-name component");
    }

    let workspace = std::fs::canonicalize(workspace)
        .with_context(|| format!("resolving workspace {}", workspace.display()))?;
    let ouroboros = open_private_child_dir(&workspace, ".ouroboros", 0o700)?;
    let images =
        open_private_child_dir_at(&ouroboros, "images", 0o700, &workspace.join(".ouroboros"))?;
    ignore_in_git(&ouroboros);

    let filename = format!("image-{id}.png");
    write_private_at(&images, &filename, bytes).with_context(|| {
        format!(
            "writing {}",
            workspace
                .join(".ouroboros/images")
                .join(&filename)
                .display()
        )
    })?;

    Ok(format!("{IMAGE_DIR}/{filename}"))
}

/// A pasted image lives inside the workspace because that is the only place the runtime
/// admits an attachment from — and a workspace is usually a repository. The client-owned
/// `.ouroboros/` directory ignores itself so a paste never lands in `git status`.
///
/// Every component is opened descriptor-relative with `O_NOFOLLOW`. A repository may
/// contain symlinks, but pasting an image must never follow one outside the workspace.
#[cfg(unix)]
fn open_private_child_dir(parent: &Path, name: &str, mode: u32) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .with_context(|| format!("opening workspace directory {}", parent.display()))?;

    open_private_child_dir_at(&parent_file, name, mode, parent)
}

#[cfg(unix)]
fn open_private_child_dir_at(
    parent: &std::fs::File,
    name: &str,
    mode: u32,
    display_parent: &Path,
) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;

    let name = CString::new(name).map_err(|_| anyhow::anyhow!("directory name contains NUL"))?;
    let mkdir_result =
        unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    let created = if mkdir_result == 0 {
        true
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| {
                format!(
                    "creating {}",
                    display_parent
                        .join(name.to_string_lossy().as_ref())
                        .display()
                )
            });
        }
        false
    };

    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "opening {} without following links",
                display_parent
                    .join(name.to_string_lossy().as_ref())
                    .display()
            )
        });
    }

    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    if created {
        directory
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| {
                format!(
                    "restricting {}",
                    display_parent
                        .join(name.to_string_lossy().as_ref())
                        .display()
                )
            })?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn ignore_in_git(directory: &std::fs::File) {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = CString::new(".gitignore").expect("static file name");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd == -1 {
        return;
    }

    let mut marker = unsafe { std::fs::File::from_raw_fd(fd) };
    let _ = marker.write_all(b"*\n").and_then(|()| marker.sync_all());
}

#[cfg(unix)]
fn write_private_at(directory: &std::fs::File, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = CString::new(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file name contains NUL")
    })?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn open_private_child_dir(_parent: &Path, _name: &str, _mode: u32) -> Result<std::fs::File> {
    bail!("clipboard image persistence requires a Unix filesystem")
}

/// A scratch path for a [`Sink::File`] reader, in this process's own temporary directory.
pub fn scratch_path(id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ouro-clipboard-{id}.png"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-pixel PNG, so the signature check has something real to accept.
    const PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D',
        b'R',
    ];

    fn shell(script: &str) -> Reader {
        Reader::stdout("sh", &["-c", script])
    }

    #[test]
    fn a_stdout_reader_that_produces_bytes_is_an_image() {
        let reader = shell(r"printf '\211PNG\r\n\032\n'");
        let clip = read(&[reader], &[], &scratch_path("test-a"));

        assert!(matches!(clip, Clip::Image(bytes) if is_png(&bytes)));
    }

    #[test]
    fn an_empty_image_reader_falls_through_to_the_text_one() {
        let clip = read(
            &[shell("true")],
            &[shell("printf 'a pasted sentence'")],
            &scratch_path("test-b"),
        );

        assert_eq!(clip, Clip::Text("a pasted sentence".into()));
    }

    /// The whole point of probing: a machine with none of these tools is told so rather
    /// than left with a key that appears to do nothing.
    #[test]
    fn a_machine_with_no_tool_at_all_says_so_rather_than_reporting_an_empty_clipboard() {
        let missing = Reader::stdout("ouro-no-such-clipboard-tool", &[]);
        assert_eq!(
            read(
                std::slice::from_ref(&missing),
                std::slice::from_ref(&missing),
                &scratch_path("test-c")
            ),
            Clip::NoTool
        );
    }

    #[test]
    fn a_reader_that_writes_the_file_itself_is_read_back_and_the_scratch_removed() {
        let scratch = scratch_path("test-d");
        let _ = std::fs::remove_file(&scratch);

        let reader = Reader::file("sh", &["-c", r"printf '\211PNG\r\n\032\n' > '{}'"]);
        let clip = read(&[reader], &[], &scratch);

        assert!(matches!(&clip, Clip::Image(bytes) if is_png(bytes)));
        assert!(!scratch.exists(), "the scratch file is not left behind");
    }

    #[test]
    fn a_tool_that_produces_more_than_the_limit_is_refused_rather_than_read() {
        let reader = shell(&format!("head -c {} /dev/zero", IMAGE_LIMIT + 4_096));

        // Nothing usable came back, and nothing was buffered past the bound.
        assert_eq!(read(&[reader], &[], &scratch_path("test-e")), Clip::Empty);
    }

    #[test]
    fn a_file_reader_is_stopped_before_an_oversized_file_is_read() {
        let scratch = scratch_path("test-file-limit");
        let _ = std::fs::remove_file(&scratch);
        // Size enforcement is independent of how quickly a helper fills the file.
        // A sparse fixture avoids writing 20 MiB on the shared test runner's deadline.
        std::fs::File::create(&scratch)
            .unwrap()
            .set_len((IMAGE_LIMIT + 4_096) as u64)
            .unwrap();
        let reader = Reader::file("sh", &["-c", ":"]);

        let error = run_with_timeout(&reader, &scratch, TIMEOUT).expect_err("the size limit");

        assert!(error.to_string().contains("more than"), "{error:#}");
        assert!(!scratch.exists(), "the oversized scratch file is removed");
    }

    #[test]
    fn a_stdout_reader_and_its_background_child_obey_the_wall_time_bound() {
        let reader = shell("sleep 30 & wait");
        let started = std::time::Instant::now();
        let error = run_with_timeout(
            &reader,
            &scratch_path("test-timeout"),
            std::time::Duration::from_millis(100),
        )
        .expect_err("a timeout");

        assert!(error.to_string().contains("did not finish"), "{error:#}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "clipboard timeout took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_image_is_written_private_and_named_relative_to_the_workspace() {
        let workspace = std::env::temp_dir().join(format!("ouro-clip-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).expect("a workspace");

        let relative = write_image(&workspace, "01ARZ3", PNG).expect("a written image");
        assert_eq!(relative, ".ouroboros/images/image-01ARZ3.png");

        let path = workspace.join(&relative);
        assert_eq!(std::fs::read(&path).expect("the file"), PNG);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the image is private to this operator");
        }

        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn the_client_owned_directory_ignores_itself_so_a_paste_never_reaches_git_status() {
        let workspace =
            std::env::temp_dir().join(format!("ouro-clip-ignore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).expect("a workspace");
        write_image(&workspace, "01IGNORE", PNG).expect("an image");
        let marker =
            std::fs::read_to_string(workspace.join(".ouroboros/.gitignore")).expect("the marker");
        assert_eq!(marker, "*\n");
        // Written once: an operator's edit is kept.
        std::fs::write(workspace.join(".ouroboros/.gitignore"), "images/\n").unwrap();
        write_image(&workspace, "01IGNOR2", PNG).expect("a second image");
        assert_eq!(
            std::fs::read_to_string(workspace.join(".ouroboros/.gitignore")).unwrap(),
            "images/\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_workspace_symlink_cannot_redirect_clipboard_writes() {
        let root = std::env::temp_dir().join(format!("ouro-clip-link-{}", std::process::id()));
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join(".ouroboros")).unwrap();

        let error = write_image(&workspace, "01LINK", PNG).expect_err("a symlink refusal");
        assert!(
            error.to_string().contains("without following links"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_workspace_this_machine_cannot_see_is_refused_with_the_reason() {
        let missing = std::env::temp_dir().join("ouro-clip-no-such-workspace");
        let _ = std::fs::remove_dir_all(&missing);

        let error = write_image(&missing, "01ARZ3", PNG).expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("not a directory on this machine"),
            "{error}"
        );
    }

    #[test]
    fn something_that_is_not_a_png_is_never_written_under_a_png_name() {
        let workspace = std::env::temp_dir().join(format!("ouro-clip-jp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).expect("a workspace");

        let error =
            write_image(&workspace, "01ARZ3", b"\xff\xd8\xff not a png").expect_err("a refusal");
        assert!(error.to_string().contains("did not hold a PNG"), "{error}");

        let _ = std::fs::remove_dir_all(&workspace);
    }
}
