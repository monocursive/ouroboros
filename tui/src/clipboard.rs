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

/// Runs one reader and returns what it produced, bounded by [`IMAGE_LIMIT`].
fn run(reader: &Reader, scratch: &Path) -> Result<Vec<u8>> {
    let args = reader.args.iter().map(|arg| match reader.sink {
        Sink::File => arg.replace("{}", &scratch.to_string_lossy()),
        Sink::Stdout => arg.clone(),
    });

    let mut child = Command::new(&reader.program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(match reader.sink {
            Sink::Stdout => Stdio::piped(),
            Sink::File => Stdio::null(),
        })
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {}", reader.program))?;

    // Bounded on both axes: at most `IMAGE_LIMIT` bytes read, and at most `TIMEOUT`
    // waited. The read is what actually bounds a `Sink::Stdout` tool — a pipe that fills
    // makes the child block, and the kill below then ends it.
    let captured = match reader.sink {
        Sink::Stdout => {
            let mut stdout = child.stdout.take().expect("a piped stdout");
            let mut bytes = Vec::new();
            let read = std::io::copy(
                &mut Read::by_ref(&mut stdout).take(IMAGE_LIMIT as u64 + 1),
                &mut bytes,
            );

            if read.is_err() || bytes.len() > IMAGE_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{} produced more than {IMAGE_LIMIT} bytes", reader.program);
            }

            bytes
        }
        Sink::File => Vec::new(),
    };

    let deadline = std::time::Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{} did not finish within {TIMEOUT:?}", reader.program);
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(error) => {
                return Err(error).with_context(|| format!("waiting for {}", reader.program))
            }
        }
    };

    if !status.success() {
        bail!("{} exited with {status}", reader.program);
    }

    match reader.sink {
        Sink::Stdout => Ok(captured),
        Sink::File => {
            let bytes = std::fs::read(scratch).with_context(|| {
                format!(
                    "reading what {} wrote to {}",
                    reader.program,
                    scratch.display()
                )
            })?;
            let _ = std::fs::remove_file(scratch);

            if bytes.len() > IMAGE_LIMIT {
                bail!("{} produced more than {IMAGE_LIMIT} bytes", reader.program);
            }

            Ok(bytes)
        }
    }
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

    let directory = workspace.join(IMAGE_DIR);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    restrict(&directory, 0o700);

    let relative = format!("{IMAGE_DIR}/image-{id}.png");
    let path = workspace.join(&relative);
    write_private(&path, bytes).with_context(|| format!("writing {}", path.display()))?;

    Ok(relative)
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    file.write_all(bytes)?;
    file.sync_all()
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
