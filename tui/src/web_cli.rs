//! `ouro web` — the one-time link to this daemon's browser surface (docs/WEB.md D14).
//!
//! The command is small on purpose. Everything hard about finding a runtime already
//! exists: `main.rs` adopts or starts one through the spawn lock and the launcher, exactly
//! as the bare `ouro` does, and hands the result here. What is left is discovery of a
//! *second* publication, one credential read, and a URL.
//!
//! ## Why there is a wait at all
//!
//! `gateway.json` and `web.json` are written by two different children of the same
//! supervision tree, and `Ouroboros.Web` is the last child of all
//! (`lib/ouroboros/application.ex`). So a runtime that has just published its gateway port
//! — which is the moment a spawn is judged ready — has not necessarily bound the browser
//! endpoint yet. The gap is the tail of a supervision tree starting, not a boot, which is
//! what makes [`PUBLICATION_WAIT`] seconds rather than the minutes a cold start is given.
//!
//! ## The URL carries the credential, and says so
//!
//! `GET /auth?token=…` is the one request that presents the operator token; the endpoint
//! exchanges it for a session cookie and redirects (`Ouroboros.Web.Auth`). That makes this
//! string exactly as sensitive as the token file it was read from, which is why the
//! failure paths here print it and stop rather than writing it anywhere.
//!
//! The desktop client's HTTPS-only rule for `open_url` deliberately does not apply. That
//! guard exists because the URL came off a stream from a provider; this one is composed
//! locally from a 0600 file this client just read, and `http://127.0.0.1` is the only
//! address the endpoint binds by default.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

use crate::runtime::{self, WebPublication};
use crate::ui::boot::BootProgress;

/// How long a runtime that is up but has not published `web.json` is given. Long enough to
/// cover a loaded machine finishing its supervision tree, short enough that a daemon
/// serving no browser surface is reported as such rather than hung on.
pub const PUBLICATION_WAIT: Duration = Duration::from_secs(10);

/// The gap between reads while waiting. Cheap: one `stat` and at most a 16 KiB read.
const POLL: Duration = Duration::from_millis(100);

/// What `ouro web` says when there is no runtime and none could be started. Context onto
/// the launcher's own error, which says what actually failed.
pub const NO_RUNTIME_REFUSAL: &str =
    "`ouro web` opens the browser surface a local daemon serves, so it needs a runtime on \
     this machine: it adopts the one this data directory already has, or starts one, the \
     same way the bare `ouro` command does. Neither was possible";

/// How the URL reaches a browser, behind a trait so the tests can watch it being asked
/// without a window opening on whoever is running them.
pub trait Opener {
    fn open(&self, url: &str) -> std::io::Result<()>;
}

/// The platform's own handler: `open` on macOS, `xdg-open` everywhere else — the same pair
/// [`crate::ui`] spawns for a sign-in URL, and spawned the same way, without waiting. A
/// browser is a window the operator closes when they are done, and a command that blocked
/// on it would be a shell that never came back.
pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &str) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        let program = "open";
        #[cfg(not(target_os = "macos"))]
        let program = "xdg-open";

        Command::new(program).arg(url).spawn().map(|_| ())
    }
}

/// Everything this command does once a runtime is up: find the endpoint, read the
/// credential it names, build the link, and hand it over.
pub async fn open<O: Write, E: Write>(
    data_dir: &Path,
    default_token_file: &Path,
    print_only: bool,
    opener: &dyn Opener,
    out: &mut O,
    err: &mut E,
) -> Result<()> {
    let publication = wait_for_publication(data_dir, PUBLICATION_WAIT).await?;
    let token_path = token_file(&publication, default_token_file);
    let token =
        runtime::read_token(&token_path).with_context(|| unreadable_token_refusal(&token_path))?;

    present(
        &auth_url(publication.port, token.expose()),
        print_only,
        opener,
        out,
        err,
    )
}

/// Prints the URL, and opens it unless `--print` asked for the string alone.
///
/// The print happens first in both cases, and unconditionally. An operator whose browser
/// did not appear still has the link, and one whose browser did has it in their scrollback
/// for the second tab.
pub fn present<O: Write, E: Write>(
    url: &str,
    print_only: bool,
    opener: &dyn Opener,
    out: &mut O,
    err: &mut E,
) -> Result<()> {
    writeln!(out, "{url}")?;
    out.flush()?;

    if print_only {
        return Ok(());
    }

    if let Err(error) = opener.open(url) {
        writeln!(err, "{}", opener_failure(&error.to_string()))?;
        err.flush()?;
    }

    Ok(())
}

/// Polls for `web.json` until it appears or the budget runs out.
pub async fn wait_for_publication(data_dir: &Path, budget: Duration) -> Result<WebPublication> {
    let deadline = Instant::now() + budget;

    loop {
        if let Some(publication) = runtime::read_live_web_publication(data_dir)? {
            return Ok(publication);
        }

        if Instant::now() >= deadline {
            let path = data_dir.join(runtime::WEB_PUBLICATION_FILE);

            // A file that is there and stale is a different situation from one that never
            // appeared, and an operator who is told the wrong one debugs the wrong thing.
            return Err(anyhow!(match runtime::read_web_publication(data_dir)? {
                Some(stale) => stale_publication_refusal(&path, stale.pid),
                None => missing_publication_refusal(&path, budget),
            }));
        }

        tokio::time::sleep(POLL).await;
    }
}

/// The credential file to read: the one the endpoint published, and otherwise the
/// gateway's own beside it.
///
/// `web.json` names a path exactly when a file supplied the token, so an absent key means
/// the endpoint was configured with `OUROBOROS_WEB_TOKEN` and there is genuinely no file
/// to point at. Falling back to `gateway.token` is right for the posture this client
/// spawns — one operator credential per data directory, shared by both surfaces — and is a
/// guess anywhere else, which is why the refusal names the file it tried.
pub fn token_file(publication: &WebPublication, default: &Path) -> PathBuf {
    publication
        .token_file
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map_or_else(|| default.to_path_buf(), PathBuf::from)
}

/// The one URL this command exists to produce: the loopback endpoint's token exchange.
///
/// Loopback is not a guess about where the endpoint is — it is where `Ouroboros.Web.Config`
/// binds unless an operator typed `OUROBOROS_WEB_ALLOW_REMOTE=1`, and `web.json` publishes
/// the port without the address, so a daemon deliberately bound elsewhere is one whose URL
/// this client could not name even if it tried. The remote posture documented in
/// docs/WEB.md D5 is a proxy in front of this bind, which the operator reaches by its own
/// name and not by this link.
pub fn auth_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/auth?token={}", encode_query(token))
}

/// What `ouro web` says when the runtime is up and no browser surface came with it.
pub fn missing_publication_refusal(path: &Path, budget: Duration) -> String {
    format!(
        "this runtime published no {} within {}s, so it is serving no browser surface. The \
         likeliest cause is OUROBOROS_WEB=0 in the environment the daemon was started \
         from — that variable is the documented opt-out — and the next likeliest is a \
         daemon started by something other than `ouro`, which was never told to serve one \
         at all. Check that variable, then `ouro stop` and `ouro web` to start a runtime \
         that serves it.",
        path.display(),
        budget.as_secs()
    )
}

/// The same situation, for a `web.json` that is present and belongs to a process that is
/// gone. `Ouroboros.Web.Publication` removes the file on an orderly stop and a killed node
/// removes nothing, which is why the pid is worth naming.
pub fn stale_publication_refusal(path: &Path, pid: i32) -> String {
    format!(
        "{} was left behind by pid {pid}, which is gone, and the runtime serving this data \
         directory now has published nothing in its place — so there is no browser surface \
         to open. The likeliest cause is OUROBOROS_WEB=0 in the environment *that* runtime \
         was started from. Check it there, then `ouro stop` and `ouro web` to start one \
         that serves it.",
        path.display()
    )
}

/// What `ouro web` says when the credential the publication names cannot be read. The
/// reader's own refusal follows this as the cause, and says which rule the file broke.
pub fn unreadable_token_refusal(path: &Path) -> String {
    format!(
        "the browser surface authenticates with the token in {}, and this client cannot \
         read it, so it has no credential to put in the link. web.json names the token \
         file rather than the token, and that file is held to the rule the gateway's own \
         credential is held to: a regular file at mode 0600 owned by you",
        path.display()
    )
}

/// What it says when the URL is built and the browser is not. Print-only is a complete
/// outcome, not a half-failure, so this is a sentence on stderr and not an error.
pub fn opener_failure(cause: &str) -> String {
    format!(
        "ouro web: the browser could not be started ({cause}); the URL above is the whole \
         of it — paste it into a browser on this machine. It carries the operator token, \
         so treat it like the credential it is."
    )
}

/// The boot's own lines, on stderr. Stdout here is one URL and a script may be reading it,
/// which is the same reason `ouro run` sends these to stderr.
pub fn report_boot<E: Write>(boot: &Mutex<BootProgress>, err: &mut E) {
    let Ok(mut boot) = boot.lock() else {
        return;
    };

    boot.settle();

    for line in boot
        .warnings()
        .iter()
        .cloned()
        .chain(boot.steps().iter().map(|step| step.label.clone()))
    {
        let _ = writeln!(err, "ouro web: {line}");
    }
}

/// Percent-encodes one query-string value.
///
/// The token this client writes is 64 hex characters and nothing else, so in the ordinary
/// case this changes not a byte. It is here for the token it did *not* write:
/// `OUROBOROS_WEB_TOKEN_FILE` may name any 0600 file an operator chose, and an `&` or a
/// `#` in one would truncate the credential silently rather than fail loudly. Unreserved
/// characters (RFC 3986 §2.3) pass through; every other byte is escaped.
fn encode_query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());

    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Mutex as StdMutex;

    /// An opener that records instead of launching, so no test can put a window on a
    /// developer's screen or a browser tab in CI.
    struct RecordingOpener {
        opened: StdMutex<Vec<String>>,
        outcome: Option<std::io::ErrorKind>,
    }

    impl RecordingOpener {
        fn working() -> Self {
            Self {
                opened: StdMutex::new(Vec::new()),
                outcome: None,
            }
        }

        fn failing() -> Self {
            Self {
                opened: StdMutex::new(Vec::new()),
                outcome: Some(std::io::ErrorKind::NotFound),
            }
        }

        fn opened(&self) -> Vec<String> {
            self.opened.lock().expect("the recording lock").clone()
        }
    }

    impl Opener for RecordingOpener {
        fn open(&self, url: &str) -> std::io::Result<()> {
            self.opened
                .lock()
                .expect("the recording lock")
                .push(url.to_string());

            match self.outcome {
                Some(kind) => Err(std::io::Error::new(kind, "no opener on this machine")),
                None => Ok(()),
            }
        }
    }

    fn publication(token_file: Option<&str>) -> WebPublication {
        WebPublication {
            port: 4321,
            protocol: 1,
            node: "nonode@nohost".into(),
            pid: 42,
            scope: "operate".into(),
            token_file: token_file.map(str::to_string),
        }
    }

    #[test]
    fn the_url_names_the_published_port_and_the_auth_exchange() {
        assert_eq!(
            auth_url(4321, "a1b2c3"),
            "http://127.0.0.1:4321/auth?token=a1b2c3"
        );
        assert_eq!(
            auth_url(65535, "0123456789abcdef"),
            "http://127.0.0.1:65535/auth?token=0123456789abcdef"
        );
    }

    #[test]
    fn a_token_that_is_not_hex_is_escaped_rather_than_truncated() {
        // `write_token` only ever produces hex, but OUROBOROS_WEB_TOKEN_FILE may name a
        // file an operator wrote, and an unescaped `&` would hand the endpoint a shorter
        // token than the one on disk — a refusal whose cause is invisible.
        assert_eq!(
            auth_url(80, "a&b=c#d e/f?g+h%i"),
            "http://127.0.0.1:80/auth?token=a%26b%3Dc%23d%20e%2Ff%3Fg%2Bh%25i"
        );

        // Unreserved characters are left exactly as they are: escaping them would be
        // correct and would still make a credential unrecognisable in a log.
        assert_eq!(encode_query("aZ0-._~"), "aZ0-._~");

        // Multi-byte UTF-8 escapes per byte, not per character.
        assert_eq!(encode_query("é"), "%C3%A9");
    }

    #[test]
    fn the_published_token_file_wins_and_the_data_dir_is_the_fallback() {
        let default = Path::new("/data/gateway.token");

        assert_eq!(
            token_file(&publication(Some("/elsewhere/web.token")), default),
            PathBuf::from("/elsewhere/web.token")
        );

        // No key at all: the endpoint's token came from the environment, so there is no
        // file to name and the shared default is the only path worth trying.
        assert_eq!(token_file(&publication(None), default), default);

        // A blank or whitespace path is not a path. Reading it would refuse with a
        // message about "" rather than about the file the operator expected.
        assert_eq!(token_file(&publication(Some("   ")), default), default);
        assert_eq!(
            token_file(&publication(Some("  /trimmed.token  ")), default),
            PathBuf::from("/trimmed.token")
        );
    }

    #[test]
    fn print_only_writes_the_url_and_launches_nothing() {
        let opener = RecordingOpener::working();
        let mut out = Vec::new();
        let mut err = Vec::new();

        present(
            "http://127.0.0.1:4321/auth?token=abc",
            true,
            &opener,
            &mut out,
            &mut err,
        )
        .expect("a printed url");

        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "http://127.0.0.1:4321/auth?token=abc\n"
        );
        assert!(err.is_empty());
        assert!(opener.opened().is_empty(), "--print must open nothing");
    }

    #[test]
    fn without_print_the_url_is_both_printed_and_opened() {
        let opener = RecordingOpener::working();
        let mut out = Vec::new();
        let mut err = Vec::new();

        present(
            "http://127.0.0.1:4321/auth?token=abc",
            false,
            &opener,
            &mut out,
            &mut err,
        )
        .expect("a printed and opened url");

        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "http://127.0.0.1:4321/auth?token=abc\n"
        );
        assert!(err.is_empty());
        assert_eq!(
            opener.opened(),
            vec!["http://127.0.0.1:4321/auth?token=abc"]
        );
    }

    #[test]
    fn a_browser_that_will_not_start_leaves_the_url_and_a_sentence() {
        let opener = RecordingOpener::failing();
        let mut out = Vec::new();
        let mut err = Vec::new();

        present(
            "http://127.0.0.1:4321/auth?token=abc",
            false,
            &opener,
            &mut out,
            &mut err,
        )
        .expect("a failed opener is not a failed command");

        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "http://127.0.0.1:4321/auth?token=abc\n"
        );

        let message = String::from_utf8(err).expect("utf-8");
        assert!(message.contains("the browser could not be started"));
        assert!(message.contains("paste it into a browser"));
    }

    #[test]
    fn the_no_surface_refusals_name_the_variable_and_the_file() {
        let missing = missing_publication_refusal(
            Path::new("/data/ouroboros/web.json"),
            Duration::from_secs(10),
        );
        assert!(missing.contains("/data/ouroboros/web.json"));
        assert!(missing.contains("within 10s"));
        assert!(missing.contains("OUROBOROS_WEB=0"));
        assert!(missing.contains("`ouro stop`"));

        let stale = stale_publication_refusal(Path::new("/data/ouroboros/web.json"), 4242);
        assert!(stale.contains("/data/ouroboros/web.json"));
        assert!(stale.contains("pid 4242"));
        assert!(stale.contains("OUROBOROS_WEB=0"));

        let token = unreadable_token_refusal(Path::new("/data/ouroboros/gateway.token"));
        assert!(token.contains("/data/ouroboros/gateway.token"));
        assert!(token.contains("mode 0600"));

        assert!(NO_RUNTIME_REFUSAL.contains("`ouro web`"));
    }

    #[tokio::test]
    async fn the_wait_ends_in_the_refusal_that_matches_what_is_on_disk() {
        // `read_web_publication` creates the leaf at 0700 when it is absent, so naming a
        // path is enough to get the private directory its reader insists on.
        let dir = std::env::temp_dir().join(format!("ouro-test-web-wait-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();

        // Nothing published: the budget is spent and the refusal is the missing one. Zero
        // is a legitimate budget — one read, then the answer — and keeps this test's wall
        // clock at the cost of two `stat` calls.
        let error = wait_for_publication(&dir, Duration::ZERO)
            .await
            .expect_err("no publication");
        assert!(format!("{error:#}").contains("published no"));

        // Present, private, and belonging to a pid that cannot exist: the same wait, the
        // other sentence.
        let path = dir.join(runtime::WEB_PUBLICATION_FILE);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("a private publication");
        file.write_all(br#"{"port":4321,"pid":2147483646}"#)
            .expect("publication contents");
        drop(file);

        let error = wait_for_publication(&dir, Duration::ZERO)
            .await
            .expect_err("a stale publication");
        assert!(format!("{error:#}").contains("was left behind by pid 2147483646"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
