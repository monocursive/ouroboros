//! The scriptable status line: an operator's own command, fed the session's facts as
//! JSON, drawn in its own row above the footer.
//!
//! Claude Code's `statusLine` contract (R2 §5), narrowed to what this client can promise:
//! shell form, one JSON object on stdin, debounced, re-run only when that object changes,
//! bounded in time and bytes, first line rendered, ANSI permitted.
//!
//! ## Bounded everything
//!
//! This runs on every state change of a session that may be doing real work, so every
//! limit here is load-bearing rather than defensive: [`TIMEOUT`] stops a command that
//! blocks from stopping the UI, [`MAX_BYTES`] stops one that prints a core dump from
//! being buffered, and only the first line is drawn because the row is one row. A command
//! that fails is reported once and then leaves the row absent — a status line that
//! flickered an error at every tick would be worse than no status line.
//!
//! ## What it is not
//!
//! It decides nothing. Its output is text on a row; the footer beside it still comes from
//! the runtime's own declarations, and nothing this command prints changes what the
//! client does. It also runs on the machine the *client* is on, which is not necessarily
//! the machine the session is on — a fleet session's `git branch` is not this command's
//! to read.

use std::process::Stdio;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// How long a status-line command may take before it is abandoned. Claude Code's own
/// contract is 300 ms of debounce and a short leash; two seconds is generous for
/// `git branch --show-current` and short enough that a hung command is noticed.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How much of the command's stdout is read at all. Only the first line is drawn, but a
/// command that prints a megabyte before its first newline must not be buffered whole.
pub const MAX_BYTES: usize = 4 * 1024;

/// Runs the command with `payload` on stdin and answers its first line of stdout.
///
/// `Err` for every way this can fail — spawn, timeout, a non-zero exit with nothing on
/// stdout — with a sentence the caller reports once. `Ok("")` is possible and means the
/// command deliberately printed nothing, which renders as an absent row rather than a
/// blank one.
pub async fn run(command: &str, payload: &Value) -> Result<String, String> {
    match tokio::time::timeout(TIMEOUT, execute(command, payload)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(format!(
            "the statusline command did not finish within {}s",
            TIMEOUT.as_secs()
        )),
    }
}

async fn execute(command: &str, payload: &Value) -> Result<String, String> {
    let input = serde_json::to_vec(payload).map_err(|error| error.to_string())?;

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The command's own diagnostics belong in its own log, not interleaved with the
        // alternate screen this process is drawing into.
        .stderr(Stdio::null())
        // Abandoning a timed-out command without killing it would leave one process per
        // debounce window behind. This reaches `sh` itself; a command that backgrounds a
        // grandchild is beyond what a `kill` on the shell can reclaim, and that is a
        // limit of running arbitrary shell rather than something this can fix.
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("the statusline command could not be started: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        // A command that never reads stdin is ordinary; the write failing on its closed
        // pipe is not an error about the command's output.
        let _ = stdin.write_all(&input).await;
        let _ = stdin.shutdown().await;
    }

    let stdout = collect(&mut child).await?;
    let status = child.wait().await.ok();

    let first = first_line(&stdout);

    if first.is_empty() && status.is_some_and(|status| !status.success()) {
        return Err(format!(
            "the statusline command exited with {} and printed nothing",
            status.map(|status| status.to_string()).unwrap_or_default()
        ));
    }

    Ok(first)
}

async fn collect(child: &mut tokio::process::Child) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;

    let Some(mut stdout) = child.stdout.take() else {
        return Ok(Vec::new());
    };

    let mut collected = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];

    while collected.len() < MAX_BYTES {
        let read = stdout.read(&mut chunk).await.map_err(|error| {
            format!("the statusline command's output could not be read: {error}")
        })?;

        if read == 0 {
            break;
        }

        let room = MAX_BYTES - collected.len();
        collected.extend_from_slice(&chunk[..read.min(room)]);
    }

    Ok(collected)
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split(['\n', '\r'])
        .next()
        .unwrap_or("")
        .trim_end()
        .to_string()
}

/// Renders one line of possibly-ANSI text as styled spans.
///
/// SGR (`ESC [ … m`) is honoured because a status line without colour is a status line
/// people stop reading. Every other escape sequence is *removed* rather than passed
/// through: this text is drawn into a Ratatui buffer that owns the cursor and the screen,
/// and a command that emitted `ESC [ 2 J` would clear the frame around it. OSC 8
/// hyperlinks are dropped for the same reason — Ratatui has no cell attribute for them,
/// so passing the bytes through would print the URL as text.
pub fn render(text: &str) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut style = Style::default();
    let mut buffer = String::new();
    let mut chars = text.chars().peekable();

    while let Some(character) = chars.next() {
        if character != '\u{1b}' {
            // A stray control byte would move the cursor or ring the bell from inside a
            // cell. Dropped, not drawn.
            if !character.is_control() {
                buffer.push(character);
            }
            continue;
        }

        match chars.next() {
            // CSI. Consume the parameter and intermediate bytes up to the final byte.
            Some('[') => {
                let mut parameters = String::new();
                let mut final_byte = None;

                for character in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&character) {
                        final_byte = Some(character);
                        break;
                    }

                    parameters.push(character);
                }

                if final_byte == Some('m') {
                    if !buffer.is_empty() {
                        spans.push(Span::styled(std::mem::take(&mut buffer), style));
                    }

                    style = apply(style, &parameters);
                }
            }
            // OSC. Ends at BEL or ST; dropped whole.
            Some(']') => {
                while let Some(character) = chars.next() {
                    if character == '\u{7}' {
                        break;
                    }

                    if character == '\u{1b}' {
                        chars.next();
                        break;
                    }
                }
            }
            // A two-byte escape this client does not interpret.
            Some(_other) => {}
            None => break,
        }
    }

    if !buffer.is_empty() {
        spans.push(Span::styled(buffer, style));
    }

    Line::from(spans)
}

fn apply(style: Style, parameters: &str) -> Style {
    // `ESC [ m` is `ESC [ 0 m`.
    let parameters = if parameters.is_empty() {
        "0"
    } else {
        parameters
    };

    let codes: Vec<u16> = parameters
        .split(';')
        .map(|code| code.trim().parse::<u16>().unwrap_or(0))
        .collect();

    let mut style = style;
    let mut index = 0;

    while index < codes.len() {
        let code = codes[index];
        index += 1;

        match code {
            0 => style = Style::default(),
            1 => style = style.add_modifier(Modifier::BOLD),
            2 => style = style.add_modifier(Modifier::DIM),
            3 => style = style.add_modifier(Modifier::ITALIC),
            4 => style = style.add_modifier(Modifier::UNDERLINED),
            7 => style = style.add_modifier(Modifier::REVERSED),
            9 => style = style.add_modifier(Modifier::CROSSED_OUT),
            22 => style = style.remove_modifier(Modifier::BOLD | Modifier::DIM),
            23 => style = style.remove_modifier(Modifier::ITALIC),
            24 => style = style.remove_modifier(Modifier::UNDERLINED),
            27 => style = style.remove_modifier(Modifier::REVERSED),
            29 => style = style.remove_modifier(Modifier::CROSSED_OUT),
            30..=37 => style = style.fg(indexed(code - 30)),
            90..=97 => style = style.fg(indexed(code - 90 + 8)),
            40..=47 => style = style.bg(indexed(code - 40)),
            100..=107 => style = style.bg(indexed(code - 100 + 8)),
            39 => style = style.fg(Color::Reset),
            49 => style = style.bg(Color::Reset),
            38 | 48 => {
                let foreground = code == 38;
                match codes.get(index).copied() {
                    Some(5) => {
                        if let Some(&value) = codes.get(index + 1) {
                            let colour = Color::Indexed(value.min(255) as u8);
                            style = if foreground {
                                style.fg(colour)
                            } else {
                                style.bg(colour)
                            };
                        }
                        index += 2;
                    }
                    Some(2) => {
                        if let (Some(&r), Some(&g), Some(&b)) = (
                            codes.get(index + 1),
                            codes.get(index + 2),
                            codes.get(index + 3),
                        ) {
                            let colour =
                                Color::Rgb(r.min(255) as u8, g.min(255) as u8, b.min(255) as u8);
                            style = if foreground {
                                style.fg(colour)
                            } else {
                                style.bg(colour)
                            };
                        }
                        index += 4;
                    }
                    _unknown => break,
                }
            }
            // A parameter this build does not know is skipped rather than treated as a
            // reset: a newer SGR code must not silently drop the colours around it.
            _other => {}
        }
    }

    style
}

fn indexed(index: u16) -> Color {
    match index {
        0 => Color::Black,
        1 => Color::Red,
        2 => Color::Green,
        3 => Color::Yellow,
        4 => Color::Blue,
        5 => Color::Magenta,
        6 => Color::Cyan,
        7 => Color::Gray,
        8 => Color::DarkGray,
        9 => Color::LightRed,
        10 => Color::LightGreen,
        11 => Color::LightYellow,
        12 => Color::LightBlue,
        13 => Color::LightMagenta,
        14 => Color::LightCyan,
        _ => Color::White,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn sgr_becomes_style_and_the_escapes_do_not_reach_the_buffer() {
        let line = render("\x1b[1;31mred\x1b[0m plain");

        assert_eq!(text(&line), "red plain");
        assert_eq!(line.spans[0].style.fg, Some(Color::Red));
        assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(line.spans[1].style.fg, None);
    }

    #[test]
    fn extended_colours_are_read_and_their_parameters_consumed() {
        let line = render("\x1b[38;5;208m256\x1b[38;2;10;20;30mrgb");

        assert_eq!(text(&line), "256rgb");
        assert_eq!(line.spans[0].style.fg, Some(Color::Indexed(208)));
        assert_eq!(line.spans[1].style.fg, Some(Color::Rgb(10, 20, 30)));
    }

    #[test]
    fn every_escape_that_is_not_sgr_is_removed() {
        // A clear-screen, a cursor move, an OSC 8 hyperlink, and a bare bell: none of
        // them may reach a buffer this client owns.
        let line = render("\x1b[2Ja\x1b[10;10Hb\x1b]8;;https://example.test\x07c\x07d\x1bZe");

        assert_eq!(text(&line), "abcde");
    }

    #[test]
    fn only_the_first_line_and_only_the_first_four_kibibytes_are_kept() {
        assert_eq!(first_line(b"one\ntwo\nthree"), "one");
        assert_eq!(first_line(b"trailing  \r\nrest"), "trailing");
        assert_eq!(first_line(b""), "");
    }

    #[tokio::test]
    async fn a_command_is_fed_the_payload_and_answers_its_first_line() {
        let payload = serde_json::json!({"session": {"id": "abc"}});
        let line = run("cat", &payload).await.expect("the command runs");

        assert!(line.contains("\"abc\""), "{line}");
    }

    #[tokio::test]
    async fn a_command_that_hangs_is_abandoned_rather_than_awaited() {
        let started = std::time::Instant::now();
        let error = run("sleep 30", &Value::Null)
            .await
            .expect_err("a hang is a failure");

        assert!(error.contains("did not finish"), "{error}");
        assert!(started.elapsed() < TIMEOUT * 3, "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_failing_command_is_an_error_rather_than_an_empty_row() {
        let error = run("exit 3", &Value::Null)
            .await
            .expect_err("a non-zero exit with no output is a failure");

        assert!(error.contains("exited with"), "{error}");
    }

    #[tokio::test]
    async fn output_beyond_the_cap_is_not_buffered() {
        let line = run("yes abcdefgh | head -c 100000 | tr -d '\\n'", &Value::Null)
            .await
            .expect("the command runs");

        assert!(line.len() <= MAX_BYTES, "{}", line.len());
    }
}
