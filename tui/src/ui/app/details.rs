//! Keys and calls for the `/details` ledger (A9).
//!
//! The ledger shares the screen with the composer, which owns the keyboard while a session
//! is open. So navigation here follows the rule `?` and `,` already follow: it claims a key
//! only while the ledger is the pane being drawn **and** the draft is empty. A reader who
//! has started typing keeps every character they type.
//!
//! `ctrl+x d` (and the palette entry, and `/details` typed into an empty composer) is the
//! way back to the conversation, because inside the ledger `/` is the filter.

use super::*;

impl App {
    /// One key for the ledger, or `false` to let it fall through to the composer.
    pub(super) fn details_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};

        if self.tab != Tab::Sessions || !self.sessions.show_event_details {
            return false;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return false;
        };

        // Here as well as in the renderer: a key can arrive before the first frame of a
        // newly opened ledger, and focusing only at draw time would let that frame reset
        // the expansion the key had just produced.
        self.details.focus(plane, &id);

        // A modifier chord is never the ledger's: `ctrl+x`, `ctrl+o` and the scroll keys
        // are claimed before this, and anything else with a modifier belongs to whoever
        // claims it next.
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return false;
        }

        if self.details.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.details.filter.clear();
                    self.details.filtering = false;
                }
                KeyCode::Enter => self.details.filtering = false,
                KeyCode::Backspace => {
                    self.details.filter.pop();
                }
                KeyCode::Char(c) => self.details.filter.push(c),
                _other => return false,
            }

            return true;
        }

        if !self.focused_prompt_empty() {
            return false;
        }

        let rows = match self.sessions.watches.get(&(plane, id.clone())) {
            Some(watch) => self.details.rows(watch),
            None => Vec::new(),
        };

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.details.move_by(1, rows.len()),
            KeyCode::Char('k') | KeyCode::Up => self.details.move_by(-1, rows.len()),
            KeyCode::Char('g') => self.details.move_to(0, rows.len()),
            KeyCode::Char('G') => self
                .details
                .move_to(rows.len().saturating_sub(1), rows.len()),
            KeyCode::Char('/') => {
                self.details.filtering = true;
                self.details.filter.clear();
            }
            KeyCode::Esc if !self.details.filter.is_empty() => self.details.filter.clear(),
            KeyCode::Char('l') | KeyCode::Right => {
                if let Some(sequence) = self.details.expand(&rows) {
                    self.fetch_event_detail(plane, id, sequence);
                }
            }
            KeyCode::Char('h') | KeyCode::Left => self.details.collapse(&rows),
            KeyCode::Enter => {
                if let Some(sequence) = self.details.toggle(&rows) {
                    self.fetch_event_detail(plane, id, sequence);
                }
            }
            _other => return false,
        }

        true
    }

    /// X6's drill-in: one event, re-encoded under `detail_leaf_bytes` instead of
    /// `event_leaf_bytes`, so the leaf an `_excerpt` named arrives whole.
    ///
    /// The answer is bounded by this client's own inbound line ceiling
    /// ([`crate::transport::DEFAULT_MAX_LINE`], 8 MiB), not by the server's cap — a runtime
    /// whose `detail_leaf_bytes` was raised past about 7 MiB produces a frame this client
    /// truncates rather than decodes, and the transport reports that as a refusal instead
    /// of handing up a short value that looks whole.
    fn fetch_event_detail(&mut self, plane: Plane, id: String, sequence: u64) {
        if !self.hello.serves(&plane.method("event_detail")) {
            self.details.fetch_failed(sequence);
            self.inform(
                format!(
                    "this runtime does not serve {} — the excerpt is all there is here",
                    plane.method("event_detail")
                ),
                NoticeKind::Info,
            );
            return;
        }

        let params =
            self.routed_session_params(plane, &id, json!({ "id": id, "sequence": sequence }));

        self.issue(Call::new(
            Tag::EventDetail {
                plane,
                id: id.clone(),
                sequence,
            },
            plane.method("event_detail"),
            params,
        ));
    }

    /// The whole event, for this view only. The watch is deliberately not updated: the
    /// transcript's projection reads what the stream delivered, and a chat pane that
    /// silently re-rendered from a fetched copy would show one reader's drill-in as if the
    /// session had sent it that way.
    pub(super) fn event_detail_answered(
        &mut self,
        plane: Plane,
        id: &str,
        sequence: u64,
        result: Result<Value, ClientError>,
    ) {
        match result {
            Ok(value) => {
                if self.sessions.open.as_ref() != Some(&(plane, id.to_string())) {
                    self.details.fetch_failed(sequence);
                    return;
                }

                self.details.fetched(sequence, value);
            }
            Err(error) => {
                self.details.fetch_failed(sequence);
                self.inform(
                    format!("event {sequence} could not be fetched whole: {error}"),
                    NoticeKind::Error,
                );
            }
        }
    }
}
