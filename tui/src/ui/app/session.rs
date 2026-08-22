use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComposerVerb {
    Message,
    FollowUp,
    Steer,
}

impl ComposerVerb {
    pub fn title(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::FollowUp => "follow-up",
            Self::Steer => "steer",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Message => "send_message",
            Self::FollowUp => "follow_up",
            Self::Steer => "steer",
        }
    }
}

#[derive(Debug)]
pub struct Composer {
    pub verb: ComposerVerb,
    pub editor: Editor,
    draft_generation: u64,
    pub(super) reconciliation_owner: Option<ReconciliationDraftOwner>,
}

impl Composer {
    pub(super) fn user_changed_draft(&mut self) {
        self.draft_generation = self.draft_generation.saturating_add(1);
        self.reconciliation_owner = None;
    }

    pub(super) fn restore_reconciliation(
        &mut self,
        input: &str,
        turn_id: &str,
        catalog: &CompletionCatalog,
    ) {
        self.editor.clear_text();
        self.editor.paste(input, catalog);
        self.draft_generation = self.draft_generation.saturating_add(1);
        self.reconciliation_owner = Some(ReconciliationDraftOwner {
            turn_id: turn_id.to_string(),
            generation: self.draft_generation,
        });
    }

    pub(super) fn owns_reconciliation(&self, turn_id: &str) -> bool {
        self.reconciliation_owner.as_ref().is_some_and(|owner| {
            owner.turn_id == turn_id && owner.generation == self.draft_generation
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReconciliationDraftOwner {
    pub(super) turn_id: String,
    pub(super) generation: u64,
}

#[derive(Debug, Clone)]
pub(super) struct SavedComposerDraft {
    pub(super) input: String,
    pub(super) generation: u64,
    pub(super) reconciliation_owner: Option<ReconciliationDraftOwner>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingComposerReconciliation {
    pub(super) kind: PendingReconciliationKind,
    pub(super) input: String,
    pub(super) turn_id: String,
    pub(super) submission_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComposerRestoreDisposition {
    Restored,
    SavedForReopen,
    ReconciliationQueued,
    NewerDraftPreserved,
}

impl ComposerRestoreDisposition {
    pub(super) fn reconciliation_deferred(self) -> bool {
        self == Self::ReconciliationQueued
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingReconciliationKind {
    FirstMessage,
    Composer(ComposerVerb),
}

#[derive(Debug)]
pub(super) struct PendingFirstMessage {
    pub(super) input: String,
    pub(super) turn_id: String,
    pub(super) start: StartRequest,
    pub(super) start_outcome_unknown: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SessionRecovery {
    pub(super) attempts: u32,
    pub(super) next_tick: u64,
}

#[derive(Debug, Default)]
pub struct SessionsTab {
    pub interactive: Loadable<Vec<SessionInfo>>,
    pub coding: Loadable<Vec<SessionInfo>>,
    pub open: Option<(Plane, String)>,
    pub watches: HashMap<(Plane, String), Watch>,
    pub composer: Option<Composer>,
    /// Owning node for remote references. First-party session ids carry 128 bits of
    /// client/runtime entropy and are therefore fleet-unique; the node is routing data,
    /// not folded into the user-facing id or map key.
    owner_nodes: HashMap<(Plane, String), String>,
    /// Explicit IDs can be supplied by API clients. The v1 stream envelope carries only
    /// plane + id, so the same value on two owners is deliberately unrouteable instead of
    /// silently choosing whichever fleet-list row happened to arrive last.
    owner_conflicts: HashMap<(Plane, String), Vec<String>>,
    /// Remote streams whose owner disappeared without a terminal session status. Their
    /// cursors stay registered while fleet status watches for the owner to return.
    pub(super) recovering: HashMap<(Plane, String), SessionRecovery>,
    /// The complete normalized event ledger is an operator detail, not the default chat.
    /// It remains one command away (`/details`, `ctrl+x d`) and is never discarded.
    pub show_event_details: bool,
    /// Whether every collapsible chat cell draws expanded in place. `Ctrl+O` — the key the
    /// field settled on for "show more" — toggles this, not the raw ledger.
    pub verbose_transcript: bool,
    /// Whether the plan/tasks panel is drawn above the composer.
    pub show_plan: bool,
    /// Per-session resync rounds since the last interruption, bounded.
    pub(super) rounds: HashMap<(Plane, String), u32>,
    /// Requests accepted by this client that have not produced their first lifecycle
    /// event yet. The Watch takes over as soon as input/turn/run state reaches the stream.
    pub(super) pending_replies: HashSet<(Plane, String)>,
    /// What has been submitted to each session, so the Up arrow recalls it after the
    /// composer has been closed and reopened. The composer itself is rebuilt on every `i`,
    /// and a recall that forgot everything typed before the last Esc is one nobody relies
    /// on twice.
    composer_history: HashMap<(Plane, String), Vec<String>>,
    /// The unsent text in each composer. Unlike submission history this must survive a
    /// session switch verbatim, especially while an older turn awaits reconciliation.
    pub(super) composer_drafts: HashMap<(Plane, String), SavedComposerDraft>,
    /// Stable-id mutations that remain outcome-unknown, keyed by their session rather than
    /// the ephemeral open composer. This survives Esc and session switching; Enter always
    /// reconciles the oldest before it can submit a newer draft.
    pub(super) pending_reconciliations:
        HashMap<(Plane, String), VecDeque<PendingComposerReconciliation>>,
    /// Rows the operator hid or deleted in this client. Last-known reconstruction must
    /// not bring them back; a later list that actually observes the id clears the hide.
    pub(super) hidden: HashSet<(Plane, String)>,
}

impl SessionsTab {
    pub(super) fn remember_owner(&mut self, plane: Plane, id: &str, node: Option<&str>) {
        if self.owner_conflicts.contains_key(&(plane, id.to_string())) {
            return;
        }

        if let Some(node) = node.map(str::trim).filter(|node| !node.is_empty()) {
            self.owner_nodes
                .insert((plane, id.to_string()), node.to_string());
        }
    }

    pub fn owner_node(&self, plane: Plane, id: &str) -> Option<&str> {
        if self.owner_conflicts.contains_key(&(plane, id.to_string())) {
            return None;
        }

        self.owner_nodes
            .get(&(plane, id.to_string()))
            .map(String::as_str)
            .or_else(|| {
                let sessions = match plane {
                    Plane::Interactive => self.interactive.value.as_ref()?,
                    Plane::Coding => self.coding.value.as_ref()?,
                };
                sessions
                    .iter()
                    .find(|session| session.id == id)
                    .and_then(|session| session.node.as_deref())
            })
    }

    /// Reconciles one fleet-wide list without ever choosing between duplicate explicit
    /// IDs. Conflicts are sticky for this client lifetime because a later fleet list may
    /// be partial while one owner is offline; absence is not proof that its id vanished.
    /// Returns newly observed/expanded conflicts for one visible notice.
    pub(super) fn remember_list_owners(
        &mut self,
        plane: Plane,
        sessions: &[SessionInfo],
    ) -> Vec<(String, Vec<String>)> {
        let mut owners = BTreeMap::<String, BTreeSet<String>>::new();
        for session in sessions {
            owners.entry(session.id.clone()).or_default().insert(
                session
                    .node
                    .as_deref()
                    .map(str::trim)
                    .filter(|node| !node.is_empty())
                    .unwrap_or("owner not reported")
                    .to_string(),
            );
        }

        let mut newly_conflicted = Vec::new();
        for (id, owners) in owners {
            let key = (plane, id.clone());
            let mut owners = owners;
            if let Some(previous) = self.owner_conflicts.get(&key) {
                owners.extend(previous.iter().cloned());
            }
            let nodes = owners.into_iter().collect::<Vec<_>>();
            if nodes.len() > 1 {
                self.owner_nodes.remove(&key);
                let changed = self.owner_conflicts.get(&key) != Some(&nodes);
                self.owner_conflicts.insert(key.clone(), nodes.clone());
                if changed {
                    newly_conflicted.push((id, nodes));
                }
            } else if !self.owner_conflicts.contains_key(&key) && !self.watches.contains_key(&key) {
                if let Some(node) = nodes
                    .first()
                    .filter(|node| node.as_str() != "owner not reported")
                {
                    self.owner_nodes.insert(key, node.clone());
                }
            }
        }

        newly_conflicted
    }

    pub fn owner_conflict(&self, plane: Plane, id: &str) -> Option<&[String]> {
        self.owner_conflicts
            .get(&(plane, id.to_string()))
            .map(Vec::as_slice)
    }

    /// Both planes' sessions in one list, ordered so the list does not reshuffle under the
    /// cursor between polls: newest activity first, ties broken by plane then id.
    pub fn merged(&self) -> Vec<&SessionInfo> {
        let mut rows: Vec<&SessionInfo> = self
            .interactive
            .value
            .iter()
            .flatten()
            .chain(self.coding.value.iter().flatten())
            .collect();

        rows.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.plane.cmp(&right.plane))
                .then_with(|| left.id.cmp(&right.id))
        });

        // One row represents one addressable v1 stream. A duplicate explicit ID is still
        // visible, but as a single conflict row whose owners are named by the renderer.
        let mut seen = HashSet::new();
        rows.retain(|session| seen.insert((session.plane, session.id.clone())));

        rows
    }

    pub fn picker_index(&self, selected: Option<&(Plane, String)>) -> usize {
        selected
            .and_then(|(plane, id)| {
                self.merged()
                    .iter()
                    .position(|session| session.plane == *plane && session.id == *id)
            })
            .unwrap_or(0)
    }

    pub fn picker_key(&self, index: usize) -> Option<(Plane, String)> {
        self.merged()
            .get(index)
            .map(|session| (session.plane, session.id.clone()))
    }

    pub fn get(&self, plane: Plane, id: &str) -> Option<&SessionInfo> {
        let sessions = match plane {
            Plane::Interactive => self.interactive.value.as_ref()?,
            Plane::Coding => self.coding.value.as_ref()?,
        };

        sessions
            .iter()
            .find(|session| session.plane == plane && session.id == id)
    }

    fn drop_row(&mut self, plane: Plane, id: &str) {
        self.hidden.insert((plane, id.to_string()));
        let sessions = match plane {
            Plane::Interactive => &mut self.interactive.value,
            Plane::Coding => &mut self.coding.value,
        };

        if let Some(sessions) = sessions {
            sessions.retain(|session| session.id != id);
        }
    }

    pub fn open_watch(&self) -> Option<&Watch> {
        self.watches.get(self.open.as_ref()?)
    }

    /// The list snapshot for the session whose transcript is open, when the latest poll
    /// has observed it. The watch stays authoritative for events; this is presentation and
    /// interaction context such as provider and whether a new turn must be queued.
    pub fn open_info(&self) -> Option<&SessionInfo> {
        let (plane, id) = self.open.as_ref()?;
        self.session(*plane, id)
    }

    /// One listed session by identity, whether or not it is the open one.
    pub fn session(&self, plane: Plane, id: &str) -> Option<&SessionInfo> {
        let sessions = match plane {
            Plane::Interactive => self.interactive.value.as_ref()?,
            Plane::Coding => self.coding.value.as_ref()?,
        };

        sessions
            .iter()
            .find(|session| session.plane == plane && session.id == id)
    }

    pub(super) fn open_watch_mut(&mut self) -> Option<&mut Watch> {
        let key = self.open.clone()?;
        self.watches.get_mut(&key)
    }

    pub(super) fn mark_reply_pending(&mut self, plane: Plane, id: &str) {
        self.pending_replies.insert((plane, id.to_string()));
    }

    pub(super) fn clear_reply_pending(&mut self, plane: Plane, id: &str) {
        self.pending_replies.remove(&(plane, id.to_string()));
    }
}

impl App {
    // ----- what the open session can actually do (B0/D14) ----------------------------

    /// The transport capabilities the runtime declared for the open session.
    ///
    /// Default — every capability [`Capability::Unknown`] — where there is no open
    /// session or the gateway predates the declaration. Unknown is never "no": the
    /// predicates below hide a control only where the runtime said `false`, because a
    /// client that hid keys on a gateway's silence would be inventing a ceiling.
    pub fn open_capabilities(&self) -> Capabilities {
        self.sessions
            .open_info()
            .map(|session| session.capabilities.clone())
            .unwrap_or_default()
    }

    /// Whether the Steer verb, `s`, `ctrl+x s`, `/steer` and the palette entry exist.
    ///
    /// X2: `steer/3` answers `{:error, :unsupported}` on every provider but `pi`, and the
    /// client offered it on all of them. Now it is offered where the transport says so.
    pub fn steer_offered(&self) -> bool {
        self.open_capabilities().steer.offered()
    }

    /// Whether the approval key and its palette entry exist. A managed transport has no
    /// approvals channel at all, so nothing will ever open that modal there.
    pub fn approvals_offered(&self) -> bool {
        self.open_capabilities().approvals.offered()
    }

    /// Whether attachment affordances may be offered. Nothing uses it yet — B4 is the
    /// slice that builds them — and it is here so that the predicate and the capability
    /// arrive together rather than the affordance arriving first.
    pub fn multimodal_offered(&self) -> bool {
        self.open_capabilities().multimodal.offered()
    }

    // ----- session verbs -------------------------------------------------------------

    /// Opens the composer, refusing where the plane has no such verb rather than sending
    /// a call that would come back `-32601`.
    pub(super) fn compose(&mut self, requested_verb: ComposerVerb) {
        if self.tab != Tab::Sessions {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "open a session with Enter before writing to it",
                NoticeKind::Info,
            );
            return;
        };

        if plane == Plane::Coding {
            self.inform(
                format!(
                    "{id} is a coding task: it runs one objective to completion and takes no \
                     input. `x` cancels it"
                ),
                NoticeKind::Info,
            );
            return;
        }

        // X2. Steer is unsupported on every transport but `pi`'s, and the runtime says so
        // per session. Refused here with the reason rather than sent and answered
        // `{:error, :unsupported}` — the refusal names the transport that cannot take it,
        // which is the fact an operator needs, and the key is not advertised anywhere
        // else on a session that would refuse it.
        if requested_verb == ComposerVerb::Steer && !self.steer_offered() {
            let capabilities = self.open_capabilities();
            let transport = capabilities
                .transport
                .as_deref()
                .map(|transport| format!(" over {transport}"))
                .unwrap_or_default();

            self.inform(
                format!(
                    "{id} cannot be steered mid-turn{transport}; press Enter to queue a \
                     follow-up instead"
                ),
                NoticeKind::Info,
            );
            return;
        }

        // Harness deliberately separates an immediate message from the durable follow-up
        // queue. Sending another immediate message to a running session is `:busy`, so `i`
        // means "queue the next request" unless the latest session snapshot is idle.
        let verb = if requested_verb == ComposerVerb::Message
            && self
                .sessions
                .open_info()
                .is_some_and(|session| session.status.as_str() != "idle")
        {
            ComposerVerb::FollowUp
        } else {
            requested_verb
        };

        let method = plane.method(verb.method());

        if !self.hello.serves(&method) {
            self.inform(
                format!("this gateway does not serve {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.verb = verb;
            return;
        }

        let key = (plane, id);
        let mut editor = Editor::default();
        editor.restore_history(
            self.sessions
                .composer_history
                .get(&key)
                .cloned()
                .unwrap_or_default(),
        );
        let saved = self.sessions.composer_drafts.get(&key).cloned();
        let (draft_generation, reconciliation_owner) = if let Some(saved) = saved {
            editor.paste(&saved.input, &self.completion_catalog);
            (saved.generation, saved.reconciliation_owner)
        } else if let Some(pending) = self
            .sessions
            .pending_reconciliations
            .get(&key)
            .and_then(|pending| pending.front())
        {
            editor.paste(&pending.input, &self.completion_catalog);
            (
                1,
                Some(ReconciliationDraftOwner {
                    turn_id: pending.turn_id.clone(),
                    generation: 1,
                }),
            )
        } else {
            (0, None)
        };

        self.sessions.composer = Some(Composer {
            verb,
            editor,
            draft_generation,
            reconciliation_owner,
        });
    }

    /// Copies the open composer's history and exact unsent draft where the next composer
    /// over the same session will find them.
    pub(super) fn remember_composer_history(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };
        let Some(composer) = self.sessions.composer.as_ref() else {
            return;
        };

        let key = (plane, id);
        let history = composer.editor.history().to_vec();
        let draft = composer.editor.text().to_string();
        let generation = composer.draft_generation;
        let reconciliation_owner = composer.reconciliation_owner.clone();

        self.sessions.composer_history.insert(key.clone(), history);
        if draft.is_empty() {
            self.sessions.composer_drafts.remove(&key);
        } else {
            self.sessions.composer_drafts.insert(
                key,
                SavedComposerDraft {
                    input: draft,
                    generation,
                    reconciliation_owner,
                },
            );
        }
    }

    /// `Ctrl+O`: the same conversation, with every collapsible cell expanded.
    ///
    /// This is what the key means everywhere else in the field (Claude Code, Gemini, Kiro,
    /// Pi, Droid all bind `Ctrl+O` to "show more"), and it is a different question from
    /// "show me the normalized ledger", which keeps its own verb.
    pub(super) fn toggle_verbose_transcript(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform(
                "open a session before expanding its transcript",
                NoticeKind::Info,
            );
            return;
        }

        self.sessions.verbose_transcript = !self.sessions.verbose_transcript;

        if let Some(watch) = self.sessions.open_watch_mut() {
            // Expanding rewrites every cell's height, so a line-based offset taken against
            // the compact layout no longer points at the rows it was taken from.
            watch.follow = true;
            watch.scroll = 0;
        }
    }

    /// `Ctrl+T`: the plan panel. It stays open while the session is idle on purpose —
    /// a task list that vanishes the moment the agent stops is Codex #18920.
    pub(super) fn toggle_plan_panel(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform("open a session before showing its plan", NoticeKind::Info);
            return;
        }

        self.sessions.show_plan = !self.sessions.show_plan;
    }

    pub(super) fn toggle_session_details(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform(
                "open a session before viewing its event details",
                NoticeKind::Info,
            );
            return;
        }

        self.sessions.show_event_details = !self.sessions.show_event_details;

        if let Some(watch) = self.sessions.open_watch_mut() {
            // Chat and event rows wrap differently. Returning to the newest content avoids
            // carrying a line-based scroll offset into a view where it means something else.
            watch.follow = true;
            watch.scroll = 0;
        }
    }

    pub(super) fn composer_key(&mut self, key: crossterm::event::KeyEvent) {
        if self.first_message_in_flight() {
            return;
        }

        let action = self
            .sessions
            .composer
            .as_mut()
            .map(|composer| {
                let before = composer.editor.text().to_string();
                let action = composer.editor.handle_key(key, &self.completion_catalog);
                if composer.editor.text() != before {
                    composer.user_changed_draft();
                }
                action
            })
            .unwrap_or(EditorAction::None);

        match action {
            EditorAction::Submit => self.submit_composer(),
            EditorAction::Cancel => self.escape_from_prompt(),
            EditorAction::Scroll(delta) => self.move_by(delta * 10),
            EditorAction::None => {}
        }
    }

    fn first_message_in_flight(&self) -> bool {
        let Some((plane, id)) = self.sessions.open.as_ref() else {
            return false;
        };

        self.in_flight.iter().any(|tag| {
            matches!(
                tag,
                Tag::FirstMessage {
                    plane: pending_plane,
                    id: pending_id,
                    ..
                } if pending_plane == plane && pending_id == id
            )
        })
    }

    pub(super) fn next_composer_submission_sequence(&mut self) -> u64 {
        self.next_composer_submission_sequence =
            self.next_composer_submission_sequence.saturating_add(1);
        self.next_composer_submission_sequence
    }

    fn same_session_mutation_in_flight(&self, plane: Plane, id: &str) -> bool {
        self.in_flight.iter().any(|tag| match tag {
            Tag::FirstMessage {
                plane: pending_plane,
                id: pending_id,
                ..
            }
            | Tag::ComposerAction {
                plane: pending_plane,
                id: pending_id,
                ..
            } => *pending_plane == plane && pending_id == id,
            _ => false,
        })
    }

    fn earlier_session_mutation_in_flight(
        &self,
        plane: Plane,
        id: &str,
        submission_sequence: u64,
    ) -> bool {
        self.in_flight.iter().any(|tag| match tag {
            Tag::FirstMessage {
                plane: pending_plane,
                id: pending_id,
                submission_sequence: pending_sequence,
                ..
            }
            | Tag::ComposerAction {
                plane: pending_plane,
                id: pending_id,
                submission_sequence: pending_sequence,
                ..
            } => {
                *pending_plane == plane
                    && pending_id == id
                    && *pending_sequence <= submission_sequence
            }
            _ => false,
        })
    }

    fn submit_composer(&mut self) {
        let open_key = self.sessions.open.clone();
        if open_key
            .as_ref()
            .is_some_and(|(plane, id)| self.refuse_owner_conflict(*plane, id))
        {
            return;
        }

        let pending = open_key.as_ref().and_then(|key| {
            self.sessions
                .pending_reconciliations
                .get(key)
                .and_then(|pending| pending.front())
                .cloned()
        });

        if let Some(pending) = pending {
            let Some((plane, id)) = self.sessions.open.clone() else {
                return;
            };

            if self.earlier_session_mutation_in_flight(plane, &id, pending.submission_sequence) {
                self.inform(
                    format!(
                        "still reconciling outcome-unknown turn {}; the draft remains unsent",
                        pending.turn_id
                    ),
                    NoticeKind::Info,
                );
                return;
            }

            self.sessions.mark_reply_pending(plane, &id);
            self.inform(
                format!(
                    "reconciling outcome-unknown turn {}; the newer draft remains in the editor",
                    pending.turn_id
                ),
                NoticeKind::Info,
            );

            let params = json!({
                "id": id,
                "input": pending.input,
                "turn_id": pending.turn_id
            });
            let params = self.routed_session_params(plane, &id, params);
            let call = match pending.kind {
                PendingReconciliationKind::FirstMessage => Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: id.clone(),
                        turn_id: pending.turn_id,
                        input: pending.input,
                        submission_sequence: pending.submission_sequence,
                    },
                    plane.method("send_message"),
                    params,
                ),
                PendingReconciliationKind::Composer(verb) => {
                    let (label, method) = match verb {
                        ComposerVerb::Message => ("send_message", plane.method("send_message")),
                        ComposerVerb::FollowUp => ("follow_up", plane.method("follow_up")),
                        ComposerVerb::Steer => {
                            unreachable!("steer has no same-id reconciliation")
                        }
                    };
                    Call::new(
                        Tag::ComposerAction {
                            label,
                            verb,
                            plane,
                            id: id.clone(),
                            turn_id: Some(pending.turn_id),
                            input: pending.input,
                            reconciling: true,
                            submission_sequence: pending.submission_sequence,
                        },
                        method,
                        params,
                    )
                }
            };
            self.issue(call);
            return;
        }

        let Some(composer) = self.sessions.composer.as_mut() else {
            return;
        };

        let Some(input) = composer.editor.submission() else {
            return;
        };
        let verb = composer.verb;

        if self.activate_slash_command(&input) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.accept_submission();
                composer.user_changed_draft();
            }
            self.remember_composer_history();
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        // JSON-RPC requests are handled by independent gateway tasks. Keep the next input
        // visible and untouched until the prior same-session mutation is classified, so
        // scheduler order can never replace the order in which the operator pressed Enter.
        if self.same_session_mutation_in_flight(plane, &id) {
            self.inform(
                format!(
                    "the earlier request for {id} is still awaiting acknowledgement; this draft remains unsent"
                ),
                NoticeKind::Info,
            );
            return;
        }

        let Some(composer) = self.sessions.composer.as_mut() else {
            return;
        };
        let turn_id = if verb == ComposerVerb::Steer {
            // A steer is an injection into an already-running provider call. There is no
            // durable request ledger behind it, so do not manufacture an idempotency key.
            None
        } else {
            Some(new_turn_id())
        };
        composer.editor.accept_submission();
        composer.user_changed_draft();

        // After the first immediate message, every later acknowledged submission uses
        // Harness's durable queueing verb. An Enter while this acknowledgement is still
        // outstanding was returned above with the next draft visibly untouched.
        if composer.verb == ComposerVerb::Message {
            composer.verb = ComposerVerb::FollowUp;
        }

        self.remember_composer_history();
        let submission_sequence = self.next_composer_submission_sequence();
        let (label, method) = match verb {
            ComposerVerb::Message => ("send_message", plane.method("send_message")),
            ComposerVerb::FollowUp => ("follow_up", plane.method("follow_up")),
            ComposerVerb::Steer => ("steer", plane.method("steer")),
        };

        if matches!(verb, ComposerVerb::Message | ComposerVerb::FollowUp) {
            self.sessions.mark_reply_pending(plane, &id);
        }

        let tag = Tag::ComposerAction {
            label,
            verb,
            plane,
            id: id.clone(),
            turn_id: turn_id.clone(),
            input: input.clone(),
            reconciling: false,
            submission_sequence,
        };

        let params = match turn_id {
            Some(turn_id) => json!({ "id": id, "input": input, "turn_id": turn_id }),
            None => json!({ "id": id, "input": input }),
        };
        let params = self.routed_session_params(plane, &id, params);

        self.issue(Call::new(tag, method, params));
    }

    pub(super) fn activate_slash_command(&mut self, input: &str) -> bool {
        let trimmed = input.trim();

        if let Some(name) = slash_arg(trimmed, "/preview") {
            self.preview_capability(name);
            return true;
        }

        if let Some(name) = slash_arg(trimmed, "/admit") {
            self.confirm_admit_capability(name);
            return true;
        }

        let command = match trimmed {
            "/new" => Some(Command::NewSession),
            "/switch" | "/sessions" => Some(Command::SwitchSession),
            "/details" => Some(Command::SessionDetails),
            "/copy" => Some(Command::CopyLast),
            "/interrupt" => Some(Command::Interrupt),
            "/steer" => Some(Command::Steer),
            "/editor" => Some(Command::ExternalEditor),
            "/close" => Some(Command::CloseSession),
            "/options" => Some(Command::NewSessionOptions),
            "/write" => Some(Command::WriteAccess),
            "/connect" => Some(Command::ConnectChatGpt),
            "/runtime" => Some(Command::Runtime),
            "/agents" => Some(Command::Agents),
            "/teams" => Some(Command::Teams),
            "/plans" => Some(Command::Plans),
            "/upgrades" => Some(Command::Upgrades),
            "/capabilities" => Some(Command::ListCapabilities),
            "/logs" => Some(Command::Logs),
            "/machines" | "/fleet" => Some(Command::Machines),
            "/settings" => Some(Command::Settings),
            "/help" | "/hotkeys" => Some(Command::Help),
            "/quit" => {
                self.open_quit();
                return true;
            }
            "/clear" => return true,
            _ => return false,
        };

        self.activate_command(command.expect("matched slash command"));
        true
    }

    /// Ctrl-C: clear the prompt if it has text; otherwise interrupt a running turn;
    /// a second press on an idle surface opens the quit dialog. Never a single-press quit.
    pub(super) fn ctrl_c(&mut self) {
        if self.overlay.is_some() {
            self.interrupt();
            return;
        }

        if !self.focused_prompt_empty() {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.clear_text();
                composer.user_changed_draft();
                self.remember_composer_history();
            } else if let Some(editor) = self.focused_editor_mut() {
                editor.clear_text();
            }
            self.ctrl_c_until = None;
            return;
        }

        if self.sessions.open.is_some() {
            self.interrupt_turn();
            self.ctrl_c_until = None;
            return;
        }

        if self.ctrl_c_until.is_some_and(|until| self.ticks < until) {
            self.ctrl_c_until = None;
            self.open_quit();
            return;
        }

        self.ctrl_c_until = Some(self.ticks + CTRL_C_QUIT_TICKS);
        self.inform(
            "press ctrl+c again to quit · esc aborts a running turn · ctrl+q opens the quit dialog",
            NoticeKind::Info,
        );
    }

    /// Ctrl-C / Esc: the active turn, never this process.
    fn interrupt(&mut self) {
        if self.overlay.is_some() {
            let login_id = match self.overlay.as_ref() {
                Some(Overlay::Account(dialog)) if dialog.pending => dialog.login_id.clone(),
                _ => None,
            };
            self.overlay = None;

            if let Some(login_id) = login_id {
                self.issue(Call::new(
                    Tag::AccountCancel,
                    "account.login.cancel",
                    json!({ "login_id": login_id }),
                ));
            }

            return;
        }

        self.interrupt_turn();
    }

    pub(super) fn interrupt_turn(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "esc or ctrl+c interrupts a running turn; ctrl+q opens the quit dialog",
                NoticeKind::Info,
            );
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let (label, method) = match plane {
            Plane::Interactive => ("interrupt", "interactive.interrupt".to_string()),
            // The coding plane has no interrupt; cancelling is what it offers, and it is
            // destructive enough to go through the confirmation instead.
            Plane::Coding => {
                self.inform(
                    format!("{id} is a coding task; ctrl+x x cancels it"),
                    NoticeKind::Info,
                );
                return;
            }
        };

        // `interactive.interrupt` defaults to the active turn, which is the only thing a
        // terminal's ctrl-c can mean.
        let params = self.routed_session_params(plane, &id, json!({ "id": id }));
        self.issue(Call::new(
            Tag::Action {
                label,
                plane,
                id: id.clone(),
            },
            method,
            params,
        ));

        self.inform(
            format!("interrupting the active turn of {id}"),
            NoticeKind::Info,
        );
    }

    pub(super) fn reopen_approval(&mut self) {
        if self.tab != Tab::Sessions {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        let has_pending = self
            .sessions
            .watches
            .get(&(plane, id.clone()))
            .and_then(Watch::next_approval)
            .is_some();

        if has_pending {
            self.open_approval(plane, id);
        } else if self.approvals_offered() {
            self.inform(
                format!("{id} is not waiting on an approval"),
                NoticeKind::Info,
            );
        } else {
            // X1's client half. A managed transport runs one process per turn with no
            // channel to ask through, so this session will never raise an approval and
            // the key is not advertised for it. Saying why beats "not waiting on one",
            // which reads as "not yet".
            let capabilities = self.open_capabilities();
            let transport = capabilities
                .transport
                .as_deref()
                .map(|transport| format!("{transport} "))
                .unwrap_or_default();

            self.inform(
                format!(
                    "{id} has no approvals channel: {transport}sessions cannot ask before \
                     acting, so nothing will open this modal"
                ),
                NoticeKind::Info,
            );
        }
    }

    fn capability_workspace(&self) -> Option<String> {
        self.sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .filter(|workspace| !workspace.is_empty())
            .or_else(|| {
                let workspace = self.default_workspace();
                (!workspace.is_empty()).then_some(workspace)
            })
    }

    fn capability_target(&self) -> (Plane, String) {
        self.sessions
            .open
            .clone()
            .unwrap_or((Plane::Interactive, "capabilities".into()))
    }

    pub(super) fn list_capabilities(&mut self) {
        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before listing capabilities",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, id) = self.capability_target();
        self.issue(Call::new(
            Tag::Action {
                label: "list capabilities",
                plane,
                id,
            },
            "capabilities.list",
            json!({ "workspace": workspace }),
        ));
    }

    pub(super) fn preview_capability(&mut self, name: &str) {
        if name.trim().is_empty() {
            self.list_capabilities();
            return;
        }

        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before previewing a capability",
                NoticeKind::Warn,
            );
            return;
        };

        let Some(path) = capability_proposal_path(name) else {
            self.inform(
                "a capability path must stay inside the workspace",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, _) = self.capability_target();
        self.issue(
            Call::new(
                Tag::Action {
                    label: "preview",
                    plane,
                    id: path.clone(),
                },
                "capabilities.preview",
                json!({ "workspace": workspace, "path": path }),
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    pub(super) fn confirm_admit_capability(&mut self, name: &str) {
        if name.trim().is_empty() {
            self.inform("name a proposal: /admit Echo", NoticeKind::Warn);
            return;
        }

        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before admitting a capability",
                NoticeKind::Warn,
            );
            return;
        };

        let Some(path) = capability_proposal_path(name) else {
            self.inform(
                "a capability path must stay inside the workspace",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, session_id) = self.capability_target();
        let mut params = json!({ "workspace": workspace, "path": path });
        if session_id != "capabilities" {
            params["session_id"] = json!(session_id);
        }

        self.overlay = Some(Overlay::Confirm {
            title: format!("admit {path}?"),
            detail: "this forges, signs, and rolls out the proposal; the selected model cannot \
                     undo it"
                .to_string(),
            options: vec![
                (
                    "admit (forge, sign, roll out)".to_string(),
                    Some(
                        Call::new(
                            Tag::Action {
                                label: "admit",
                                plane,
                                id: path,
                            },
                            "capabilities.admit",
                            params,
                        )
                        .with_timeout(START_TIMEOUT),
                    ),
                ),
                ("cancel".to_string(), None),
            ],
            choice: 1,
        });
    }

    pub(super) fn capability_answered(&mut self, label: &str, id: &str, value: Value) {
        let text = match label {
            "list capabilities" => format_capability_list(&value),
            "preview" => format_capability_preview(id, &value),
            "admit" => format_capability_admit(id, &value),
            _ => format!("{label} accepted for {id}"),
        };

        self.inform(text, NoticeKind::Info);
    }

    pub(super) fn open_close_confirm(&mut self) {
        let from_picker = matches!(self.overlay, Some(Overlay::SessionPicker { .. }));
        let Some((plane, id)) = self.session_action_target() else {
            if !self.sessions.merged().is_empty() {
                self.activate_command(Command::SwitchSession);
                self.inform(
                    "choose a session, then press x to end or remove it",
                    NoticeKind::Info,
                );
            }
            return;
        };
        self.open_close_confirm_for(plane, id, from_picker);
    }

    fn session_action_target(&self) -> Option<(Plane, String)> {
        match &self.overlay {
            Some(Overlay::SessionPicker { selected }) => selected
                .clone()
                .or_else(|| self.sessions.picker_key(self.sessions.picker_index(None))),
            _ => self.sessions.open.clone(),
        }
    }

    pub(super) fn open_close_confirm_for(&mut self, plane: Plane, id: String, from_picker: bool) {
        if self.tab != Tab::Sessions && !from_picker {
            return;
        }

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        self.resume_session_picker = from_picker;
        let session = self.sessions.get(plane, &id);

        if session.is_some_and(|session| session.last_known) {
            self.overlay = Some(Overlay::Confirm {
                title: format!("hide {id}?"),
                detail: "its owner is offline, so this only hides the last-known row in this client; the durable record stays on that machine"
                    .to_string(),
                options: vec![
                    (
                        "hide here".to_string(),
                        Some(Call::new(
                            Tag::Action {
                                label: "hide",
                                plane,
                                id: id.clone(),
                            },
                            "interactive.delete",
                            json!({ "id": id }),
                        )),
                    ),
                    ("keep it".to_string(), None),
                ],
                choice: 0,
            });
            return;
        }

        if session.is_some_and(|session| session.status.terminal()) {
            let routed = self.routed_session_params(plane, &id, json!({ "id": id }));
            let method = plane.method("delete");
            self.overlay = Some(Overlay::Confirm {
                title: format!("remove {id}?"),
                detail:
                    "this deletes the durable record on its owner; it is not undone by reattaching"
                        .to_string(),
                options: vec![
                    (
                        "remove from this machine".to_string(),
                        Some(Call::new(
                            Tag::Action {
                                label: "remove",
                                plane,
                                id: id.clone(),
                            },
                            method,
                            routed,
                        )),
                    ),
                    ("keep it".to_string(), None),
                ],
                choice: 0,
            });
            return;
        }

        let routed = self.routed_session_params(plane, &id, json!({ "id": id }));

        let options = match plane {
            Plane::Interactive => vec![
                (
                    "close (let the provider finish and shut down)".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "close",
                            plane,
                            id: id.clone(),
                        },
                        "interactive.close",
                        routed.clone(),
                    )),
                ),
                (
                    "kill (stop it now)".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "kill",
                            plane,
                            id: id.clone(),
                        },
                        "interactive.kill",
                        routed.clone(),
                    )),
                ),
                ("cancel".to_string(), None),
            ],
            Plane::Coding => vec![
                (
                    "cancel the task".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "cancel",
                            plane,
                            id: id.clone(),
                        },
                        "coding.cancel",
                        routed,
                    )),
                ),
                ("leave it running".to_string(), None),
            ],
        };

        self.overlay = Some(Overlay::Confirm {
            title: format!("end {id}?"),
            detail: "this ends work the runtime is doing; it is not undone by reattaching"
                .to_string(),
            options,
            // The least destructive answer is under the cursor: an operator who reflexively
            // presses Enter on a dialog they did not expect must not kill a session.
            choice: 0,
        });
    }

    pub(super) fn submit_confirm(&mut self, call: Call) {
        if let Tag::Action {
            label: "hide",
            plane,
            id,
        } = &call.tag
        {
            let plane = *plane;
            let id = id.clone();
            self.session_removed(plane, &id);
            return;
        }

        self.issue(call);
    }

    pub(super) fn session_removed(&mut self, plane: Plane, id: &str) {
        self.drop_local_session(plane, id);
        self.inform(format!("{id} removed from this client"), NoticeKind::Info);
        self.resume_picker_if_requested();
    }

    fn drop_local_session(&mut self, plane: Plane, id: &str) {
        let key = (plane, id.to_string());
        self.cursors.forget(plane, id);
        self.sessions.watches.remove(&key);
        self.sessions.rounds.remove(&key);
        self.sessions.clear_reply_pending(plane, id);
        self.sessions.composer_history.remove(&key);
        self.sessions.composer_drafts.remove(&key);
        self.sessions.pending_reconciliations.remove(&key);
        self.sessions.recovering.remove(&key);
        self.sessions.drop_row(plane, id);

        if self.sessions.open.as_ref() == Some(&key) {
            self.sessions.open = None;
            self.sessions.composer = None;
        }
    }

    pub(super) fn refresh_session_lists(&mut self) {
        self.sessions.interactive.invalidate();
        self.sessions.coding.invalidate();
        self.poll();
    }

    pub(super) fn resume_picker_if_requested(&mut self) {
        if !self.resume_session_picker {
            return;
        }

        self.resume_session_picker = false;
        if self.sessions.merged().is_empty() {
            return;
        }

        let selected = self
            .sessions
            .open
            .clone()
            .or_else(|| self.sessions.picker_key(0));
        self.overlay = Some(Overlay::SessionPicker { selected });
    }
}

fn slash_arg<'a>(input: &'a str, command: &str) -> Option<&'a str> {
    if input == command {
        Some("")
    } else {
        input
            .strip_prefix(command)
            .and_then(|rest| rest.strip_prefix(' '))
            .map(str::trim)
    }
}

fn capability_proposal_path(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_start_matches('/').replace('\\', "/");

    if trimmed.is_empty() {
        return None;
    }

    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == "..")
    {
        return None;
    }

    if trimmed.contains('/') {
        Some(trimmed)
    } else {
        Some(format!(".ouroboros/capabilities/{trimmed}"))
    }
}

fn format_capability_list(value: &Value) -> String {
    let Some(items) = value.as_array() else {
        return "listed capability proposals".into();
    };

    if items.is_empty() {
        return "no capability proposals under .ouroboros/capabilities".into();
    }

    let names: Vec<String> = items
        .iter()
        .filter_map(|item| {
            item.get("path")
                .and_then(Value::as_str)
                .map(|path| path.rsplit('/').next().unwrap_or(path).to_string())
                .or_else(|| {
                    item.get("module")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
        })
        .collect();

    format!(
        "{} proposal{}: {}",
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names.join(", ")
    )
}

fn format_capability_preview(id: &str, value: &Value) -> String {
    let module = value.get("module").and_then(Value::as_str).unwrap_or(id);
    let loaded = value
        .get("loaded?")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let report = value.get("test_report");
    let total = report
        .and_then(|report| report.get("total"))
        .and_then(Value::as_u64);
    let failures = report
        .and_then(|report| report.get("failures"))
        .and_then(Value::as_u64);
    let tests = match (total, failures) {
        (Some(total), Some(failures)) => {
            format!("tests {}/{total}", total.saturating_sub(failures))
        }
        _ => "tests unknown".into(),
    };
    let load = if loaded {
        "loaded on this node"
    } else {
        "not loaded"
    };

    format!("preview {module}: {tests}, {load}")
}

fn format_capability_admit(id: &str, value: &Value) -> String {
    let module = value.get("module").and_then(Value::as_str).unwrap_or(id);
    let epoch = value
        .get("epoch")
        .map(model::compact)
        .unwrap_or_else(|| "-".into());
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let started = match value.get("started") {
        None | Some(Value::Null) => None,
        Some(started) => {
            if let Some(error) = started.get("error") {
                Some(format!("start failed: {}", model::compact(error)))
            } else if let Some(agent) = started.get("id").and_then(Value::as_str) {
                Some(format!("started {agent}"))
            } else {
                Some(model::compact(started))
            }
        }
    };

    match started {
        Some(started) => format!("admitted {module} epoch={epoch} {state}; {started}"),
        None => format!("admitted {module} epoch={epoch} {state}"),
    }
}
