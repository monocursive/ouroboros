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
    /// B4. The `@`-mentions and pasted images this turn will carry as
    /// `params.input.attachments`, drawn as chips above the editor. Bounded by
    /// [`TurnInput::ATTACHMENT_LIMIT`], which is the gateway's own ceiling.
    pub attachments: Vec<Attachment>,
    /// A per-turn `reasoning_effort` override from `/effort`. Cleared after a send: it is
    /// *per turn*, and a dial that silently stayed set would be a mode wearing a verb's
    /// clothes.
    pub reasoning_effort: Option<Effort>,
    /// The last refusal that was about this composer's own attachments, kept on the
    /// composer rather than in the notice row so the chips and the reason why they were
    /// rejected are on screen together.
    pub attachment_refusal: Option<String>,
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

    /// The whole envelope this composer would send right now.
    pub(super) fn turn_input(&self, prompt: String) -> TurnInput {
        TurnInput {
            prompt,
            attachments: self.attachments.clone(),
            reasoning_effort: self.reasoning_effort,
        }
    }

    /// Adds one attachment, refusing a duplicate and the 33rd.
    pub(super) fn attach(&mut self, attachment: Attachment) -> Result<(), AttachError> {
        if self
            .attachments
            .iter()
            .any(|existing| existing.path == attachment.path)
        {
            return Err(AttachError::Duplicate);
        }

        if self.attachments.len() >= TurnInput::ATTACHMENT_LIMIT {
            return Err(AttachError::Full);
        }

        self.attachments.push(attachment);
        self.attachment_refusal = None;
        Ok(())
    }
}

/// Why a chip was not added. Both are the operator's to know: a silently dropped
/// attachment is a turn that quietly does something other than what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttachError {
    Duplicate,
    Full,
}

#[derive(Debug, Clone)]
pub(super) struct ReconciliationDraftOwner {
    pub(super) turn_id: String,
    pub(super) generation: u64,
}

/// How many drafts this client will hold for one session before Enter refuses.
///
/// The runtime's own follow-up queue is durable and unbounded by anything this client
/// can see; this bounds only what is still *here*, unsent, and would be lost if the
/// process died. Thirty-two is the gateway's own attachment ceiling reused as a number
/// that is obviously a bound rather than a guess.
pub const QUEUE_LIMIT: usize = 32;

/// A draft the operator sent with Enter that this client could not dispatch yet.
///
/// It exists because JSON-RPC acknowledgements are the only proof a turn was accepted and
/// exactly one same-session mutation may be outstanding at a time (`submission_sequence`
/// is what protects the order the keys were pressed). Before B3 a second Enter was
/// *refused* and the draft stayed in the editor; now it is accepted, drawn, and
/// dispatched the moment the earlier acknowledgement lands.
///
/// These are the rows labelled `local` in the queue panel. They are **not** durable: only
/// the runtime's own `queue_changed` depth is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDraft {
    pub input: TurnInput,
}

#[derive(Debug, Clone)]
pub(super) struct SavedComposerDraft {
    pub(super) input: String,
    pub(super) generation: u64,
    pub(super) reconciliation_owner: Option<ReconciliationDraftOwner>,
    pub(super) attachments: Vec<Attachment>,
    pub(super) reasoning_effort: Option<Effort>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingComposerReconciliation {
    pub(super) kind: PendingReconciliationKind,
    pub(super) input: TurnInput,
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
    /// Codex's `/raw`: every cell drawn with no frame, gutter, glyph column, or app-side
    /// wrapping, so a native terminal selection yields logical lines. Read by the footer,
    /// which shows a `raw` badge while it is on.
    pub raw_mode: bool,
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
    /// Drafts accepted with Enter that have not reached the runtime yet, oldest first.
    ///
    /// Keyed by session rather than by the open composer, exactly like
    /// [`pending_reconciliations`](Self::pending_reconciliations), so switching away and
    /// back does not lose them and an interrupt does not either (Claude Code #16905: Esc
    /// must keep working *and* keep the queue).
    pub(super) queued_drafts: HashMap<(Plane, String), Vec<QueuedDraft>>,
    /// Sessions this client auto-approves: every ordinary approval request is answered
    /// `approve, once` the moment it arrives, marked `actor: automation` in the runtime's
    /// ledger. Plan-exit questions still ask — see `ApprovalRequest::plan_exit`.
    ///
    /// Client-side and this-client-only, deliberately: the runtime's `approval_mode` is
    /// what the session was *started* with and providers renegotiate changes to it
    /// unevenly, while an answering robot at the keyboard works identically for every
    /// transport and leaves an honest per-request ledger trail. Not persisted — the mode
    /// is an operator's live decision about a running session, not a preference.
    pub auto_approve: HashSet<(Plane, String)>,
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
}

/// One row of the session list, with the two things a renderer needs beside the session
/// itself: which triage group it landed in, and how deep it is nested under a parent.
#[derive(Debug, Clone, Copy)]
pub struct TriageRow<'a> {
    pub group: Triage,
    /// `0` for a top-level row, `1` for a coding task its parent conversation delegated.
    pub depth: usize,
    pub session: &'a SessionInfo,
}

impl SessionsTab {
    /// Both planes' sessions in one list, across every fleet node, grouped by what each
    /// one needs (G2) and then ordered so the list does not reshuffle under the cursor
    /// between polls: newest activity first, ties broken by plane then id.
    ///
    /// The grouping is the ordering, not a second pass: every surface that lists sessions
    /// — the rail, the picker, `ouro agents` — reads this one function, so a session that
    /// is first here is first everywhere.
    pub fn merged(&self) -> Vec<&SessionInfo> {
        self.triaged().into_iter().map(|row| row.session).collect()
    }

    /// The same list with each row's group beside it, for the surfaces that draw headings.
    pub fn triaged(&self) -> Vec<TriageRow<'_>> {
        let mut rows: Vec<(Triage, &SessionInfo)> = self
            .interactive
            .value
            .iter()
            .flatten()
            .chain(self.coding.value.iter().flatten())
            .map(|session| (self.triage_of(session), session))
            .collect();

        rows.sort_by(|(left_group, left), (right_group, right)| {
            left_group
                .cmp(right_group)
                .then_with(|| right.updated_at.cmp(&left.updated_at))
                .then_with(|| left.plane.cmp(&right.plane))
                .then_with(|| left.id.cmp(&right.id))
        });

        // One row represents one addressable v1 stream. A duplicate explicit ID is still
        // visible, but as a single conflict row whose owners are named by the renderer.
        let mut seen = HashSet::new();
        rows.retain(|(_group, session)| seen.insert((session.plane, session.id.clone())));

        Self::nest_children(rows)
    }

    /// G1. Moves each delegated coding task directly under the conversation that started
    /// it, and marks it as nested.
    ///
    /// **Only within a group.** The two orderings this rail carries answer different
    /// questions — "what needs me" and "who started this" — and where they disagree the
    /// first one wins, because a child that needs a human must not be buried under a
    /// parent that does not. A child whose parent sits in another group therefore keeps
    /// its own place at depth zero, which is the honest answer rather than a tree drawn
    /// across a heading.
    fn nest_children(rows: Vec<(Triage, &SessionInfo)>) -> Vec<TriageRow<'_>> {
        let mut ordered: Vec<TriageRow<'_>> = Vec::with_capacity(rows.len());
        let mut taken: HashSet<(Plane, String)> = HashSet::new();

        for (group, session) in &rows {
            if taken.contains(&(session.plane, session.id.clone())) {
                continue;
            }

            ordered.push(TriageRow {
                group: *group,
                depth: 0,
                session,
            });

            if session.children.is_empty() {
                continue;
            }

            for (child_group, child) in &rows {
                let claimed = child.plane == Plane::Coding
                    && (session.children.iter().any(|id| id == &child.id)
                        || child
                            .parent
                            .as_ref()
                            .is_some_and(|parent| parent.id == session.id));

                if claimed && child_group == group {
                    taken.insert((child.plane, child.id.clone()));
                    ordered.push(TriageRow {
                        group: *child_group,
                        depth: 1,
                        session: child,
                    });
                }
            }
        }

        ordered
    }

    /// Which group one row belongs to, counting the approvals this client is holding for
    /// it as well as the status the plane declared. Unanswered ones, that is: an approval
    /// the auto-approve robot (or a keypress) has already answered is not a reason to
    /// triage the row as waiting on a person.
    pub fn triage_of(&self, session: &SessionInfo) -> Triage {
        let pending = self
            .watches
            .get(&(session.plane, session.id.clone()))
            .map(Watch::unanswered_approvals)
            .unwrap_or(0);

        session.triage(pending)
    }

    /// How many rows sit in each group, for the footer's cell and for `ouro agents`.
    pub fn triage_counts(&self) -> [usize; 3] {
        let mut counts = [0usize; 3];

        for row in self.triaged() {
            counts[row.group as usize] += 1;
        }

        counts
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

    /// The local, not-yet-durable drafts for the open session, oldest first.
    pub fn open_queued_drafts(&self) -> &[QueuedDraft] {
        self.open
            .as_ref()
            .and_then(|key| self.queued_drafts.get(key))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The runtime's own follow-up depth for the open session, as `queue_changed` last
    /// reported it. `0` where no such event has been seen — the footer is the surface that
    /// distinguishes "zero" from "never said", and the queue panel only needs the rows.
    pub fn open_runtime_queue(&self) -> usize {
        self.open_watch().map(Watch::queue_len).unwrap_or(0)
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
            editor.paste(pending.input.prompt(), &self.completion_catalog);
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

        let (attachments, reasoning_effort) = self
            .sessions
            .composer_drafts
            .get(&key)
            .map(|saved| (saved.attachments.clone(), saved.reasoning_effort))
            .unwrap_or_default();

        self.sessions.composer = Some(Composer {
            verb,
            editor,
            draft_generation,
            reconciliation_owner,
            attachments,
            reasoning_effort,
            attachment_refusal: None,
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
        let attachments = composer.attachments.clone();
        let reasoning_effort = composer.reasoning_effort;

        self.sessions.composer_history.insert(key.clone(), history);
        // Chips and a per-turn effort are part of the unsent draft: a composer closed with
        // Esc and reopened with `i` that had quietly dropped them would send a different
        // turn from the one on screen a moment earlier.
        if draft.is_empty() && attachments.is_empty() && reasoning_effort.is_none() {
            self.sessions.composer_drafts.remove(&key);
        } else {
            self.sessions.composer_drafts.insert(
                key,
                SavedComposerDraft {
                    input: draft,
                    generation,
                    reconciliation_owner,
                    attachments,
                    reasoning_effort,
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

    /// `/raw`: Codex's copy mode.
    ///
    /// Deliberately palette- and slash-only, with no chord of its own: the composer owns
    /// the keyboard while a session is open, and spending another leader key on a toggle
    /// that is reached twice a week is how a key map stops being learnable.
    pub(super) fn toggle_raw_transcript(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform(
                "open a session before switching it to raw",
                NoticeKind::Info,
            );
            return;
        }

        self.sessions.raw_mode = !self.sessions.raw_mode;

        if let Some(watch) = self.sessions.open_watch_mut() {
            // Undecorating rewrites every cell's height, so a line-based offset taken
            // against the framed layout no longer points at the rows it was taken from.
            watch.follow = true;
            watch.scroll = 0;
        }

        self.inform(
            if self.sessions.raw_mode {
                "raw: no frames or gutters — select with shift or option to copy logical lines"
            } else {
                "raw off"
            },
            NoticeKind::Info,
        );
    }

    /// `Ctrl+T`: the plan panel. It stays open while the session is idle on purpose —
    /// a task list that vanishes the moment the agent stops is Codex #18920.
    pub(super) fn toggle_plan_panel(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform("open a session before showing its plan", NoticeKind::Info);
            return;
        }

        self.sessions.show_plan = !self.sessions.show_plan;

        // G1. The panel lists this conversation's children beside its plan, so opening it
        // is what reads them. Only on the way *open*: closing a panel is not a reason to
        // ask the runtime anything.
        if self.sessions.show_plan {
            self.read_delegations();
        }
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

        use crossterm::event::KeyCode;

        // B3. `↑` on an empty draft takes the newest queued draft back before the editor
        // can read it as prompt history. Claimed here rather than in the editor because
        // the queue belongs to the session, not to the text field, and because a draft
        // with text in it means the operator is writing rather than retracting.
        if self.retract_key(key) && self.retract_queued_draft() {
            return;
        }

        // B4. `Ctrl+V` and Backspace-at-the-chip are about the *attachments*, which the
        // editor knows nothing about, so both are claimed before it sees them. Backspace
        // with text in the draft is still Backspace.
        if self.keymap.hits(Action::PasteImage, key) {
            self.request_clipboard_paste();
            return;
        }

        if key.code == KeyCode::Backspace && key.modifiers.is_empty() && self.detach_newest() {
            return;
        }

        let action = self
            .sessions
            .composer
            .as_mut()
            .map(|composer| {
                let before = composer.editor.text().to_string();
                let action =
                    composer
                        .editor
                        .handle_key_with(key, &self.completion_catalog, &self.keymap);
                if composer.editor.text() != before {
                    composer.user_changed_draft();
                }
                action
            })
            .unwrap_or(EditorAction::None);

        // Before the action, so a Tab that completes `@src/app.rs` and an Enter that sends
        // in the same breath cannot send the turn without the chip that keystroke made.
        self.collect_completed_attachments();

        match action {
            EditorAction::Submit => self.submit_composer(),
            EditorAction::SubmitAlternate => self.alternate_submit(),
            EditorAction::Cancel => self.escape_from_prompt(),
            EditorAction::Scroll(delta) => self.move_by(delta * 10),
            EditorAction::None => {}
        }
    }

    /// Opens the composer with `text` already in it, leaving the caret at the end.
    ///
    /// How the palette teaches a verb that takes an argument: the row is discoverable, and
    /// what it produces is the same `/` command that would have been typed, so there is
    /// one spelling of it rather than two.
    pub(super) fn prefill_composer(&mut self, text: &str) {
        if self.sessions.open.is_none() {
            self.inform(
                "open a session before setting anything on its next turn",
                NoticeKind::Info,
            );
            return;
        }

        self.compose(ComposerVerb::Message);

        let catalog = self.completion_catalog.clone();
        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.editor.clear_text();
            composer.editor.paste(text, &catalog);
            composer.user_changed_draft();
        }
    }

    // ----- B5: Esc, Esc Esc, and going back ------------------------------------------

    /// Whether the backtrack menu may offer a fork.
    ///
    /// Two gates, both of them real: `hello.methods` decides whether this gateway serves
    /// the verb at all, and `capabilities.fork` decides whether the transport this session
    /// selected can honour it. An unknown capability is not "no" — hiding the verb on a
    /// runtime that never spoke about forking would be this client inventing a ceiling —
    /// but an absent *method* is, because the call would come back `-32601`.
    pub fn fork_offered(&self) -> bool {
        self.hello.serves("interactive.fork") && self.open_capabilities().fork.offered()
    }

    /// How many user turns the backtrack menu lists. Ten, as Claude Code's rewind does.
    pub(super) const BACKTRACK_ENTRIES: usize = 10;

    /// Opens the backtrack menu for the open session, reopening it if the first Esc of an
    /// `Esc Esc` had already left it.
    pub(super) fn open_backtrack(&mut self, key: Option<(Plane, String)>) {
        let Some((plane, id)) = key.or_else(|| self.sessions.open.clone()) else {
            self.inform(
                "open a session before going back through it",
                NoticeKind::Info,
            );
            return;
        };

        if plane != Plane::Interactive {
            self.inform(
                format!("{id} is a coding task: it has one objective and no earlier messages"),
                NoticeKind::Info,
            );
            return;
        }

        if self.sessions.open.as_ref() != Some(&(plane, id.clone())) {
            self.open_session(plane, id.clone());
        }

        let entries = self
            .sessions
            .watches
            .get(&(plane, id.clone()))
            .map(|watch| watch.recent_user_turns(Self::BACKTRACK_ENTRIES))
            .unwrap_or_default();

        if entries.is_empty() {
            self.inform(
                format!("{id} has no earlier message this client has replayed"),
                NoticeKind::Info,
            );
            return;
        }

        let choice = entries.len().saturating_sub(1);
        let fork_offered = self.fork_offered();
        // D6. A rewind is the third answer this menu can give, and it is offered on the
        // same two-gate rule as the fork: the method must be served and the transport must
        // be the one that keeps the checkpoints a rewind restores from.
        let rewind_offered = self
            .native_verb_offered("interactive.rewind_points")
            .is_ok();

        self.overlay = Some(Overlay::Backtrack {
            plane,
            id,
            entries,
            choice,
            fork_offered,
            rewind_offered,
        });
    }

    /// "Edit and resend as a new turn": the chosen message's text goes into the composer.
    ///
    /// Deliberately not called a rewind. Nothing about this removes what came after it —
    /// the transcript is unchanged and the provider's context is unchanged — and a menu
    /// that implied otherwise would be the rewind that silently under-delivers.
    pub(super) fn backtrack_edit(&mut self) {
        let Some(Overlay::Backtrack {
            plane,
            id,
            entries,
            choice,
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        let Some((_sequence, text)) = entries.get(choice).cloned() else {
            return;
        };

        if self.sessions.open.as_ref() != Some(&(plane, id.clone())) {
            self.open_session(plane, id.clone());
        }

        self.compose(ComposerVerb::Message);

        let catalog = self.completion_catalog.clone();
        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.editor.clear_text();
            composer.editor.paste(&text, &catalog);
            composer.user_changed_draft();
        }

        self.remember_composer_history();
        self.inform(
            "that message is in the composer as a new turn; nothing earlier was removed",
            NoticeKind::Info,
        );
    }

    /// `interactive.fork`, where the gateway serves it and the transport can take it.
    ///
    /// **What the fork carries is the runtime's to say, and this client does not say more.**
    /// The verb takes a session and a routing node and no message, so a branch that started
    /// exactly at the highlighted row is not something this client can promise: Codex can
    /// fork a thread from a message, Claude's `--fork-session` branches at the tail, and
    /// which of those a session gets is decided on the other side of the wire. The menu
    /// says that, and the notice says it again.
    pub(super) fn backtrack_fork(&mut self) {
        let Some(Overlay::Backtrack { plane, id, .. }) = self.overlay.take() else {
            return;
        };

        self.fork_session(plane, &id);
    }

    /// `/fork` and the palette's Fork row: the same call, without going through the menu.
    pub(super) fn fork_open_session(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a session before forking it", NoticeKind::Info);
            return;
        };

        self.fork_session(plane, &id);
    }

    fn fork_session(&mut self, plane: Plane, id: &str) {
        let method = "interactive.fork";

        if !self.hello.serves(method) {
            self.inform(
                format!("this gateway does not serve {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        if !self.open_capabilities().fork.offered() {
            let capabilities = self.open_capabilities();
            let transport = capabilities
                .transport
                .as_deref()
                .map(|transport| transport.to_string())
                .unwrap_or_else(|| "this transport".to_string());

            self.inform(
                format!("{transport} cannot branch a session"),
                NoticeKind::Info,
            );
            return;
        }

        let params = self.routed_session_params(plane, id, json!({ "id": id }));

        self.issue(Call::new(
            Tag::Action {
                label: "fork",
                plane,
                id: id.to_string(),
            },
            method,
            params,
        ));

        self.inform(
            format!(
                "asking the runtime to fork {id}; where the branch starts is the transport's \
                 decision, not this client's"
            ),
            NoticeKind::Info,
        );
    }

    // ----- B4: structured input ------------------------------------------------------

    /// Lifts every `@path` the editor just completed into an attachment chip.
    ///
    /// The text stays in the prompt and the path *also* travels structurally, which is the
    /// difference B4 is about: before this, `@src/app.rs` was substituted text and the
    /// gateway's `{prompt, attachments, reasoning_effort}` envelope — accepted since
    /// `structured_turn_input` landed — was never sent by anything.
    fn collect_completed_attachments(&mut self) {
        let paths = self
            .sessions
            .composer
            .as_mut()
            .map(|composer| composer.editor.take_completed_paths())
            .unwrap_or_default();

        if paths.is_empty() {
            return;
        }

        // D14: an attachment is only carried where the runtime said this transport takes
        // one. Elsewhere the `@` still completes as text — it always did — and the chip is
        // refused by name so nobody is left wondering where it went.
        if !self.multimodal_offered() {
            let capabilities = self.open_capabilities();
            let transport = capabilities
                .transport
                .as_deref()
                .map(|transport| transport.to_string())
                .unwrap_or_else(|| "this transport".to_string());

            self.inform(
                format!(
                    "{transport} takes no attachments, so the path stays in the prompt as text \
                     rather than becoming a chip"
                ),
                NoticeKind::Info,
            );
            return;
        }

        let mut full = false;

        for path in paths {
            let attachment = Attachment::path(path);

            match self
                .sessions
                .composer
                .as_mut()
                .map(|composer| composer.attach(attachment))
            {
                Some(Err(AttachError::Full)) => full = true,
                _added_or_duplicate => {}
            }
        }

        if full {
            self.inform(
                format!(
                    "a turn carries at most {} attachments; the rest stay in the prompt as text",
                    TurnInput::ATTACHMENT_LIMIT
                ),
                NoticeKind::Warn,
            );
        }
    }

    /// Backspace on an empty draft: the newest chip comes off.
    ///
    /// This is "Backspace at the chip" — with the draft empty the caret sits immediately
    /// after the last chip, which is where Backspace has meant "delete the thing before
    /// the caret" since readline. The composer chrome names it, because a chip that can
    /// only be removed by a key nobody mentions is a chip that cannot be removed.
    fn detach_newest(&mut self) -> bool {
        let Some(composer) = self.sessions.composer.as_mut() else {
            return false;
        };

        if !composer.editor.is_empty() {
            return false;
        }

        let Some(removed) = composer.attachments.pop() else {
            return false;
        };

        composer.attachment_refusal = None;
        self.remember_composer_history();
        self.inform(
            format!("removed the attachment {}", removed.path),
            NoticeKind::Info,
        );
        true
    }

    /// `/effort low|medium|high`: `reasoning_effort` on the *next* send, and only that one.
    fn set_reasoning_effort(&mut self, level: &str) {
        if self.sessions.composer.is_none() {
            return;
        }

        if level.is_empty() {
            let current = self
                .sessions
                .composer
                .as_ref()
                .and_then(|composer| composer.reasoning_effort);

            self.inform(
                match current {
                    Some(effort) => format!(
                        "the next turn carries reasoning_effort {}. /effort low|medium|high \
                         changes it; /effort none clears it",
                        effort.as_str()
                    ),
                    None => "/effort low|medium|high sets reasoning_effort on the next turn only"
                        .to_string(),
                },
                NoticeKind::Info,
            );
            return;
        }

        if matches!(level, "none" | "clear" | "off") {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.reasoning_effort = None;
            }
            self.remember_composer_history();
            self.inform("the next turn names no effort", NoticeKind::Info);
            return;
        }

        let Some(effort) = Effort::parse(level) else {
            self.inform(
                format!(
                    "{level} is not an effort the gateway takes; it accepts low, medium, and high"
                ),
                NoticeKind::Warn,
            );
            return;
        };

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.reasoning_effort = Some(effort);
        }

        self.remember_composer_history();
        self.inform(
            format!(
                "the next turn carries reasoning_effort {} — per turn, not a mode",
                effort.as_str()
            ),
            NoticeKind::Info,
        );
    }

    /// B2. `/plan`, `/plan on`, `/plan off`: `interactive.configure {plan}`.
    ///
    /// `None` toggles whatever the session is in now, which is what the palette row and
    /// the bare verb send. The posture is read from the same three sources the badge uses,
    /// so a toggle acts on what the operator can see rather than on a stale list.
    ///
    /// **This client does not predict the answer.** Plan mode is not a Harness
    /// configuration key: the native transport applies it now, Claude refuses a mid-life
    /// change because it carries the posture on every launch, and every other transport
    /// refuses by declaration. Which of those applies is the runtime's to say, so the
    /// refusal is rendered as data when it arrives instead of being second-guessed here.
    pub(super) fn configure_plan(&mut self, want: Option<bool>) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a session before asking it to plan", NoticeKind::Info);
            return;
        };

        if plane != Plane::Interactive {
            self.inform(
                format!("{id} is a coding task; plan mode is a conversation's posture"),
                NoticeKind::Info,
            );
            return;
        }

        let method = "interactive.configure";

        if !self.hello.serves(method) {
            self.inform(
                format!(
                    "this gateway does not serve {method}, so plan mode cannot be changed \
                     on a running session; start a new one with --plan"
                ),
                NoticeKind::Warn,
            );
            return;
        }

        let planning = self.open_planning();
        let want = want.unwrap_or(!planning);

        if want == planning {
            self.inform(
                if want {
                    format!("{id} is already planning; /plan off leaves plan mode")
                } else {
                    format!("{id} is not planning; /plan on enters plan mode")
                },
                NoticeKind::Info,
            );
            return;
        }

        let params = self.routed_session_params(plane, &id, json!({ "id": id, "plan": want }));

        self.issue(Call::new(
            Tag::PlanMode {
                plane,
                id: id.clone(),
                want,
            },
            method,
            params,
        ));

        self.inform(
            if want {
                format!("asking {id} to plan — it will stop editing anything")
            } else {
                format!("asking {id} to leave plan mode")
            },
            NoticeKind::Info,
        );
    }

    /// `/auto-approve [on|off]`: the client-side mode that answers every ordinary
    /// approval this session raises with `approve, once, actor: automation`.
    ///
    /// Client-side on purpose — see [`SessionsTab::auto_approve`]. Turning it on answers
    /// the backlog immediately (including the request an open modal is showing, whose
    /// modal then closes under it); turning it off reopens the modal for anything still
    /// unanswered. Plan-exit questions are never auto-answered on either path.
    pub(super) fn set_auto_approve(&mut self, want: Option<bool>) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "open a session before switching it to auto-approve",
                NoticeKind::Info,
            );
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let key = (plane, id.clone());
        let current = self.sessions.auto_approve.contains(&key);
        let want = want.unwrap_or(!current);

        if want == current {
            self.inform(
                if want {
                    format!("{id} is already auto-approving; /auto-approve off stops it")
                } else {
                    format!("{id} is not auto-approving; /auto-approve on starts it")
                },
                NoticeKind::Info,
            );
            return;
        }

        if want {
            self.sessions.auto_approve.insert(key.clone());
            self.auto_answer_approvals(plane, &id);

            // A modal whose request the flush just answered is a question with no
            // answerer left; one it skipped — a plan exit or an `ask_user` question —
            // keeps its modal, because a person still owes that answer.
            if let Some(Overlay::Approval {
                plane: modal_plane,
                id: modal_id,
                request_id,
                ..
            }) = self.overlay.as_ref()
            {
                let answered_under_it = *modal_plane == plane
                    && *modal_id == id
                    && !self
                        .sessions
                        .watches
                        .get(&key)
                        .is_some_and(|watch| watch.awaiting_answer(request_id));

                if answered_under_it {
                    self.overlay = None;
                }
            }

            self.inform(
                format!(
                    "auto-approve on: this client answers yes to everything {id} asks, \
                     for this session; plan and ask-user questions still ask. \
                     /auto-approve off stops it"
                ),
                NoticeKind::Warn,
            );
        } else {
            self.sessions.auto_approve.remove(&key);
            self.inform(
                format!("auto-approve off: {id} asks before acting again"),
                NoticeKind::Info,
            );
            // Anything that arrived un-answerable while the toggle flipped — a failed
            // send, a plan exit behind another overlay — gets its modal back.
            self.open_approval(plane, id);
        }
    }

    /// `/model <name>`: `interactive.configure`, where the gateway serves it.
    ///
    /// The method is behind the `hello.methods` gate like every other verb. A gateway that
    /// does not serve it is answered here with the same `-32601` sentence the client
    /// already uses, naming the method, rather than by a call that would come back refused.
    fn configure_model(&mut self, model: &str) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform("open a session before changing its model", NoticeKind::Info);
            return;
        };

        if plane != Plane::Interactive {
            self.inform(
                format!("{id} is a coding task; its model is fixed at start"),
                NoticeKind::Info,
            );
            return;
        }

        if model.is_empty() {
            let current = self
                .sessions
                .open_info()
                .and_then(|session| session.model.clone())
                .or_else(|| {
                    self.sessions
                        .open_watch()
                        .and_then(Watch::model)
                        .map(str::to_string)
                });

            self.inform(
                match current {
                    Some(model) => format!("{id} is running {model}; /model <name> changes it"),
                    None => format!(
                        "neither the start nor the transcript named a model for {id}; \
                         /model <name> sets one"
                    ),
                },
                NoticeKind::Info,
            );
            return;
        }

        let method = "interactive.configure";

        if !self.hello.serves(method) {
            self.inform(
                format!(
                    "this gateway does not serve {method}, so the model cannot be changed \
                         on a running session; start a new one with the model you want"
                ),
                NoticeKind::Warn,
            );
            return;
        }

        // D14: the footer says "from next turn" where that is the truth, and the truth is
        // the transport's `dynamic_configuration` mechanism, which the runtime declares.
        let capabilities = self.open_capabilities();
        let when = match capabilities.dynamic_model.mechanism() {
            Some("native") => "on the running turn",
            Some(_managed) => "from the next turn",
            None => "when the runtime is able to apply it",
        };

        let params = self.routed_session_params(plane, &id, json!({ "id": id, "model": model }));

        self.issue(Call::new(
            Tag::Action {
                label: "configure",
                plane,
                id: id.clone(),
            },
            method,
            params,
        ));

        self.inform(
            format!("asking {id} for {model} — {when}"),
            NoticeKind::Info,
        );
    }

    /// `Ctrl+V`: the clipboard, as an image where it holds one.
    fn request_clipboard_paste(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        if plane != Plane::Interactive {
            return;
        }

        if !self.multimodal_offered() {
            let capabilities = self.open_capabilities();
            let transport = capabilities
                .transport
                .as_deref()
                .map(|transport| transport.to_string())
                .unwrap_or_else(|| "this transport".to_string());

            self.inform(
                format!("{transport} takes no images, so ctrl+v pastes text only here"),
                NoticeKind::Info,
            );
            return;
        }

        let Some(workspace) = self
            .sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .filter(|workspace| !workspace.trim().is_empty())
        else {
            self.inform(
                format!(
                    "{id} reported no workspace, and an attachment has to live inside one for \
                     the runtime to accept it"
                ),
                NoticeKind::Warn,
            );
            return;
        };

        self.clipboard_pending = Some(ClipboardRequest {
            workspace,
            id: new_turn_id(),
        });
    }

    /// What the driver found on the clipboard.
    pub(super) fn clipboard_read(&mut self, outcome: ClipboardOutcome) {
        match outcome {
            ClipboardOutcome::Image(path) => {
                let attachment = Attachment::image(path.clone());

                match self
                    .sessions
                    .composer
                    .as_mut()
                    .map(|composer| composer.attach(attachment))
                {
                    Some(Ok(())) => {
                        self.remember_composer_history();
                        self.inform(format!("attached {path}"), NoticeKind::Info);
                    }
                    Some(Err(AttachError::Full)) => self.inform(
                        format!(
                            "a turn carries at most {} attachments; {path} was written but not \
                             attached",
                            TurnInput::ATTACHMENT_LIMIT
                        ),
                        NoticeKind::Warn,
                    ),
                    Some(Err(AttachError::Duplicate)) | None => {}
                }
            }
            // The fall-through: a clipboard with no image is an ordinary paste, and this
            // key must never be one that silently does nothing.
            ClipboardOutcome::Text(text) => self.paste(&text),
            ClipboardOutcome::Empty => self.inform(
                "the clipboard held nothing this client could read",
                NoticeKind::Info,
            ),
            ClipboardOutcome::NoTool => {
                if !self.clipboard_tool_reported {
                    self.clipboard_tool_reported = true;
                    self.inform(
                        "no clipboard tool on this machine: install pngpaste (macOS) or \
                         wl-clipboard/xclip (Linux), or set OURO_CLIPBOARD_IMAGE_COMMAND",
                        NoticeKind::Warn,
                    );
                }
            }
            ClipboardOutcome::Failed(reason) => self.inform(
                format!("the clipboard paste failed: {reason}"),
                NoticeKind::Warn,
            ),
        }
    }

    /// Keeps an attachment refusal on the composer that produced it.
    ///
    /// `authorize_turn_attachments` refuses a path outside the session workspace, and one
    /// that does not resolve at all, before the turn is dispatched. The chips are already
    /// back in the composer by the time this runs — [`Self::restore_composer_submission`]
    /// put them there — so the reason goes next to them.
    pub(super) fn note_attachment_refusal(&mut self, diagnostic: &str) {
        if !model::attachment_refusal(diagnostic) {
            return;
        }

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.attachment_refusal = Some(diagnostic.to_string());
        }
    }

    /// Whether this keystroke is the bare `↑` that retracts, on an empty draft.
    fn retract_key(&self, key: crossterm::event::KeyEvent) -> bool {
        self.keymap.hits(Action::QueueRetract, key)
            && self
                .sessions
                .composer
                .as_ref()
                .is_some_and(|composer| composer.editor.is_empty())
    }

    /// `Alt+Enter`: the second send key.
    ///
    /// Two explicit keys is the fix R1 §4d(2) names for the queue/steer confusion that
    /// produced Codex #13595 and #17285 — never one key whose meaning depends on timing.
    /// Enter queues; `Alt+Enter` steers. Where the runtime declared `steer: false` this
    /// session has no second verb at all, so the key keeps the newline it always inserted
    /// there and the composer chrome does not advertise a steer.
    fn alternate_submit(&mut self) {
        if !self.steer_offered() {
            let catalog = self.completion_catalog.clone();

            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.paste("\n", &catalog);
                composer.user_changed_draft();
            }

            return;
        }

        let Some(composer) = self.sessions.composer.as_ref() else {
            return;
        };

        if composer.editor.submission().is_none() {
            return;
        }

        let restore = composer.verb;
        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.verb = ComposerVerb::Steer;
        }

        self.submit_composer();

        // The verb is a property of the composer, not of the keystroke: an `Alt+Enter`
        // must not leave the next bare Enter meaning "steer".
        if let Some(composer) = self.sessions.composer.as_mut() {
            if composer.verb == ComposerVerb::Steer {
                composer.verb = if restore == ComposerVerb::Steer {
                    ComposerVerb::FollowUp
                } else {
                    restore
                };
            }
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

    pub(super) fn submit_composer(&mut self) {
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
                "input": pending.input.to_value(),
                "turn_id": pending.turn_id
            });
            let params = self.routed_session_params(plane, &id, params);
            let call = match pending.kind {
                PendingReconciliationKind::FirstMessage => Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: id.clone(),
                        turn_id: pending.turn_id,
                        input: pending.input.prompt.clone(),
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

        // B7. A draft that begins with `!` is the operator's own command, not a message to
        // the model. Claimed here, beside the slash verbs, because it is the same kind of
        // thing: a line the composer acts on itself rather than sending as a turn.
        if let Some(command) = input.strip_prefix('!') {
            self.run_operator_shell(command);

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
        // B3. Before this slice a second Enter was refused and the draft was left in the
        // editor for the operator to press Enter again later. That is the one-in-flight
        // rule showing through as a *refusal*; the rule itself is still here — exactly one
        // same-session mutation may be outstanding, because `submission_sequence` is what
        // keeps the order the keys were pressed — but the draft is now accepted, drawn in
        // the queue panel as `local`, and dispatched as a follow-up the moment the earlier
        // acknowledgement lands.
        //
        // A steer is never queued: it is an injection into a call that is running *now*,
        // and one delivered several seconds later against a different tool boundary is not
        // the thing that was asked for.
        // The whole envelope, taken before anything clears the composer: a queued draft
        // that lost its chips would arrive as a different turn from the one drawn.
        let Some(turn_input) = self
            .sessions
            .composer
            .as_ref()
            .map(|composer| composer.turn_input(input.clone()))
        else {
            return;
        };

        if verb != ComposerVerb::Steer && self.same_session_mutation_in_flight(plane, &id) {
            let queued = self
                .sessions
                .queued_drafts
                .entry((plane, id.clone()))
                .or_default();

            if queued.len() >= QUEUE_LIMIT {
                self.inform(
                    format!(
                        "{id} already has {QUEUE_LIMIT} drafts waiting here; this one stays in \
                         the editor"
                    ),
                    NoticeKind::Warn,
                );
                return;
            }

            queued.push(QueuedDraft { input: turn_input });
            let ordinal = queued.len();

            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.accept_submission();
                composer.user_changed_draft();
                composer.attachments.clear();
                composer.reasoning_effort = None;
                composer.attachment_refusal = None;
            }
            self.remember_composer_history();

            self.inform(
                format!(
                    "queued here as #{ordinal} for {id}; it is sent when the earlier request is \
                     acknowledged. ↑ takes it back"
                ),
                NoticeKind::Info,
            );
            return;
        }

        if self.same_session_mutation_in_flight(plane, &id) {
            self.inform(
                format!(
                    "the earlier request for {id} is still awaiting acknowledgement; this steer \
                     remains unsent"
                ),
                NoticeKind::Info,
            );
            return;
        }

        let Some(composer) = self.sessions.composer.as_mut() else {
            return;
        };
        composer.editor.accept_submission();
        composer.user_changed_draft();
        composer.attachments.clear();
        composer.reasoning_effort = None;
        composer.attachment_refusal = None;

        // After the first immediate message, every later acknowledged submission uses
        // Harness's durable queueing verb.
        if composer.verb == ComposerVerb::Message {
            composer.verb = ComposerVerb::FollowUp;
        }

        self.remember_composer_history();
        self.dispatch_composer_turn(plane, &id, verb, turn_input);
    }

    /// Issues one turn. The single place a composer submission, a queued draft, and a
    /// retried steer all become a call, so the three cannot drift apart.
    fn dispatch_composer_turn(
        &mut self,
        plane: Plane,
        id: &str,
        verb: ComposerVerb,
        input: TurnInput,
    ) {
        let turn_id = if verb == ComposerVerb::Steer {
            // A steer is an injection into an already-running provider call. There is no
            // durable request ledger behind it, so do not manufacture an idempotency key.
            None
        } else {
            Some(new_turn_id())
        };

        let submission_sequence = self.next_composer_submission_sequence();
        let (label, method) = match verb {
            ComposerVerb::Message => ("send_message", plane.method("send_message")),
            ComposerVerb::FollowUp => ("follow_up", plane.method("follow_up")),
            ComposerVerb::Steer => ("steer", plane.method("steer")),
        };

        if matches!(verb, ComposerVerb::Message | ComposerVerb::FollowUp) {
            self.sessions.mark_reply_pending(plane, id);
            self.count_prompt();
        }

        let tag = Tag::ComposerAction {
            label,
            verb,
            plane,
            id: id.to_string(),
            turn_id: turn_id.clone(),
            input: input.clone(),
            reconciling: false,
            submission_sequence,
        };

        // B4: the bare string for a plain prompt, the gateway's object form the moment
        // there is an attachment or an effort to carry. Both are what the gateway accepts;
        // sending the object for every turn would rewrite the wire for nothing.
        let wire_input = input.to_value();
        let params = match turn_id {
            Some(turn_id) => json!({ "id": id, "input": wire_input, "turn_id": turn_id }),
            None => json!({ "id": id, "input": wire_input }),
        };
        let params = self.routed_session_params(plane, id, params);

        // A11. The images this turn carries, recorded where they were sent. Deliberately
        // after the params are built and before the call is issued: what is drawn is what
        // was actually put on the wire, and the header is read from the file this client
        // itself wrote a moment ago rather than from anything a provider will say later.
        self.note_sent_images(plane, id, &input);

        self.issue(Call::new(tag, method, params));
    }

    /// Draws the turn's image attachments into the transcript, one placeholder each.
    ///
    /// The runtime's `input_accepted` carries the prompt's text and nothing else, so an
    /// attachment never comes back down the stream — this is the only place the
    /// conversation can learn that a picture was part of the turn. Bounded by
    /// [`crate::model::ATTACHMENT_LIMIT`], which is what the composer already accepted.
    ///
    /// The header read is one bounded prefix of a local file per attachment, and it happens
    /// here rather than in the projection because projection must stay clock-free and
    /// filesystem-free: the export snapshot depends on it.
    fn note_sent_images(&mut self, plane: Plane, id: &str, input: &crate::model::TurnInput) {
        if input.attachments.is_empty() {
            return;
        }

        let workspace = self
            .sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .map(std::path::PathBuf::from);

        let images: Vec<_> = input
            .attachments
            .iter()
            .filter(|attachment| {
                // An attachment the composer classified as an image, or one whose name
                // ends in a format this client reads. A `@`-completed `notes.md` is not an
                // image and does not become a placeholder claiming to be one.
                attachment.kind == crate::model::AttachmentKind::Image
                    || crate::images::format_of(&attachment.path).is_some()
            })
            .map(|attachment| {
                let described = crate::images::describe(workspace.as_deref(), &attachment.path);

                crate::ui::transcript_cells::ImageCell {
                    named: attachment.path.clone(),
                    pixels: described.header.map(|header| (header.width, header.height)),
                    format: described
                        .header
                        .map(|header| header.format.as_str().to_string()),
                    note: described.note,
                }
            })
            .collect();

        if images.is_empty() {
            return;
        }

        if let Some(watch) = self.sessions.watches.get_mut(&(plane, id.to_string())) {
            for image in images {
                watch.image_note(image);
            }
        }
    }

    /// Sends whatever the queue is holding, for every session, as soon as it can.
    ///
    /// Driven from the answer path and from the tick rather than from one call site, so a
    /// draft queued behind a request that failed, was refused, or simply took a while is
    /// still sent — and so that a session the operator has navigated away from does not
    /// silently keep an unsent draft forever.
    ///
    /// Two things hold it back, both of them existing rules rather than new ones: a
    /// same-session mutation still in flight (the one-in-flight rule), and an
    /// outcome-unknown turn awaiting reconciliation (Enter reconciles the oldest before it
    /// can submit anything newer, and a queued draft is newer).
    pub(super) fn flush_queued_drafts(&mut self) {
        let ready = self
            .sessions
            .queued_drafts
            .iter()
            .filter(|(_key, drafts)| !drafts.is_empty())
            .map(|(key, _drafts)| key.clone())
            .filter(|(plane, id)| {
                !self.same_session_mutation_in_flight(*plane, id)
                    && self
                        .sessions
                        .pending_reconciliations
                        .get(&(*plane, id.clone()))
                        .is_none_or(VecDeque::is_empty)
            })
            .collect::<Vec<_>>();

        for (plane, id) in ready {
            let Some(drafts) = self.sessions.queued_drafts.get_mut(&(plane, id.clone())) else {
                continue;
            };

            if drafts.is_empty() {
                continue;
            }

            let draft = drafts.remove(0);

            if drafts.is_empty() {
                self.sessions.queued_drafts.remove(&(plane, id.clone()));
            }

            // Durable queueing is what `follow_up` is for, and this draft is by
            // construction not the session's first turn: something was in flight when it
            // was typed.
            self.dispatch_composer_turn(plane, &id, ComposerVerb::FollowUp, draft.input);
        }
    }

    /// `↑` on an empty draft: the newest queued draft comes back into the editor.
    ///
    /// Claude Code's rule, and the reason a visible queue is safe to have at all — a queue
    /// nobody can take something out of is a queue that has swallowed the message.
    /// Returns whether anything was retracted, so the key can fall through to prompt
    /// history when the queue is empty.
    pub(super) fn retract_queued_draft(&mut self) -> bool {
        let Some(key) = self.sessions.open.clone() else {
            return false;
        };

        let Some(drafts) = self.sessions.queued_drafts.get_mut(&key) else {
            return false;
        };

        let Some(draft) = drafts.pop() else {
            return false;
        };

        let remaining = drafts.len();

        if remaining == 0 {
            self.sessions.queued_drafts.remove(&key);
        }

        let catalog = self.completion_catalog.clone();

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.editor.clear_text();
            composer.editor.paste(draft.input.prompt(), &catalog);
            composer.user_changed_draft();
            // The whole turn comes back, not just its words.
            composer.attachments = draft.input.attachments.clone();
            composer.reasoning_effort = draft.input.reasoning_effort;
        }

        self.remember_composer_history();
        self.inform(
            format!("took the newest queued draft back; {remaining} still waiting here"),
            NoticeKind::Info,
        );
        true
    }

    pub(super) fn activate_slash_command(&mut self, input: &str) -> bool {
        let trimmed = input.trim();

        if let Some(level) = slash_arg(trimmed, "/effort") {
            self.set_reasoning_effort(level);
            return true;
        }

        if let Some(model) = slash_arg(trimmed, "/model") {
            self.configure_model(model);
            return true;
        }

        if let Some(name) = slash_arg(trimmed, "/preview") {
            self.preview_capability(name);
            return true;
        }

        if let Some(name) = slash_arg(trimmed, "/admit") {
            self.confirm_admit_capability(name);
            return true;
        }

        // A9. `/export` takes `[--json] [path]`; `/copy raw` is the source-Markdown twin of
        // `/copy`, which keeps its own row below.
        if let Some(argument) = slash_arg(trimmed, "/export") {
            self.export_transcript(argument);
            return true;
        }

        if slash_arg(trimmed, "/copy").is_some_and(|rest| rest.eq_ignore_ascii_case("raw")) {
            self.copy_last_agent_source();
            return true;
        }

        // A10. Bare `/theme` cycles; `/theme <name>` goes straight to one. Both take effect
        // on the next frame, which is the preview: there is nothing to preview a palette
        // *in* but the screen already showing the conversation.
        if trimmed == "/theme" {
            self.cycle_theme();
            return true;
        }

        if let Some(name) = slash_arg(trimmed, "/theme") {
            self.choose_theme(name);
            return true;
        }

        // D9/G1. Four verbs that take the rest of the line: a compaction focus, a handoff
        // prompt, a delegation's objective. Bare `/compact` is the unfocused fold, which
        // is why it also has a row in the table below.
        if let Some(focus) = slash_arg(trimmed, "/compact") {
            self.compact_session(Some(focus));
            return true;
        }

        if let Some(prompt) = slash_arg(trimmed, "/handoff") {
            self.handoff_session(prompt);
            return true;
        }

        if let Some(objective) = slash_arg(trimmed, "/delegate") {
            self.delegate(objective);
            return true;
        }

        // B2. `/plan on` and `/plan off` name the posture; anything else after the verb is
        // refused rather than guessed at, because "off" and "of" must not mean the same
        // thing when one of them turns a session's write access back on.
        if let Some(argument) = slash_arg(trimmed, "/plan") {
            match argument.to_ascii_lowercase().as_str() {
                // `slash_arg` answers the bare verb with an empty argument, which is the
                // toggle. (`/plans` does not reach here: it needs a space after `/plan`.)
                "" => self.configure_plan(None),
                "on" => self.configure_plan(Some(true)),
                "off" => self.configure_plan(Some(false)),
                other => self.inform(
                    format!("/plan takes on or off, not {other:?}; bare /plan toggles"),
                    NoticeKind::Info,
                ),
            }
            return true;
        }

        // The same `on`/`off`/toggle grammar as `/plan`, for the same reason: a verb that
        // turns every safety question into a yes must not guess what "of" meant.
        if let Some(argument) = slash_arg(trimmed, "/auto-approve") {
            match argument.to_ascii_lowercase().as_str() {
                "" => self.set_auto_approve(None),
                "on" => self.set_auto_approve(Some(true)),
                "off" => self.set_auto_approve(Some(false)),
                other => self.inform(
                    format!(
                        "/auto-approve takes on or off, not {other:?}; bare /auto-approve toggles"
                    ),
                    NoticeKind::Info,
                ),
            }
            return true;
        }

        let command = match trimmed {
            "/new" => Some(Command::NewSession),
            "/switch" | "/sessions" => Some(Command::SwitchSession),
            "/details" => Some(Command::SessionDetails),
            "/diff" | "/changes" => Some(Command::ShowDiff),
            "/raw" => Some(Command::RawMode),
            "/copy" => Some(Command::CopyLast),
            "/interrupt" => Some(Command::Interrupt),
            "/steer" => Some(Command::Steer),
            "/backtrack" => Some(Command::Backtrack),
            "/fork" => Some(Command::Fork),
            "/compact" => Some(Command::Compact),
            "/handoff" => Some(Command::Handoff),
            "/context" => Some(Command::Context),
            "/rewind" => Some(Command::Rewind),
            "/delegate" => Some(Command::Delegate),
            "/delegations" => Some(Command::Delegations),
            "/plan" => Some(Command::Plan),
            "/mcp" => Some(Command::Mcp),
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
            "/keys" | "/keymap" => Some(Command::Keys),
            "/cost" | "/usage" => Some(Command::Cost),
            "/quit" => {
                self.open_quit();
                return true;
            }
            // "clear this draft" means the draft: the chips and the per-turn effort are
            // part of what would have been sent, so they go with the words.
            "/clear" => {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.attachments.clear();
                    composer.reasoning_effort = None;
                    composer.attachment_refusal = None;
                }
                self.remember_composer_history();
                return true;
            }
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
        let (cancel, interrupt, quit) = (
            self.keymap.label(Action::Cancel),
            self.keymap.label(Action::Interrupt),
            self.keymap.label(Action::Quit),
        );
        self.inform(
            format!(
                "press {cancel} again to quit · {interrupt} aborts a running turn · \
                 {quit} opens the quit dialog"
            ),
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
                format!(
                    "{} or {} interrupts a running turn; {} opens the quit dialog",
                    self.keymap.label(Action::Interrupt),
                    self.keymap.label(Action::Cancel),
                    self.keymap.label(Action::Quit)
                ),
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
        self.sessions.auto_approve.remove(&key);
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
