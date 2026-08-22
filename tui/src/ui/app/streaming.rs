use super::*;

impl App {
    // ----- streaming -----------------------------------------------------------------

    pub(super) fn notification(&mut self, notification: Notification) {
        match notification.method.as_str() {
            "interactive.event" => self.event(Plane::Interactive, &notification.params),
            "coding.event" => self.event(Plane::Coding, &notification.params),
            "stream.lagged" => self.lagged(&notification.params),
            "stream.ended" => self.ended(&notification.params),
            // A notification a newer gateway invented. Counted in the notice line rather
            // than dropped in silence, because it is evidence of a version skew.
            other => self.inform(
                format!("the gateway sent a notification this build does not know: {other}"),
                NoticeKind::Warn,
            ),
        }
    }

    fn event(&mut self, plane: Plane, params: &Value) {
        let Some(id) = params.get("id").and_then(Value::as_str) else {
            return;
        };

        if self.sessions.owner_conflict(plane, id).is_some() {
            self.cursors.forget(plane, id);
            return;
        }

        let key = (plane, id.to_string());
        let owner = self.session_route_node(plane, id).map(str::to_string);

        if !self.sessions.watches.contains_key(&key) {
            // An event for a session this client stopped watching. The gateway drops the
            // registration on unsubscribe, so this is the one frame that can cross it.
            return;
        }

        let Some(event) = params.get("event") else {
            return;
        };

        match Event::decode(event) {
            Ok(event) => {
                let approval = matches!(event.kind, EventType::ApprovalRequested);
                let acknowledges_reply = Self::event_acknowledges_reply_request(&event);
                let Some(watch) = self.sessions.watches.get_mut(&key) else {
                    return;
                };
                watch.absorb(vec![event]);

                let cursor = watch.cursor();
                let gap = watch.has_gap();

                if acknowledges_reply {
                    self.sessions.clear_reply_pending(plane, id);
                }

                self.cursors.set(plane, id, cursor, owner.as_deref());

                // A hole in the live stream that no `stream.lagged` explained: this side
                // lost frames, and the repair is the same one.
                if gap {
                    self.resync(plane, id.to_string(), false);
                }

                if approval {
                    self.open_approval(plane, id.to_string());
                }
            }
            Err(_undecodable) => {
                if let Some(watch) = self.sessions.watches.get_mut(&key) {
                    watch.undecodable += 1;
                }
            }
        }
    }

    fn lagged(&mut self, params: &Value) {
        let Ok(lagged) = serde_json::from_value::<model::Lagged>(params.clone()) else {
            return;
        };

        let Some((plane, key)) = self.locate(lagged.plane(), &lagged.id) else {
            return;
        };

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.dropped += lagged.dropped;
            watch.note(
                Note::Lagged {
                    dropped: lagged.dropped,
                },
                lagged.last_sequence,
            );
        }

        self.sessions.rounds.remove(&key);
        self.inform(
            format!(
                "the gateway dropped {} event frames for {}; replaying from {}",
                lagged.dropped,
                lagged.id,
                self.sessions
                    .watches
                    .get(&key)
                    .map(Watch::cursor)
                    .unwrap_or(0)
            ),
            NoticeKind::Warn,
        );

        self.resync(plane, lagged.id, false);
    }

    fn ended(&mut self, params: &Value) {
        let Ok(ended) = serde_json::from_value::<model::Ended>(params.clone()) else {
            return;
        };

        let Some((plane, key)) = self.locate(ended.plane(), &ended.id) else {
            return;
        };

        self.sessions
            .remember_owner(plane, &ended.id, params.get("node").and_then(Value::as_str));

        // `unknown` means the coordinator disappeared, not that the provider session
        // reached a terminal state. A remote BEAM node may keep running and return after
        // the network heals, so retain the cursor and wait for fleet status to report its
        // owner connected before resubscribing.
        if ended.status == "unknown" && self.session_route_node(plane, &ended.id).is_some() {
            self.wait_for_remote_owner(plane, &ended.id);
            self.inform(
                format!(
                    "{} became unreachable; its cursor is safe and Ouroboros will resubscribe when the machine reconnects",
                    ended.id
                ),
                NoticeKind::Warn,
            );
            return;
        }

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.end(ended.status.clone());
        }

        self.sessions.recovering.remove(&key);
        self.sessions.clear_reply_pending(plane, &ended.id);

        self.cursors.forget(plane, &ended.id);
    }

    /// Retains a remote stream exactly where it stopped and waits for live fleet status
    /// before trying to subscribe again. This is shared by `stream.ended status=unknown`
    /// and by the reconnect hook: after the local gateway reconnects, the hook can be the
    /// first caller to discover that this particular owner is still offline.
    fn wait_for_remote_owner(&mut self, plane: Plane, id: &str) {
        let key = (plane, id.to_string());

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.ended = None;
            watch.resyncing = false;
            watch.resync_again = false;
        }

        self.sessions.rounds.remove(&key);
        self.sessions
            .recovering
            .entry(key)
            .or_insert(SessionRecovery {
                attempts: 0,
                next_tick: self.ticks,
            });
        self.sessions.clear_reply_pending(plane, id);
        self.status.invalidate();
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
    }

    /// Whether a failed remote subscribe says only that the owner cannot be reached yet.
    /// Typed RPC data is preferred; transport loss is necessarily outcome-unknown. Bad
    /// frames and a stopped client are deterministic local failures and must not create a
    /// background retry loop.
    fn resync_waits_for_remote_owner(error: &ClientError) -> bool {
        match error {
            ClientError::Rpc(rpc) => {
                rpc.data
                    .as_ref()
                    .and_then(|data| data.get("reason"))
                    .and_then(Value::as_str)
                    == Some("owner_unavailable")
            }
            ClientError::ConnectionClosed | ClientError::Timeout | ClientError::Io(_) => true,
            ClientError::FrameTooLarge { .. }
            | ClientError::BadJson(_)
            | ClientError::Stopped(_) => false,
        }
    }

    pub(super) fn recover_remote_sessions(&mut self) {
        let Some(status) = self.status.value.as_ref() else {
            return;
        };
        let connected_nodes: HashSet<&str> =
            status.connected_nodes.iter().map(String::as_str).collect();
        let fleet_machines = status
            .cluster
            .get("fleet")
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array);

        let due = self
            .sessions
            .recovering
            .iter()
            .filter_map(|(key @ (plane, id), recovery)| {
                if self.ticks < recovery.next_tick {
                    return None;
                }
                let owner = self.session_route_node(*plane, id)?;
                let connected = connected_nodes.contains(owner)
                    || fleet_machines.is_some_and(|machines| {
                        machines.iter().any(|machine| {
                            machine.get("node").and_then(Value::as_str) == Some(owner)
                                && matches!(
                                    machine.get("state").and_then(Value::as_str),
                                    Some("connected" | "local")
                                )
                        })
                    });
                connected.then(|| key.clone())
            })
            .collect::<Vec<_>>();

        for (plane, id) in due {
            let Some(recovery) = self.sessions.recovering.get_mut(&(plane, id.clone())) else {
                continue;
            };
            recovery.attempts = recovery.attempts.saturating_add(1);
            let shift = recovery.attempts.saturating_sub(1).min(5);
            let delay = 13_u64.checked_shl(shift).unwrap_or(375).min(375);
            recovery.next_tick = self.ticks.saturating_add(delay);
            self.sessions.rounds.remove(&(plane, id.clone()));
            self.resync(plane, id, true);
        }
    }

    /// A notification the transport could not hand over is indistinguishable from a lag,
    /// except that this side lost it. Every watched session is resynced, because the
    /// counter does not say which one the frame belonged to.
    pub(super) fn client_dropped(&mut self, total: u64) {
        if total <= self.dropped_seen {
            return;
        }

        let lost = total - self.dropped_seen;
        self.dropped_seen = total;

        self.note_all_watches(Note::ClientDropped);

        for watch in self.sessions.watches.values_mut() {
            watch.dropped += lost;
        }

        self.inform(
            format!(
                "this client could not take {lost} event frames; replaying every watched session"
            ),
            NoticeKind::Warn,
        );

        let keys: Vec<(Plane, String)> = self.sessions.watches.keys().cloned().collect();

        for (plane, id) in keys {
            self.sessions.rounds.remove(&(plane, id.clone()));
            self.resync(plane, id, false);
        }
    }

    pub(super) fn note_all_watches(&mut self, note: Note) {
        for watch in self.sessions.watches.values_mut() {
            let at = watch.newest();
            watch.note(note.clone(), at);
        }
    }

    /// The one repair. `subscribe` is true when the registration is gone (a first open, or
    /// a reconnect) and false when only frames were lost.
    fn resync(&mut self, plane: Plane, id: String, subscribe: bool) {
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let key = (plane, id.clone());

        let Some(watch) = self.sessions.watches.get_mut(&key) else {
            return;
        };

        if watch.ended.is_some() && !subscribe {
            return;
        }

        if watch.resyncing {
            // A second interruption while the first repair is in flight. The answer on
            // its way was asked from a cursor that predates this one, so it cannot repair
            // it — the request is remembered rather than dropped.
            watch.resync_again = true;
            return;
        }

        let rounds = self.sessions.rounds.entry(key.clone()).or_insert(0);
        *rounds += 1;

        if *rounds > MAX_RESYNC_ROUNDS {
            self.inform(
                format!(
                    "{id} is producing history faster than this client can replay it; the \
                     transcript keeps its gap rather than looping"
                ),
                NoticeKind::Error,
            );

            return;
        }

        watch.resyncing = true;
        let cursor = watch.cursor();

        let (verb, params) = if subscribe {
            ("subscribe", json!({ "id": id, "cursor": cursor }))
        } else {
            (
                "replay",
                json!({ "id": id, "cursor": cursor, "limit": REPLAY_LIMIT }),
            )
        };
        let params = self.routed_session_params(plane, &id, params);

        self.issue(Call::new(
            Tag::Resync {
                plane,
                id: id.clone(),
                cursor,
                subscribe,
            },
            plane.method(verb),
            params,
        ));
    }

    pub(super) fn resync_answered(
        &mut self,
        plane: Plane,
        id: String,
        asked_from: u64,
        subscribe: bool,
        result: Result<Value, ClientError>,
    ) {
        let key = (plane, id.clone());
        if self.sessions.owner_conflict(plane, &id).is_some() {
            if let Some(watch) = self.sessions.watches.get_mut(&key) {
                watch.resyncing = false;
                watch.resync_again = false;
            }
            self.cursors.forget(plane, &id);
            return;
        }

        let owner = self.session_route_node(plane, &id).map(str::to_string);
        let recovering = subscribe && self.sessions.recovering.contains_key(&key);

        let Some(watch) = self.sessions.watches.get_mut(&key) else {
            return;
        };

        watch.resyncing = false;

        match result {
            Ok(value) => {
                let (events, refused) = Event::decode_batch(&value);
                let batch = events.len() as u64;
                let approvals = events
                    .iter()
                    .any(|event| matches!(event.kind, EventType::ApprovalRequested));
                let acknowledges_reply = events.iter().any(Self::event_acknowledges_reply_request);

                // Both verbs answer "the retained events after this cursor, in order". A
                // first entry above `cursor + 1` therefore *proves* the ones between are
                // no longer retained — a prune the gateway had no reason to raise, since
                // the cursor itself was still inside the window. Raising the floor here
                // is what stops the transcript showing a hole that will never fill.
                if let Some(first) = events.first().map(|event| event.sequence) {
                    if first > asked_from + 1 {
                        watch.raise_floor(first - 1);
                    }
                }

                watch.undecodable += refused;
                let before = watch.cursor();
                watch.absorb(events);

                let cursor = watch.cursor();
                let progressed = cursor > before;
                let more = batch >= REPLAY_LIMIT || watch.has_gap();
                let again = std::mem::take(&mut watch.resync_again);

                if recovering {
                    watch.ended = None;
                    watch.note(Note::Reconnected, cursor);
                }

                if acknowledges_reply {
                    self.sessions.clear_reply_pending(plane, &id);
                }

                self.cursors.set(plane, &id, cursor, owner.as_deref());

                if recovering {
                    self.sessions.recovering.remove(&key);
                    self.inform(
                        format!("{id} reconnected and resumed from cursor {cursor}"),
                        NoticeKind::Info,
                    );
                }

                // Another round while it is buying something, or because an interruption
                // arrived while this one was in flight. A replay that answered nothing new
                // and had no second cause leaves the gap visible instead of asking again
                // forever.
                if (progressed && more) || again {
                    self.resync(plane, id.clone(), false);
                } else {
                    self.sessions.rounds.remove(&key);
                }

                if approvals {
                    self.open_approval(plane, id);
                }
            }
            Err(error)
                if subscribe && owner.is_some() && Self::resync_waits_for_remote_owner(&error) =>
            {
                watch.resync_again = false;
                self.wait_for_remote_owner(plane, &id);
                self.inform(
                    format!(
                        "{id}'s machine is still unreachable; its cursor is safe and Ouroboros will retry after it reconnects ({error})"
                    ),
                    NoticeKind::Warn,
                );
            }
            Err(ClientError::Rpc(rpc)) => {
                match CursorPruned::from_error_data(rpc.data.as_ref()) {
                    Some(pruned) => {
                        watch.raise_floor(pruned.floor);
                        watch.resync_again = false;
                        let cursor = watch.cursor();
                        self.cursors.set(plane, &id, cursor, owner.as_deref());

                        self.inform(
                            format!(
                                "{id}: the runtime no longer retains history below {}; the \
                                 transcript starts there",
                                pruned.floor
                            ),
                            NoticeKind::Warn,
                        );

                        // Restart from the floor through the same path, which is why the
                        // prune arm is three lines rather than a second implementation.
                        self.resync(plane, id, subscribe);
                    }
                    None => {
                        watch.resync_again = false;
                        self.sessions.rounds.remove(&key);
                        self.inform(format!("replaying {id} failed: {rpc}"), NoticeKind::Error);
                    }
                }
            }
            Err(other) => {
                watch.resync_again = false;
                self.sessions.rounds.remove(&key);
                self.inform(format!("replaying {id} failed: {other}"), NoticeKind::Error);
            }
        }
    }

    /// Which watched session a stream notification is about. The plane is on the wire, but
    /// an id this client is watching on exactly one plane is answerable without it.
    fn locate(&self, plane: Option<Plane>, id: &str) -> Option<(Plane, (Plane, String))> {
        if let Some(plane) = plane {
            let key = (plane, id.to_string());

            if self.sessions.watches.contains_key(&key) {
                return Some((plane, key));
            }
        }

        self.sessions
            .watches
            .keys()
            .find(|(_plane, watched)| watched == id)
            .map(|key| (key.0, key.clone()))
    }

    /// Opens (or re-opens) a session: one watch, one subscribe, and the cursor registered
    /// where the reconnect hook can find it.
    pub fn open_session(&mut self, plane: Plane, id: String) {
        let owner = self.sessions.owner_node(plane, &id).map(str::to_string);
        self.open_session_on(plane, id, owner);
    }

    /// Opens a returned fleet reference before the next list poll has had a chance to
    /// report it. Callers that only have a local id use [`open_session`](Self::open_session).
    pub fn open_session_on(&mut self, plane: Plane, id: String, node: Option<String>) {
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        self.sessions.remember_owner(plane, &id, node.as_deref());
        let key = (plane, id.clone());
        let switching = self.sessions.open.as_ref() != Some(&key);

        if switching {
            self.remember_composer_history();
            self.sessions.composer = None;
        }

        self.sessions
            .watches
            .entry(key.clone())
            .or_insert_with(|| Watch::new(plane, id.clone()));

        self.sessions.open = Some(key.clone());
        self.tab = Tab::Sessions;

        if plane == Plane::Interactive {
            if self.sessions.composer.is_none() {
                self.compose(ComposerVerb::Message);
            }
        } else {
            self.sessions.composer = None;
        }

        let cursor = self
            .sessions
            .watches
            .get(&key)
            .map(Watch::cursor)
            .unwrap_or(0);

        let owner = self.session_route_node(plane, &id);
        self.cursors.set(plane, &id, cursor, owner);
        self.resync(plane, id, true);
    }

    /// Reissues an indeterminate initial message under its original logical turn id.
    ///
    /// This is the `ouro new -m` handoff after its pre-UI call lost a trustworthy answer.
    /// The runtime either accepts this as the first arrival when the original request
    /// never reached it, reports a turn whose dispatch is now known, or keeps a
    /// checkpointed uncertain dispatch outcome-unknown. It never redispatches that
    /// uncertain intent. [`Tag::FirstMessage`] keeps the draft and same id only while the
    /// outcome stays unknown; a definite refusal restores the draft with a fresh id.
    pub fn retry_first_message(&mut self, id: String, input: String, turn_id: String) {
        let plane = Plane::Interactive;
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let method = plane.method("send_message");
        if !self.hello.serves(&method) {
            self.restore_refused_first_message(plane, &id, input, ComposerVerb::Message);
            self.inform(
                format!("{id} is open, but this gateway no longer serves {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        let submission_sequence = self.next_composer_submission_sequence();
        self.restore_first_message(
            plane,
            &id,
            input.clone(),
            turn_id.clone(),
            submission_sequence,
        );

        self.sessions.mark_reply_pending(plane, &id);
        let params = self.routed_session_params(
            plane,
            &id,
            json!({ "id": id, "input": input, "turn_id": turn_id }),
        );
        self.issue(Call::new(
            Tag::FirstMessage {
                plane,
                id: id.clone(),
                turn_id: turn_id.clone(),
                input: input.clone(),
                submission_sequence,
            },
            method,
            params,
        ));
    }

    /// Opens a known-created but failed `ouro new` handoff without dispatching its CLI
    /// message. Unlike reconciliation, the gateway has already proved the start outcome:
    /// the session exists and readiness failed before this draft was sent.
    pub fn restore_created_start_failure(
        &mut self,
        plane: Plane,
        id: &str,
        input: Option<String>,
        notice: String,
    ) {
        if let Some(input) = input {
            self.restore_refused_first_message(plane, id, input, ComposerVerb::Message);
        }
        self.inform(notice, NoticeKind::Error);
    }

    /// Marks the successful pre-UI `ouro new -m` turn so the next typed request queues
    /// behind it instead of attempting a second immediate Harness message.
    pub fn continue_after_first_message(&mut self, id: &str) {
        if self.sessions.open.as_ref() != Some(&(Plane::Interactive, id.to_string())) {
            return;
        }

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.verb = ComposerVerb::FollowUp;
        }
    }

    pub(super) fn open_approval(&mut self, plane: Plane, id: String) {
        // An approval modal must not steal the terminal from a dialog already open.
        if self.overlay.is_some() {
            return;
        }

        self.open_approval_with(plane, id, String::new(), 0, None);
    }

    /// Opens (or reopens after a reason prompt) the chooser for the watch's pending
    /// approval. The request is peeked afresh so the subject is always the live one;
    /// `request_id` must still be pending, or nothing opens.
    pub(super) fn open_approval_with(
        &mut self,
        plane: Plane,
        id: String,
        request_id: String,
        choice: usize,
        reason: Option<String>,
    ) {
        let Some(watch) = self.sessions.watches.get(&(plane, id.clone())) else {
            return;
        };

        let Some(request) = watch.next_approval() else {
            return;
        };

        let request_id = if request.request_id == request_id {
            request_id
        } else {
            request.request_id.clone()
        };

        let subject = request.subject();
        let detail = request.detail();
        let (rule, rule_absent) = self.approval_rule(plane, &id, detail.suggested_rule.as_deref());

        // The reason prompt reopens this modal, and the fifth row may not exist the second
        // time — a rule can stop being offerable between the two, and a cursor left past
        // the last row would answer something the reader never selected.
        let rows = APPROVAL_CHOICES.len() + usize::from(rule.is_some());

        self.overlay = Some(Overlay::Approval {
            plane,
            id,
            request_id,
            subject,
            choice: choice.min(rows - 1),
            reason,
            detail: Box::new(detail),
            rule,
            rule_absent,
            expanded: false,
        });
    }

    /// The rule the modal's fifth answer would write, or the reason there is no fifth
    /// answer.
    ///
    /// Three things have to be true at once, and each failure is named rather than
    /// swallowed: the runtime must have suggested a pattern (only `Control.Permissions`
    /// knows the rule language, and this client never invents one), this gateway must
    /// serve `permissions.add` (an older one does not, and the answer is then absent
    /// rather than broken), and the session must name the workspace the rule is scoped to
    /// — `permissions.add` refuses a `workspace` rule without one, and picking `user`
    /// scope instead would quietly write a broader rule than the operator was shown.
    fn approval_rule(
        &self,
        plane: Plane,
        id: &str,
        suggested: Option<&str>,
    ) -> (Option<ApprovalRule>, Option<&'static str>) {
        let Some(pattern) = suggested else {
            return (None, None);
        };

        if !self.hello.serves("permissions.add") {
            return (
                None,
                Some("this runtime does not serve permissions.add, so the rule cannot be saved"),
            );
        }

        let workspace = self
            .sessions
            .session(plane, id)
            .and_then(|session| session.workspace.clone())
            .map(|workspace| workspace.trim().to_string())
            .filter(|workspace| !workspace.is_empty());

        match workspace {
            Some(workspace) => (
                Some(ApprovalRule {
                    pattern: pattern.to_string(),
                    workspace,
                }),
                None,
            ),
            None => (
                None,
                Some("this session names no workspace, so there is no scope to save the rule in"),
            ),
        }
    }
}
