use super::*;

impl App {
    // ----- answers -------------------------------------------------------------------

    pub(super) fn answer(&mut self, tag: Tag, result: Result<Value, ClientError>) {
        self.in_flight.remove(&tag);

        if let Err(error) = &result {
            if matches!(
                error,
                ClientError::ConnectionClosed | ClientError::Stopped(_)
            ) {
                self.connection = Connection::Lost {
                    reason: error.to_string(),
                };
            }
        }

        let ticks = self.ticks;

        match tag {
            Tag::Account => match result {
                Ok(value) => match AccountState::decode(&value) {
                    Ok(account) => {
                        let connected = account.connected();
                        let cadence = if account.login.status == "pending" {
                            ACCOUNT_LOGIN_TICKS
                        } else {
                            ACCOUNT_TICKS
                        };

                        self.account.ok(account, ticks, cadence);

                        if connected {
                            if self.config.defaults.provider.is_none() {
                                self.config.defaults.provider = Some("native".to_string());
                                self.config.defaults.model =
                                    Some("openai_codex:gpt-5.6-sol".to_string());
                                self.save_pending = true;
                            }

                            if matches!(self.overlay, Some(Overlay::Account(_))) {
                                self.overlay = None;
                                self.inform(
                                    "ChatGPT is connected. Type a request to start coding.",
                                    NoticeKind::Info,
                                );
                            }
                        } else if let Some(Overlay::Account(dialog)) = self.overlay.as_mut() {
                            if let Some(account) = self.account.value.as_ref() {
                                dialog.login_id = account.login.login_id.clone();
                                if account.login.status == "failed" {
                                    dialog.pending = false;
                                    dialog.error = account.login.error.clone().or_else(|| {
                                        Some("ChatGPT sign-in did not complete".to_string())
                                    });
                                }
                            }
                        }
                    }
                    Err(error) => self.account.failed(
                        format!("account.read did not decode: {error}"),
                        ticks,
                        ACCOUNT_TICKS,
                    ),
                },
                Err(error) => self.account.failed(error.to_string(), ticks, ACCOUNT_TICKS),
            },
            Tag::AccountLogin => self.account_login_answered(result),
            Tag::AccountCancel => {
                self.account.invalidate();
                self.poll();

                if let Err(error) = result {
                    self.inform(
                        format!("cancelling ChatGPT sign-in failed: {error}"),
                        NoticeKind::Error,
                    );
                }
            }
            Tag::AccountLogout => {
                self.account.invalidate();
                self.poll();

                match result {
                    Ok(_) => self.inform("ChatGPT was disconnected", NoticeKind::Info),
                    Err(error) => self.inform(
                        format!("disconnecting ChatGPT failed: {error}"),
                        NoticeKind::Error,
                    ),
                }
            }
            Tag::Status => match result {
                Ok(value) => match RuntimeStatus::decode(&value) {
                    Ok(status) => {
                        self.status.ok(status, ticks, STATUS_TICKS);
                        self.recover_remote_sessions();
                    }
                    Err(error) => self.status.failed(
                        format!("runtime.status did not decode: {error}"),
                        ticks,
                        STATUS_TICKS,
                    ),
                },
                Err(error) => self.status.failed(error.to_string(), ticks, STATUS_TICKS),
            },
            Tag::Providers => match result {
                Ok(value) => {
                    let providers = ProviderEntry::decode_list(&value);
                    self.providers.ok(providers, ticks, PROVIDER_TICKS);
                    // A dialog opened before the list arrived has a default it could not
                    // point at yet. This is the moment it can.
                    self.place_default_provider();
                }
                Err(error) => self
                    .providers
                    .failed(error.to_string(), ticks, PROVIDER_TICKS),
            },
            Tag::Models => match result {
                Ok(value) => match ModelsCatalog::decode(&value) {
                    Ok(catalogue) => self.models.ok(catalogue, ticks, MODEL_TICKS),
                    Err(error) => self.models.failed(
                        format!("runtime.models did not decode: {error}"),
                        ticks,
                        MODEL_TICKS,
                    ),
                },
                // Including the `-32601` a gateway that does not serve the verb answers
                // with. A picker reading this shows the refusal rather than an empty list.
                Err(error) => self.models.failed(error.to_string(), ticks, MODEL_TICKS),
            },
            Tag::Sessions(plane) => match result {
                Ok(value) => {
                    let sessions = self.retain_offline_session_rows(
                        plane,
                        SessionInfo::decode_list(plane, &value),
                    );
                    let conflicts = self.sessions.remember_list_owners(plane, &sessions);
                    for (id, owners) in conflicts {
                        self.cursors.forget(plane, &id);
                        self.inform(
                            format!(
                                "session ID {id} is reported by {}; Ouroboros will not open or route it. Explicit IDs must be fleet-unique (generated IDs already are); stop or restart one duplicate with a unique ID, then reconnect this TUI",
                                owners.join(" and ")
                            ),
                            NoticeKind::Error,
                        );
                    }
                    let panel = match plane {
                        Plane::Interactive => &mut self.sessions.interactive,
                        Plane::Coding => &mut self.sessions.coding,
                    };
                    panel.ok(sessions, ticks, LIST_TICKS)
                }
                Err(error) => {
                    let panel = match plane {
                        Plane::Interactive => &mut self.sessions.interactive,
                        Plane::Coding => &mut self.sessions.coding,
                    };
                    panel.failed(error.to_string(), ticks, LIST_TICKS)
                }
            },
            Tag::Agents => Self::fill_rows(&mut self.agents, result, ticks, project_agent),
            Tag::Teams => Self::fill_rows(&mut self.teams, result, ticks, project_team),
            Tag::Plans => Self::fill_rows(&mut self.plans, result, ticks, project_plan),
            Tag::ControlRuns => Self::fill_rows(&mut self.control, result, ticks, project_run),
            Tag::AgentState(_) => Self::fill_detail(&mut self.agents, result, ticks),
            Tag::TeamState(_) => Self::fill_detail(&mut self.teams, result, ticks),
            Tag::Plan(_) => Self::fill_detail(&mut self.plans, result, ticks),
            Tag::ControlRun(_) => Self::fill_detail(&mut self.control, result, ticks),
            Tag::UpgradeStatus => {
                Self::fill_value(&mut self.upgrade.status, result, ticks, UPGRADE_TICKS)
            }
            Tag::Rollouts => {
                Self::fill_value(&mut self.upgrade.rollouts, result, ticks, UPGRADE_TICKS)
            }
            Tag::History(_) => {
                Self::fill_value(&mut self.upgrade.history, result, ticks, UPGRADE_TICKS)
            }
            Tag::Signing => {
                Self::fill_value(&mut self.upgrade.signing, result, ticks, UPGRADE_TICKS)
            }
            Tag::Grants(_) => {
                Self::fill_value(&mut self.upgrade.grants, result, ticks, UPGRADE_TICKS)
            }
            Tag::Resync {
                plane,
                id,
                cursor,
                subscribe,
            } => self.resync_answered(plane, id, cursor, subscribe, result),
            Tag::ComposerAction {
                label,
                verb,
                plane,
                id,
                turn_id,
                input,
                reconciling,
                submission_sequence,
            } => match result {
                Ok(value) => match model::turn_reply(&value) {
                    model::TurnReply::Accepted => {
                        if reconciling {
                            if let Some(turn_id) = turn_id.as_deref() {
                                self.accept_reconciled_composer_draft(plane, &id, turn_id);
                            }
                            self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                        }
                        self.inform(format!("{label} accepted for {id}"), NoticeKind::Info);
                    }
                    model::TurnReply::OutcomeUnknown => {
                        // Current runtimes return these states as typed RPC errors. Keep
                        // this branch for a same-id read from an older runtime: it is still
                        // not proof that the turn was accepted.
                        let retry_turn_id = if verb == ComposerVerb::Steer {
                            None
                        } else {
                            turn_id
                        };
                        let reconciliation_id = retry_turn_id.clone();
                        let disposition = self.restore_composer_submission(
                            plane,
                            &id,
                            input,
                            retry_turn_id,
                            verb,
                            submission_sequence,
                        );
                        if verb == ComposerVerb::Steer {
                            self.steer_delivery_unconfirmed(&id, disposition);
                        } else if disposition.reconciliation_deferred() {
                            self.inform(
                                format!(
                                    "{label} on {id}: {}; saved outcome-unknown turn {} without \
                                     overwriting the session draft. Open {id}; Enter reconciles \
                                     it before newer input",
                                    model::turn_reply_diagnostic(&value),
                                    reconciliation_id.as_deref().unwrap_or("unknown")
                                ),
                                NoticeKind::Error,
                            );
                        } else {
                            self.inform(
                                format!(
                                    "{label} on {id}: {}; the exact draft and turn id were \
                                     restored",
                                    model::turn_reply_diagnostic(&value)
                                ),
                                NoticeKind::Error,
                            );
                        }
                    }
                    model::TurnReply::Rejected => {
                        if reconciling {
                            self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                            if let Some(turn_id) = turn_id.as_deref() {
                                self.release_reconciliation_draft(plane, &id, turn_id);
                            }
                        }
                        if matches!(verb, ComposerVerb::Message | ComposerVerb::FollowUp) {
                            self.sessions.clear_reply_pending(plane, &id);
                        }

                        let retry_verb =
                            if verb == ComposerVerb::Message && model::turn_reply_busy(&value) {
                                ComposerVerb::FollowUp
                            } else {
                                verb
                            };

                        // This id is durably terminal. Preserve the exact input but mint a
                        // fresh logical turn if the operator deliberately retries it.
                        self.restore_composer_submission(
                            plane,
                            &id,
                            input,
                            None,
                            retry_verb,
                            submission_sequence,
                        );
                        self.inform(
                            format!("{label} on {id}: {}", model::turn_reply_diagnostic(&value)),
                            NoticeKind::Error,
                        );
                    }
                },
                Err(error) => {
                    let outcome_unknown = Self::reply_outcome_unknown(&error);
                    let busy = matches!(
                        &error,
                        ClientError::Rpc(rpc) if model::turn_busy(rpc.data.as_ref())
                    );

                    if reconciling && !outcome_unknown {
                        self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                        if let Some(turn_id) = turn_id.as_deref() {
                            self.release_reconciliation_draft(plane, &id, turn_id);
                        }
                    }

                    if matches!(label, "send_message" | "follow_up") && !outcome_unknown {
                        self.sessions.clear_reply_pending(plane, &id);
                    }

                    // Only dispatched turns have a caller-owned reconciliation id. A
                    // definite refusal mints a fresh one; steer has no idempotency at all.
                    let retry_turn_id = if outcome_unknown && verb != ComposerVerb::Steer {
                        turn_id
                    } else {
                        None
                    };
                    let retry_verb = if busy && verb == ComposerVerb::Message {
                        ComposerVerb::FollowUp
                    } else {
                        verb
                    };

                    let reconciliation_id = retry_turn_id.clone();
                    let disposition = self.restore_composer_submission(
                        plane,
                        &id,
                        input,
                        retry_turn_id,
                        retry_verb,
                        submission_sequence,
                    );
                    if outcome_unknown && verb == ComposerVerb::Steer {
                        self.steer_delivery_unconfirmed(&id, disposition);
                    } else if disposition.reconciliation_deferred() {
                        let diagnostic = match &error {
                            ClientError::Rpc(rpc) => model::refusal(rpc),
                            other => other.to_string(),
                        };
                        self.inform(
                            format!(
                                "{label} on {id}: {diagnostic}; saved outcome-unknown turn {} \
                                 without overwriting the session draft. Open {id}; Enter \
                                 reconciles it before newer input",
                                reconciliation_id.as_deref().unwrap_or("unknown")
                            ),
                            NoticeKind::Error,
                        );
                    } else {
                        self.action_failed(label, plane, &id, error);
                    }
                }
            },
            // D9/D6/B7/G1. Each of these answers with something to *draw* rather than
            // an acknowledgement to acknowledge, which is why none of them is a
            // `Tag::Action`. The refusals branch first on the two native-only shapes so a
            // capability answer and a liveness one do not read the same.
            Tag::Compact { plane, id } => match result {
                Ok(value) => self.compacted(plane, &id, &value),
                Err(error) => self.native_verb_failed("compact", &id, error),
            },
            Tag::Handoff {
                plane: _,
                id,
                child,
            } => match result {
                Ok(value) => self.handed_off(&id, &child, &value),
                Err(error) => self.native_verb_failed("handoff", &id, error),
            },
            Tag::Context { plane, id, show } => match result {
                Ok(value) => self.context_read(plane, &id, show, &value),
                // A background refresh says nothing: it was not asked for, and a notice
                // about a meter nobody was looking at is noise.
                Err(error) if show => self.native_verb_failed("context", &id, error),
                Err(_quiet) => {}
            },
            Tag::RewindPoints { plane, id } => match result {
                Ok(value) => self.rewind_points_read(plane, &id, &value),
                Err(error) => self.native_verb_failed("rewind", &id, error),
            },
            Tag::Rewind {
                plane,
                id,
                label,
                what,
            } => match result {
                Ok(value) => self.rewound(plane, &id, &label, what, &value),
                Err(error) => self.native_verb_failed("rewind", &id, error),
            },
            Tag::Shell { plane, id, command } => match result {
                Ok(value) => self.shell_finished(plane, &id, &command, &value),
                Err(error) => self.shell_refused(&error),
            },
            Tag::Delegate { plane: _, id } => {
                self.delegating = false;

                match result {
                    Ok(value) => self.delegated(&value),
                    Err(error) => self.action_failed("delegate", Plane::Interactive, &id, error),
                }
            }
            Tag::Delegations { plane, id, show } => match result {
                Ok(value) => self.delegations_read(plane, &id, show, &value),
                Err(error) if show => self.action_failed("delegations", plane, &id, error),
                Err(_quiet) => {}
            },
            Tag::Artifact { sha } => {
                if let Ok(value) = result {
                    if let Ok(bytes) = model::decode_artifact(&value, &sha) {
                        self.desktop_artifacts.insert(sha, Arc::new(bytes));
                    }
                }
            }
            Tag::Action {
                label, plane, id, ..
            } => match result {
                Ok(value) if matches!(label, "preview" | "admit" | "list capabilities") => {
                    self.capability_answered(label, &id, value)
                }
                Ok(_) if label == "remove" => self.session_removed(plane, &id),
                Err(error) if label == "remove" && error.code() == Some(ErrorCode::NotFound) => {
                    self.session_removed(plane, &id)
                }
                Ok(_value) => {
                    self.inform(format!("{label} accepted for {id}"), NoticeKind::Info);
                    self.refresh_session_lists();
                    self.resume_picker_if_requested();
                }
                Err(error) => {
                    if matches!(label, "send_message" | "follow_up")
                        && !Self::reply_outcome_unknown(&error)
                    {
                        self.sessions.clear_reply_pending(plane, &id);
                    }
                    self.action_failed(label, plane, &id, error);
                    self.resume_picker_if_requested();
                }
            },
            Tag::ControlSubmit => match result {
                Ok(value) => {
                    let id = value
                        .get("id")
                        .map(model::compact)
                        .unwrap_or_else(|| "unknown".to_string());
                    self.inform(format!("control run {id} submitted"), NoticeKind::Info);
                    self.control.rows.invalidate();
                    self.control.detail.invalidate();
                }
                Err(ClientError::Rpc(rpc)) => self.inform(
                    format!("control submit was refused: {}", model::refusal(&rpc)),
                    NoticeKind::Error,
                ),
                Err(error) => self.inform(
                    format!("control submit was refused: {error}"),
                    NoticeKind::Error,
                ),
            },
            Tag::ControlCancel(id) => match result {
                Ok(_) => {
                    self.inform(
                        format!("cancel accepted for control run {id}"),
                        NoticeKind::Info,
                    );
                    self.control.rows.invalidate();
                    self.control.detail.invalidate();
                }
                Err(ClientError::Rpc(rpc)) => self.inform(
                    format!(
                        "cancel of control run {id} was refused: {}",
                        model::refusal(&rpc)
                    ),
                    NoticeKind::Error,
                ),
                Err(error) => self.inform(
                    format!("cancel of control run {id} was refused: {error}"),
                    NoticeKind::Error,
                ),
            },
            Tag::EventDetail {
                plane,
                id,
                sequence,
            } => self.event_detail_answered(plane, &id, sequence, result),
            // The approval it accompanies was already sent and is reported separately.
            // A rule that failed to save is not a failed approval, and saying so in the
            // same sentence would make the operator re-answer a question that was answered.
            Tag::PermissionRule { pattern } => match result {
                Ok(_value) => self.inform(
                    format!("saved the workspace rule {pattern} — this will not be asked again"),
                    NoticeKind::Info,
                ),
                Err(ClientError::Rpc(rpc)) => self.inform(
                    format!(
                        "the approval was sent; the rule {pattern} was not saved: {}",
                        model::refusal(&rpc)
                    ),
                    NoticeKind::Error,
                ),
                Err(error) => self.inform(
                    format!("the approval was sent; the rule {pattern} was not saved: {error}"),
                    NoticeKind::Error,
                ),
            },
            Tag::Approval {
                plane,
                id,
                request_id,
            } => match result {
                Ok(_value) => self.inform(
                    format!("approval response accepted for {id}"),
                    NoticeKind::Info,
                ),
                Err(error) => {
                    if let Some(watch) = self.sessions.watches.get_mut(&(plane, id.clone())) {
                        watch.retry_approval_response(&request_id);
                    }
                    self.action_failed("respond_approval", plane, &id, error);
                }
            },
            // B2. The same answer, sent with an explicit `provider_options.choice`. The
            // one extra outcome is a gateway that does not admit that key at all.
            Tag::PlanExit {
                plane,
                id,
                request_id,
                choice,
                had_follow_up,
            } => match result {
                Ok(_value) => self.inform(
                    format!("plan exit answered {} for {id}", choice.as_str()),
                    NoticeKind::Info,
                ),
                Err(error) => {
                    // Clear the in-flight mark first either way: the answer did not land,
                    // and a retry has to be able to mark it again.
                    if let Some(watch) = self.sessions.watches.get_mut(&(plane, id.clone())) {
                        watch.retry_approval_response(&request_id);
                    }

                    let refused_options = matches!(
                        &error,
                        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams
                    ) && !self.plan_options_refused;

                    if !refused_options {
                        self.action_failed("respond_approval", plane, &id, error);
                        return;
                    }

                    // Once, and said out loud. The fallback still reaches the same three
                    // answers — `PlanChoice::decision` is the mapping the runtime itself
                    // falls back to — so what is lost is the follow-up and nothing else.
                    self.plan_options_refused = true;
                    self.inform(
                        if had_follow_up {
                            "this gateway does not take a plan-exit choice; answering with \
                             approve/deny alone, which reaches the same three answers — the \
                             follow-up prompt was dropped, so send it as an ordinary message"
                                .to_string()
                        } else {
                            "this gateway does not take a plan-exit choice; answering with \
                             approve/deny alone, which reaches the same three answers"
                                .to_string()
                        },
                        NoticeKind::Warn,
                    );

                    self.submit_plan_exit(plane, id, request_id, choice, None);
                }
            },
            // B2. Success re-lists, exactly as `/model` does, so `options.plan` on the row
            // catches up with the event that already moved the badge.
            Tag::PlanMode { plane, id, want } => match result {
                Ok(_value) => {
                    self.inform(
                        if want {
                            format!("{id} is planning; it will not edit anything")
                        } else {
                            format!("{id} has left plan mode")
                        },
                        NoticeKind::Info,
                    );
                    self.refresh_session_lists();
                }
                Err(error) => {
                    // The one refusal worth rendering as itself: plan mode is not a
                    // Harness configuration key, so a transport that carries the posture
                    // on every launch can only be told at start. The runtime says which
                    // transport and what to do instead; the generic renderer would show
                    // that sentence as one field of a JSON blob.
                    let named = match &error {
                        ClientError::Rpc(rpc) => rpc
                            .data
                            .as_ref()
                            .filter(|data| {
                                data.get("field").and_then(Value::as_str) == Some("plan")
                            })
                            .and_then(|data| {
                                let reason =
                                    data.get("reason").and_then(Value::as_str).unwrap_or("");
                                let message = data.get("message").and_then(Value::as_str);

                                message.map(|message| (reason.to_string(), message.to_string()))
                            }),
                        _other => None,
                    };

                    match named {
                        Some((reason, message)) => self.inform(
                            if reason.is_empty() {
                                message
                            } else {
                                format!("{message} ({reason})")
                            },
                            NoticeKind::Warn,
                        ),
                        None => self.action_failed("plan mode", plane, &id, error),
                    }
                }
            },
            // The same shape as `Tag::PlanMode`, for the same reasons. Success re-lists so
            // the footer's C5 cell and the desktop's posture picker read the mode off the
            // session row the runtime just updated, rather than off a value this client
            // assumed took hold: whether a change applies now or next turn is the
            // runtime's answer, and only its own row can report which happened.
            Tag::SandboxMode { plane, id, want } => match result {
                Ok(_value) => {
                    self.inform(
                        format!("{id} is on {} — {}", want.label(), want.describe()),
                        if want.warns() {
                            NoticeKind::Warn
                        } else {
                            NoticeKind::Info
                        },
                    );
                    self.refresh_session_lists();
                }
                Err(error) => match sandbox_refusal(&error) {
                    Some(sentence) => self.inform(sentence, NoticeKind::Warn),
                    None => self.action_failed("file access", plane, &id, error),
                },
            },
            Tag::McpList { node } => match result {
                Ok(value) => self.mcp_read(node, &value),
                Err(error) => {
                    let text = match &error {
                        ClientError::Rpc(rpc) => format!("mcp.list: {}", model::refusal(rpc)),
                        other => format!("mcp.list failed: {other}"),
                    };
                    self.inform(text, NoticeKind::Error);
                }
            },
            Tag::Start { plane, id } => match result {
                Ok(value) => match StartedRef::decode(&value) {
                    Some(started) if started.id == id => {
                        if self
                            .pending_background_start
                            .as_ref()
                            .is_some_and(|request| request.id == id)
                        {
                            self.pending_background_start = None;
                        }
                        self.started(plane, started);
                    }
                    Some(started) => self.start_failed(
                        plane,
                        &id,
                        ClientError::BadJson(format!(
                            "the runtime answered start id {} for retry id {id}; both identities \
                             must be inspected before another start",
                            started.id
                        )),
                    ),
                    // The session exists; this client just cannot address it. Saying so is
                    // the only honest answer. The same id makes reconciliation safe.
                    None => self.start_failed(
                        plane,
                        &id,
                        ClientError::BadJson(format!(
                            "the runtime started a session but answered a reference this build \
                         cannot read: {value}"
                        )),
                    ),
                },
                Err(error) => self.start_failed(plane, &id, error),
            },
            Tag::FirstMessage {
                plane,
                id,
                turn_id,
                input,
                submission_sequence,
            } => match result {
                Ok(value) => match model::turn_reply(&value) {
                    model::TurnReply::Accepted => {
                        self.accept_first_message(plane, &id, &turn_id);
                    }
                    model::TurnReply::OutcomeUnknown => {
                        self.restore_first_message(plane, &id, input, turn_id, submission_sequence);
                        self.inform(
                            format!(
                                "send_message on {id}: {}; the exact draft and turn id were \
                                 restored",
                                model::turn_reply_diagnostic(&value)
                            ),
                            NoticeKind::Error,
                        );
                    }
                    model::TurnReply::Rejected => {
                        self.settle_pending_reconciliation(plane, &id, Some(&turn_id));
                        self.sessions.clear_reply_pending(plane, &id);
                        let verb = if model::turn_reply_busy(&value) {
                            ComposerVerb::FollowUp
                        } else {
                            ComposerVerb::Message
                        };
                        self.restore_refused_first_message(plane, &id, input, verb);
                        self.inform(
                            format!(
                                "send_message on {id}: {}",
                                model::turn_reply_diagnostic(&value)
                            ),
                            NoticeKind::Error,
                        );
                    }
                },
                Err(error) => {
                    let outcome_unknown = Self::reply_outcome_unknown(&error);
                    let busy = matches!(
                        &error,
                        ClientError::Rpc(rpc) if model::turn_busy(rpc.data.as_ref())
                    );

                    if !outcome_unknown {
                        self.settle_pending_reconciliation(plane, &id, Some(&turn_id));
                        self.sessions.clear_reply_pending(plane, &id);
                    }

                    if outcome_unknown {
                        self.restore_first_message(plane, &id, input, turn_id, submission_sequence);
                    } else {
                        // This logical id is durably failed. Replaying it would return the
                        // existing failed turn as an idempotent read and falsely clear the
                        // draft. Keep the text but mint a replacement on Enter; `:busy`
                        // also changes the retry to Harness's safe queueing verb.
                        let verb = if busy {
                            ComposerVerb::FollowUp
                        } else {
                            ComposerVerb::Message
                        };
                        self.restore_refused_first_message(plane, &id, input, verb);
                    }

                    self.action_failed("send_message", plane, &id, error);
                }
            },
        }
    }

    fn fill_rows(
        explorer: &mut Explorer,
        result: Result<Value, ClientError>,
        ticks: u64,
        project: fn(&Value) -> Option<Row>,
    ) {
        match result {
            Ok(value) => {
                let rows: Vec<Row> = value
                    .as_array()
                    .map(|items| items.iter().filter_map(project).collect())
                    .unwrap_or_default();

                if explorer.selected >= rows.len() {
                    explorer.selected = rows.len().saturating_sub(1);
                }

                explorer.rows.ok(rows, ticks, LIST_TICKS);
            }
            Err(error) => explorer.rows.failed(error.to_string(), ticks, LIST_TICKS),
        }
    }

    fn fill_detail(explorer: &mut Explorer, result: Result<Value, ClientError>, ticks: u64) {
        match result {
            Ok(value) => explorer.detail.ok(value, ticks, DETAIL_TICKS),
            Err(error) => explorer
                .detail
                .failed(error.to_string(), ticks, DETAIL_TICKS),
        }
    }

    fn fill_value(
        panel: &mut Loadable<Value>,
        result: Result<Value, ClientError>,
        ticks: u64,
        cadence: u64,
    ) {
        match result {
            Ok(value) => panel.ok(value, ticks, cadence),
            Err(error) => panel.failed(error.to_string(), ticks, cadence),
        }
    }

    fn account_login_answered(&mut self, result: Result<Value, ClientError>) {
        if !matches!(self.overlay, Some(Overlay::Account(_))) {
            // The operator dismissed the modal before Codex returned its login id. Once
            // that id exists, cancel it rather than leaving an invisible managed login
            // alive on the runtime host.
            if let Ok(value) = result {
                if let Some(login_id) = value.get("loginId").and_then(Value::as_str) {
                    self.issue(Call::new(
                        Tag::AccountCancel,
                        "account.login.cancel",
                        json!({ "login_id": login_id }),
                    ));
                }
            }
            return;
        }

        let Some(Overlay::Account(dialog)) = self.overlay.as_mut() else {
            return;
        };

        match result {
            Ok(value) => {
                dialog.pending = true;
                dialog.login_id = value
                    .get("loginId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.url = value
                    .get("authUrl")
                    .or_else(|| value.get("verificationUrl"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.code = value
                    .get("userCode")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.error = None;

                if let Some(url) = dialog.url.as_deref() {
                    if url.starts_with("https://") {
                        self.open_url_pending = Some(url.to_string());
                    }
                }

                self.account.invalidate();
                self.poll();
            }
            Err(error) => {
                dialog.pending = false;
                dialog.error = Some(error.to_string());
            }
        }
    }

    /// A refused operate verb, said in the terms the gateway used.
    /// A native-only verb's refusal.
    ///
    /// Two of the shapes it can take are worth their own sentence: `unsupported_on_transport`
    /// is permanent for this session, and `native_transport_unavailable` is not. Everything
    /// else falls through to the ordinary renderer, which keeps every field the runtime
    /// sent rather than summarising it away.
    fn native_verb_failed(&mut self, label: &str, id: &str, error: ClientError) {
        if let Some(sentence) = Self::native_refusal(&error) {
            self.inform(format!("{label}: {sentence}"), NoticeKind::Info);
            return;
        }

        self.action_failed(label, Plane::Interactive, id, error);
    }

    fn action_failed(&mut self, label: &str, _plane: Plane, id: &str, error: ClientError) {
        let text = match &error {
            ClientError::Rpc(rpc) if rpc.code == ErrorCode::ScopeDenied => format!(
                "{label} was refused: this listener runs at scope `{}` and {label} mutates the \
                 runtime",
                self.hello.scope
            ),
            ClientError::Rpc(rpc)
                if rpc.code == ErrorCode::UpstreamTimeout
                    && model::outcome_unknown(rpc.data.as_ref()) =>
            {
                format!(
                    "{label} on {id}: the gateway stopped waiting, the runtime did not stop \
                     working — read the session to see which it was"
                )
            }
            ClientError::Rpc(rpc) => format!("{label} on {id}: {}", model::refusal(rpc)),
            other => format!("{label} on {id} failed: {other}"),
        };

        // B4. A refusal that named an attachment belongs beside the chips that caused it,
        // not only in a notice row that scrolls away in eight seconds.
        self.note_attachment_refusal(&text);
        self.inform(text, NoticeKind::Error);
    }

    fn steer_delivery_unconfirmed(&mut self, id: &str, disposition: ComposerRestoreDisposition) {
        let preservation = match disposition {
            ComposerRestoreDisposition::Restored => {
                "the exact draft was restored for inspection".to_string()
            }
            ComposerRestoreDisposition::SavedForReopen => {
                "the exact draft was saved for inspection when this composer is reopened"
                    .to_string()
            }
            ComposerRestoreDisposition::NewerDraftPreserved => {
                "the newer draft was preserved; the prior steer remains available in composer history"
                    .to_string()
            }
            ComposerRestoreDisposition::ReconciliationQueued => {
                unreachable!("steer has no durable reconciliation id")
            }
        };
        self.inform(
            format!(
                "steer on {id}: delivery could not be confirmed; {preservation}. Steer is not \
                 idempotent — check the transcript and provider state before deliberately \
                 sending it again"
            ),
            NoticeKind::Error,
        );
    }

    pub(super) fn accept_reconciled_composer_draft(
        &mut self,
        plane: Plane,
        id: &str,
        turn_id: &str,
    ) {
        let key = (plane, id.to_string());
        let cleared = if self.sessions.open.as_ref() == Some(&key) {
            self.sessions.composer.as_mut().is_some_and(|composer| {
                if composer.owns_reconciliation(turn_id) {
                    composer.editor.accept_submission();
                    composer.user_changed_draft();
                    true
                } else {
                    false
                }
            })
        } else {
            self.sessions
                .composer_drafts
                .get(&key)
                .and_then(|draft| draft.reconciliation_owner.as_ref())
                .is_some_and(|owner| {
                    owner.turn_id == turn_id
                        && self
                            .sessions
                            .composer_drafts
                            .get(&key)
                            .is_some_and(|draft| owner.generation == draft.generation)
                })
        };

        if cleared {
            self.sessions.composer_drafts.remove(&key);
            if self.sessions.open.as_ref() == Some(&key) {
                self.remember_composer_history();
            }
        }
    }

    fn release_reconciliation_draft(&mut self, plane: Plane, id: &str, turn_id: &str) {
        let key = (plane, id.to_string());
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.owns_reconciliation(turn_id) {
                    composer.reconciliation_owner = None;
                }
            }
            self.remember_composer_history();
            return;
        }

        if let Some(draft) = self.sessions.composer_drafts.get_mut(&key) {
            let owned = draft.reconciliation_owner.as_ref().is_some_and(|owner| {
                owner.turn_id == turn_id && owner.generation == draft.generation
            });
            if owned {
                draft.reconciliation_owner = None;
            }
        }
    }

    pub(super) fn settle_pending_reconciliation(
        &mut self,
        plane: Plane,
        id: &str,
        turn_id: Option<&str>,
    ) {
        let Some(turn_id) = turn_id else {
            return;
        };
        let key = (plane, id.to_string());
        if let Some(pending) = self.sessions.pending_reconciliations.get_mut(&key) {
            pending.retain(|entry| entry.turn_id != turn_id);
            if pending.is_empty() {
                self.sessions.pending_reconciliations.remove(&key);
            }
        }
    }

    fn reply_outcome_unknown(error: &ClientError) -> bool {
        match error {
            ClientError::Rpc(rpc) => {
                rpc.code == ErrorCode::UpstreamTimeout || model::outcome_unknown(rpc.data.as_ref())
            }
            // The transport can disappear after the gateway received the mutation but
            // before its answer reached this client. As in the CLI first-message path,
            // no local transport error is permission to mint a second logical turn.
            _transport => true,
        }
    }

    pub(super) fn event_acknowledges_reply_request(event: &Event) -> bool {
        matches!(
            event.kind,
            EventType::RunStarted
                | EventType::RunCompleted
                | EventType::RunFailed
                | EventType::RunCancelled
                | EventType::InputAccepted
                | EventType::TurnQueued
                | EventType::TurnStarted
                | EventType::OutputTextDelta
                | EventType::OutputTextFinal
                | EventType::TurnCompleted
                | EventType::TurnFailed
                | EventType::TurnInterrupted
                | EventType::ApprovalRequested
        )
    }
}

fn project_agent(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  {}",
            value.get("node").map(model::compact).unwrap_or_default()
        ),
        status: value
            .get("replicas")
            .map(|replicas| format!("{} replicas", model::compact(replicas))),
        id,
        raw: value.clone(),
    })
}

fn project_team(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  {} workers  {} delegations",
            value
                .get("worker_count")
                .map(model::compact)
                .unwrap_or_default(),
            value
                .get("delegation_count")
                .map(model::compact)
                .unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}

/// The one `interactive.configure {sandbox_mode}` refusal worth rendering as itself.
///
/// The runtime's typed answers name `field: "sandbox_mode"` and say, in their own words,
/// *which* of the several no's this is: a transport that declares no
/// `dynamic_configuration` at all, one whose `configuration_options` exclude the field, or
/// a provider whose `normalized_values` do not list the mode. Those are different problems
/// with different fixes, and the generic renderer shows all of them as one JSON blob.
///
/// `None` means "not one of those", and the caller falls back to the generic report rather
/// than paraphrasing an error it did not recognise.
fn sandbox_refusal(error: &ClientError) -> Option<String> {
    let ClientError::Rpc(rpc) = error else {
        return None;
    };

    let data = rpc.data.as_ref()?;

    if data.get("field").and_then(Value::as_str) != Some("sandbox_mode") {
        return None;
    }

    let reason = data.get("reason").and_then(Value::as_str).unwrap_or("");

    if let Some(message) = data.get("message").and_then(Value::as_str) {
        return Some(if reason.is_empty() {
            message.to_string()
        } else {
            format!("{message} ({reason})")
        });
    }

    // `value_not_accepted` carries the allowlist instead of a sentence, and the allowlist
    // is the whole answer: it says which postures this provider *would* take.
    let accepted = data
        .get("accepted_values")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(model::compact)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|accepted| !accepted.is_empty())?;

    Some(format!(
        "this session's provider takes only {accepted} for sandbox_mode ({reason})"
    ))
}

fn project_plan(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  v{}",
            value.get("version").map(model::compact).unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}

fn project_run(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  rev {}",
            value
                .get("revision")
                .map(model::compact)
                .unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}
