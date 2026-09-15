use super::session::{
    PendingComposerReconciliation, PendingReconciliationKind, SavedComposerDraft,
};
use super::*;

impl App {
    /// Only drafts containing images are added to the private client recovery file.
    pub fn image_draft_snapshot(&mut self) -> Value {
        self.remember_composer_history();
        let drafts: Vec<Value> = self.sessions.composer_drafts.iter()
            .filter(|(_, draft)| persistable(&draft.attachments))
            .map(|((plane, id), draft)| json!({"id": id,
                "node": self.sessions.owner_node(*plane, id),
                "input": TurnInput {prompt: draft.input.clone(), attachments: draft.attachments.clone(), reasoning_effort: draft.reasoning_effort}})).collect();
        let mut pending: Vec<Value> = self.in_flight.iter().filter_map(|tag| match tag {
            Tag::ComposerAction {id, plane, verb, turn_id: Some(turn_id), input, submission_sequence, ..}
                if persistable(&input.attachments) => Some(json!({"id": id,
                    "node": self.sessions.owner_node(*plane, id), "turn_id": turn_id,
                    "input": input, "sequence": submission_sequence, "queue": *verb == ComposerVerb::FollowUp})),
            _ => None,
        }).collect();
        for ((plane, id), items) in &self.sessions.pending_reconciliations {
            for item in items.iter().filter(|p| persistable(&p.input.attachments)) {
                if !pending.iter().any(|p| p["turn_id"] == item.turn_id) {
                    pending.push(json!({"id": id, "node": self.sessions.owner_node(*plane,id),
                        "turn_id": item.turn_id, "input": item.input, "sequence": item.submission_sequence,
                        "queue": matches!(item.kind, PendingReconciliationKind::Composer(ComposerVerb::FollowUp))}));
                }
            }
        }
        pending.sort_by_key(|p| p["sequence"].as_u64().unwrap_or(0));
        let mut queued = Vec::new();
        for ((plane, id), queue) in &self.sessions.queued_drafts {
            for draft in queue
                .iter()
                .filter(|draft| persistable(&draft.input.attachments))
            {
                queued.push(json!({"id": id, "node": self.sessions.owner_node(*plane, id), "input": draft.input}));
            }
        }
        json!({"version": 1, "draft_id": self.image_draft_id, "home_draft_id": self.home_image_draft_id, "drafts": drafts,
            "first_message": if persistable(&self.home_images) {self.first_message.as_ref()} else {None},
            "pending": pending, "queued": queued, "home": if persistable(&self.home_images) {self.home_images.clone()} else {Vec::new()},
            "home_text": if persistable(&self.home_images) {self.home_draft.text()} else {""},
            "home_node": self.home_image_node})
    }

    pub fn restore_image_drafts(&mut self, value: Value) {
        if value["version"] != 1 {
            return;
        }
        if let Some(id) = value["draft_id"].as_str().filter(|id| id.len() <= 100) {
            self.image_draft_id = id.into();
            self.home_image_draft_id = id.into();
        }
        if let Some(id) = value["home_draft_id"].as_str().filter(|id| id.len() <= 100) {
            self.home_image_draft_id = id.into();
        }
        if let Ok(mut images) = serde_json::from_value::<Vec<Attachment>>(value["home"].clone()) {
            images.truncate(32);
            mark_interrupted(&mut images);
            self.home_images = images;
            self.home_image_node = value["home_node"].as_str().unwrap_or("").into();
            if self.home_draft.is_empty() {
                self.home_draft.paste(
                    value["home_text"].as_str().unwrap_or(""),
                    &self.completion_catalog,
                );
            }
        }
        if !self.home_images.is_empty() {
            if let Ok(mut first) = serde_json::from_value::<super::session::PendingFirstMessage>(
                value["first_message"].clone(),
            ) {
                // A crash can occur before or after the start acknowledgement. Retry
                // must reconcile the recorded session ID before creating anything new.
                if first.start.plane == Plane::Interactive && first.start.params().is_ok() {
                    first.start_outcome_unknown = true;
                    self.config.location.machine = first.start.machine.clone();
                    self.config.location.workspace = Some(first.start.workspace.clone());
                    self.config.defaults.model = first.start.model.clone();
                    self.first_message = Some(first);
                }
            }
        }
        for kind in ["drafts", "pending", "queued"] {
            for entry in value[kind].as_array().into_iter().flatten().take(128) {
                let Some(id) = entry["id"].as_str().filter(|id| id.len() <= 200) else {
                    continue;
                };
                let Ok(mut input) = serde_json::from_value::<TurnInput>(entry["input"].clone())
                else {
                    continue;
                };
                if input.attachments.len() > 32 {
                    continue;
                }
                mark_interrupted(&mut input.attachments);
                self.sessions
                    .remember_owner(Plane::Interactive, id, entry["node"].as_str());
                let key = (Plane::Interactive, id.to_string());
                match kind {
                    "drafts" => {
                        self.sessions
                            .composer_drafts
                            .entry(key)
                            .or_insert(SavedComposerDraft {
                                input: input.prompt,
                                generation: 0,
                                reconciliation_owner: None,
                                attachments: input.attachments,
                                reasoning_effort: input.reasoning_effort,
                            });
                    }
                    "pending" => {
                        let Some(turn_id) = entry["turn_id"].as_str() else {
                            continue;
                        };
                        self.sessions
                            .pending_reconciliations
                            .entry(key)
                            .or_default()
                            .push_back(PendingComposerReconciliation {
                                input,
                                turn_id: turn_id.into(),
                                submission_sequence: entry["sequence"].as_u64().unwrap_or(0),
                                kind: PendingReconciliationKind::Composer(
                                    if entry["queue"] == true {
                                        ComposerVerb::FollowUp
                                    } else {
                                        ComposerVerb::Message
                                    },
                                ),
                            });
                    }
                    _ => {
                        self.sessions
                            .queued_drafts
                            .entry(key)
                            .or_default()
                            .push(QueuedDraft { input });
                    }
                }
            }
        }
        // A startup session may already have created its empty editor before recovery.
        if let Some(key) = &self.sessions.open {
            if let (Some(saved), Some(composer)) = (
                self.sessions.composer_drafts.get(key),
                self.sessions.composer.as_mut(),
            ) {
                if composer.editor.is_empty() && composer.attachments.is_empty() {
                    composer
                        .editor
                        .paste(&saved.input, &self.completion_catalog);
                    composer.attachments = saved.attachments.clone();
                    composer.reasoning_effort = saved.reasoning_effort;
                }
            }
        }
    }
}

fn mark_interrupted(images: &mut [Attachment]) {
    for image in images {
        if image.kind == crate::model::AttachmentKind::PendingImage {
            image.kind = crate::model::AttachmentKind::FailedImage;
            image.name = Some("Interrupted image upload · remove and attach again".into());
        }
    }
}

fn persistable(images: &[Attachment]) -> bool {
    images.iter().any(|a| {
        matches!(
            a.kind,
            crate::model::AttachmentKind::ManagedImage
                | crate::model::AttachmentKind::PendingImage
                | crate::model::AttachmentKind::FailedImage
        )
    }) && images.iter().all(|a| {
        a.kind == crate::model::AttachmentKind::Path
            || (a.kind != crate::model::AttachmentKind::Image && !a.ephemeral)
    })
}
