//! S1 — the shared command catalogue, as this client reads it.
//!
//! `priv/ui/commands.json` is the one list of verbs the terminal palette and the web
//! palette both draw. These tests are the terminal half of the drift fence: they parse the
//! file themselves — a second reader, not a second opinion from the crate's own parse —
//! and refuse the three ways the two can come apart.
//!
//!   * a [`Command`] variant with no row in the file, which is a palette row with no
//!     wording behind it;
//!   * a row whose `tui` block names a variant this build does not have, which is a file
//!     describing a client that no longer exists;
//!   * a row whose heading, wording or spelling has drifted from what the palette draws.
//!
//! The Elixir half lives in `test/ouroboros/web/catalogue_test.exs`, and the count of
//! one-sided verbs is pinned there.

use serde_json::Value;

use ouro::keymap::Action;
use ouro::ui::app::{Command, Group};

/// The same bytes the crate compiles in, parsed here from the source path. Malformed JSON
/// is a failure of every test in this file rather than a palette that draws nothing.
const CATALOGUE_JSON: &str = include_str!("../../priv/ui/commands.json");

fn rows() -> Vec<Value> {
    serde_json::from_str::<Value>(CATALOGUE_JSON)
        .expect("priv/ui/commands.json is not valid JSON")
        .as_array()
        .expect("priv/ui/commands.json is not an array")
        .clone()
}

fn row(id: &str) -> Value {
    rows()
        .into_iter()
        .find(|row| row["id"] == Value::String(id.to_string()))
        .unwrap_or_else(|| panic!("no row for {id}"))
}

/// This variant's own name, spelled out.
///
/// The `match` is total, so a variant added to [`Command`] without a line here does not
/// compile — which is the half of the fence a test cannot provide, because a test can only
/// check the variants it is handed.
fn variant(command: Command) -> &'static str {
    match command {
        Command::NewSession => "NewSession",
        Command::SwitchSession => "SwitchSession",
        Command::SessionDetails => "SessionDetails",
        Command::ShowDiff => "ShowDiff",
        Command::RawMode => "RawMode",
        Command::CopyLast => "CopyLast",
        Command::CopyRawLast => "CopyRawLast",
        Command::Export => "Export",
        Command::DumpScrollback => "DumpScrollback",
        Command::ViewTranscript => "ViewTranscript",
        Command::Interrupt => "Interrupt",
        Command::Steer => "Steer",
        Command::ExternalEditor => "ExternalEditor",
        Command::CloseSession => "CloseSession",
        Command::NewSessionOptions => "NewSessionOptions",
        Command::WriteAccess => "WriteAccess",
        Command::ConnectChatGpt => "ConnectChatGpt",
        Command::Runtime => "Runtime",
        Command::Upgrades => "Upgrades",
        Command::Logs => "Logs",
        Command::Settings => "Settings",
        Command::Help => "Help",
        Command::ListCapabilities => "ListCapabilities",
        Command::PreviewCapability => "PreviewCapability",
        Command::AdmitCapability => "AdmitCapability",
        Command::Backtrack => "Backtrack",
        Command::Fork => "Fork",
        Command::Model => "Model",
        Command::Effort => "Effort",
        Command::Cost => "Cost",
        Command::Keys => "Keys",
        Command::Compact => "Compact",
        Command::Handoff => "Handoff",
        Command::Context => "Context",
        Command::Rewind => "Rewind",
        Command::Theme => "Theme",
        Command::Plan => "Plan",
        Command::AutoApprove => "AutoApprove",
        Command::Sandbox => "Sandbox",
        Command::Mcp => "Mcp",
        Command::Rename => "Rename",
        Command::Quit => "Quit",
        Command::Approval => "Approval",
    }
}

/// What this surface actually spells a row, which is the shared spelling unless the `tui`
/// block overrides it. Five rows do; each says why in its `note`.
fn tui_spelling(row: &Value, key: &str) -> Option<String> {
    row["tui"]
        .get(key)
        .and_then(Value::as_str)
        .or_else(|| row[key].as_str())
        .map(str::to_string)
}

// ----- the file itself ------------------------------------------------------------------

/// One row per id, filed under one of the five groups, and belonging to at least one
/// surface. A row with neither side is a verb nobody can reach, written down.
#[test]
fn the_file_is_one_row_per_id_in_one_of_the_five_groups() {
    let rows = rows();
    let mut seen = Vec::new();

    for row in &rows {
        let id = row["id"].as_str().expect("a row with no id");

        assert!(!seen.contains(&id), "{id} is written twice");
        seen.push(id);

        let group = row["group"].as_str().expect("{id} has no group");
        assert!(
            Group::parse(group).is_some(),
            "{id} is filed under {group:?}, which is not one of the five"
        );

        assert!(
            row["tui"].is_object() || row["web"].is_object(),
            "{id} belongs to neither surface"
        );

        if let Some(tui) = row["tui"].as_object() {
            assert!(tui.contains_key("command"), "{id} names no Command variant");
        }

        if let Some(web) = row["web"].as_object() {
            assert!(web.contains_key("event"), "{id} names no web event");
        }
    }

    assert_eq!(seen.len(), rows.len());
}

/// Every group the plan names earns its place. A heading with no rows under it is a
/// taxonomy the file carries and neither surface uses.
#[test]
fn each_of_the_five_groups_holds_at_least_one_row() {
    let rows = rows();

    for group in Group::ALL {
        assert!(
            rows.iter()
                .any(|row| row["group"] == Value::String(group.as_str().to_ascii_lowercase())),
            "{} holds no rows",
            group.as_str()
        );
    }
}

// ----- the fence, both ways -------------------------------------------------------------

/// Every variant has a row, and the row names it back. Delete a row and this goes red;
/// add a variant without one and `variant` above stops compiling.
#[test]
fn every_command_variant_has_a_row_that_names_it() {
    for command in Command::ALL {
        let row = row(command.id());

        assert_eq!(
            row["tui"]["command"].as_str(),
            Some(variant(command)),
            "{} is {:?} in the file",
            command.id(),
            row["tui"]["command"]
        );
    }
}

/// And back: a row with a `tui` block names a variant this build has. A file describing a
/// command that was deleted is a file a reader would go looking for.
#[test]
fn every_tui_row_names_a_variant_this_build_has() {
    for row in rows() {
        let Some(tui) = row["tui"].as_object() else {
            continue;
        };

        let id = row["id"].as_str().expect("a row with no id");
        let named = tui["command"]
            .as_str()
            .expect("a tui block with no command");

        let found = Command::ALL
            .into_iter()
            .find(|command| command.id() == id)
            .unwrap_or_else(|| panic!("{id} has a tui block and no variant answers to it"));

        assert_eq!(variant(found), named, "{id} names the wrong variant");
    }
}

// ----- what the palette draws -----------------------------------------------------------

/// The heading, the wording and the typed spelling the palette shows are the file's, for
/// every row. Edit a label in the file and the palette moves with it; edit one in the
/// crate and there is nowhere left to edit it.
#[test]
fn the_palette_draws_the_labels_groups_and_spellings_the_file_carries() {
    for command in Command::ALL {
        let row = row(command.id());
        let id = command.id();

        assert_eq!(
            Some(command.label().to_string()),
            tui_spelling(&row, "label"),
            "{id} draws a label the file does not carry"
        );

        assert_eq!(
            command.group(),
            Group::parse(row["group"].as_str().expect("a row with no group")).expect("bad group"),
            "{id} is drawn under a heading the file does not carry"
        );

        assert_eq!(
            tui_spelling(&row, "slash").unwrap_or_default(),
            command.slash(),
            "{id} spells its verb differently from the file"
        );
    }
}

/// The keymap action each row claims is the one [`Command::action`] answers with, and it
/// is an action this build still has. The palette's shortcut column is drawn from that
/// action, so a row naming a stale one would print a key nobody can press.
#[test]
fn every_row_names_the_action_the_command_answers_with() {
    for command in Command::ALL {
        let row = row(command.id());
        let named = row["tui"]["action"].as_str();

        assert_eq!(
            named,
            command.action().map(Action::name),
            "{} names the wrong action",
            command.id()
        );

        if let Some(named) = named {
            assert!(
                Action::parse(named).is_some(),
                "{} names {named}, which is not an action this build has",
                command.id()
            );
        }
    }
}

/// A command with no key must have a verb, because the palette's shortcut column falls
/// back to the verb and an empty column teaches nothing. The three rows with an empty
/// spelling — scrollback, the `$EDITOR` view and the approval — all have keys.
#[test]
fn a_command_with_no_key_has_a_typed_spelling() {
    for command in Command::ALL {
        if command.action().is_none() {
            assert!(
                !command.slash().is_empty(),
                "{} has neither a key nor a verb",
                command.id()
            );
        }
    }
}
