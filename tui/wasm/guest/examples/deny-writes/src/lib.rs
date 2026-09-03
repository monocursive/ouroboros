//! A `PreToolUse` hook that denies a `write` or an `edit` outside one configured directory.
//!
//! Declare it, in `ouroboros.toml` or `~/.config/ouroboros/hooks.toml`:
//!
//! ```toml
//! [[hooks]]
//! event = "PreToolUse"
//! matcher = "write|edit"
//! component = "./hooks/deny-writes.wasm"
//! config = '{"root": "src/"}'
//! ```
//!
//! Build it:
//!
//! ```text
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! and `target/wasm32-wasip2/release/deny_writes.wasm` is a component in
//! `ouroboros:capability@0.1.0` importing exactly `log`. `tui/wasm/tests/sdk.rs` builds this
//! file, asserts both facts against the real helper, and drives a denial and an allowance
//! through it.
//!
//! # What it demonstrates
//!
//! * [`Hook`], the verdict seam: a typed [`HookInput`] in, a [`Verdict`] out.
//! * Both directions of the verdict vocabulary — a [`Verdict::Deny`] with the reason a human
//!   reads, and a [`Verdict::Context`] line on the calls it lets through.
//! * [`Verdict::Silent`] for every event this hook has no opinion about, which is the answer an
//!   `allow` would have got wrong: silence is not consent, and an `allow` from an untrusted
//!   workspace is read as silence anyway.
//!
//! # What it is not
//!
//! A boundary. This component has no filesystem: it sees the path the model asked for, as a
//! string, and cannot canonicalise it, resolve a symlink, or know what the workspace root is.
//! So the test below is textual, and it is deliberately strict in the only safe direction — a
//! path it cannot read as being under `root` is denied, and a `..` anywhere in it is denied
//! outright rather than resolved.
//!
//! What actually bounds a write is `Ouroboros.Control.Permissions` and the workspace scope,
//! both of which run before this hook is invoked at all and neither of which this hook can
//! loosen: a rule that denied is final and no hook is called, and from an untrusted workspace
//! an `allow` here is read as silence and an `updatedInput` is dropped. This hook adds an
//! opinion on top of that, in the strict direction only. It is the right shape for "not in this
//! repository, not in this directory"; it is the wrong shape for anything a security decision
//! depends on.

#![no_std]

use ouroboros_guest::{
    export_hook, format, log, Hook, HookInput, String, ToString, Value, Verdict,
};

/// The directory writes are confined to, as the operator wrote it.
struct DenyWrites {
    root: String,
}

impl Hook for DenyWrites {
    /// `{"root": "<prefix>"}`, required. A hook with no root would have nothing to say, and a
    /// hook that defaulted to "everything is fine" would be an installed hook that never fires
    /// — which is worse than one that refuses to start and says why at `instantiate`.
    fn init(config: Value) -> Result<Self, String> {
        let root = config
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| "config needs a string `root`, e.g. {\"root\": \"src/\"}".to_string())?;

        if root.is_empty() {
            return Err("`root` must not be empty".to_string());
        }

        // Normalised once, here, so the comparison below is a plain prefix test: "src" and
        // "src/" must not differ, and without the separator "src" would also match "srcfoo".
        let root = if root.ends_with('/') {
            root.to_string()
        } else {
            format!("{root}/")
        };

        Ok(DenyWrites { root })
    }

    fn on(&mut self, input: HookInput) -> Result<Verdict, String> {
        // Every other event, including the ones this hook is not declared for. A hook is
        // invoked for what its `matcher` matched and nothing else, but a component that
        // assumed so would be a component whose behaviour depends on somebody else's TOML.
        if !input.is("PreToolUse") {
            return Ok(Verdict::Silent);
        }

        let Some(tool) = input.tool_name.as_deref() else {
            return Ok(Verdict::Silent);
        };

        if !tool.eq_ignore_ascii_case("write") && !tool.eq_ignore_ascii_case("edit") {
            return Ok(Verdict::Silent);
        }

        // No path to judge is not an allowance: this hook cannot tell whether a `write` with
        // no `path` is a shape it does not understand or a tool it does not know, and neither
        // is a reason to say `deny` or a reason to say anything at all.
        let Some(path) = input.tool_input_str("path") else {
            return Ok(Verdict::Silent);
        };

        if !confined(path, &self.root) {
            log("warn", "deny-writes: refused a write outside the root");

            return Ok(Verdict::deny(format!(
                "{tool} to `{path}` was refused: this workspace's hook confines writes to `{}`",
                self.root
            )));
        }

        Ok(Verdict::context(format!(
            "deny-writes checked `{path}` against `{}` and let it through",
            self.root
        )))
    }
}

/// Whether `path` reads as being under `root`, textually and strictly.
///
/// `..` in any position is refused rather than resolved: resolving it would need to know what
/// the path is relative *to*, and a component in this world knows nothing about the host it did
/// not arrive knowing. A backslash is refused for the same reason — this hook does not know
/// which separator the host uses, and a rule that is wrong about that is a rule with a hole.
fn confined(path: &str, root: &str) -> bool {
    if path.contains('\\') {
        return false;
    }

    if path.split('/').any(|segment| segment == "..") {
        return false;
    }

    path.starts_with(root)
}

export_hook!(DenyWrites);
